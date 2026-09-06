# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
verify_external_roundtrip_correctness.py

Comprehensive encrypt/decrypt roundtrip correctness verification for DBPA encryption.

Generates a random table with 20 000+ rows and one column for every relevant
Parquet physical type, then writes → reads it back for every combination of:

    dictionary encoding  ×  compression  ×  data-page version

All columns are encrypted with EXTERNAL_PROTECT_V1, each with its own key.
Roundtrip correctness is verified column-by-column after every read-back.

Tested dimensions
-----------------
  Data types (7 columns):
    BOOLEAN, INT32, INT64, FLOAT, DOUBLE, BYTE_ARRAY, FIXED_LEN_BYTE_ARRAY

  Dictionary encoding:  True, False
  Compression:          NONE, SNAPPY, GZIP
  Data page version:    "1.0", "2.0"

  Total combinations:   2 × 3 × 2 = 12

Additional:
  - ~10 % of values in every column are null.
  - Footer is always plaintext (plaintext_footer=True).


Execution instructions
----------------------
This script needs to be pointed the the DBPA library to be tested. It can be done by
setting the DBPA_LIBRARY_PATH environment variable.
You need to ensure that the library is in the LD_LIBRARY_PATH (or its equivalent)

Then, once it's been set, execute the script with:

$ python verify_external_roundtrip_correctness.py

e.g.
$ export DBPA_LIBRARY_PATH=libdbpsLocalAgent.so
$ python verify_external_roundtrip_correctness.py
"""

from __future__ import annotations

import base64
import datetime
import itertools
import os
import random
import string
import sys
import tempfile

import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NUM_ROWS = 20_000
NULL_FRACTION = 0.10           # ~10 % nulls
FIXED_BYTE_LEN = 16           # byte width for FIXED_LEN_BYTE_ARRAY column
RANDOM_SEED = 42

FOOTER_KEY_NAME = "footer_key"
FOOTER_KEY_VALUE = "012footer_secret"  # must be exactly 16 chars

# Each entry: (column_name, pyarrow_type, key_name, key_value_16chars)
COLUMNS = [
    ("col_bool", pa.bool_(), "key_bool", "bool_secret__001"),
    ("col_int32", pa.int32(), "key_int32", "int32_secret_002"),
    ("col_int64", pa.int64(), "key_int64", "int64_secret_003"),
    ("col_float32", pa.float32(), "key_float", "float_secret_004"),
    ("col_float64", pa.float64(), "key_double", "double_secret_05"),
    ("col_string", pa.utf8(), "key_bytearr", "bytearr_secret06"),
    ("col_fixedbin", pa.binary(FIXED_BYTE_LEN), "key_fixbin", "fixbin_secret_07"),
]

# Test-matrix axes
DICTIONARY_OPTIONS = [False, True]
COMPRESSION_OPTIONS = ["NONE", "SNAPPY", "GZIP"]
PAGE_VERSION_OPTIONS = ["1.0", "2.0"]


# ---------------------------------------------------------------------------
# KMS client (same pattern as base_app.py — simple wrap / unwrap)
# ---------------------------------------------------------------------------

class TestKmsClient(pe.KmsClient):
    """Trivial KMS that base64-wraps (master_key || DEK)."""

    def __init__(self, kms_connection_config):
        pe.KmsClient.__init__(self)
        self.master_keys_map = kms_connection_config.custom_kms_conf

    def wrap_key(self, key_bytes, master_key_identifier):
        master_key_bytes = self.master_keys_map[master_key_identifier].encode(
            "utf-8"
        )
        return base64.b64encode(b"".join([master_key_bytes, key_bytes]))

    def unwrap_key(self, wrapped_key, master_key_identifier):
        expected_master = self.master_keys_map[master_key_identifier]
        decoded = base64.b64decode(wrapped_key)
        master_key_bytes = decoded[:16]
        decrypted_key = decoded[16:]
        if expected_master == master_key_bytes.decode("utf-8"):
            return decrypted_key
        raise ValueError(
            f"Bad master key: got {master_key_bytes!r}, "
            f"expected {expected_master!r}"
        )


def _kms_client_factory(kms_connection_config):
    return TestKmsClient(kms_connection_config)


# ---------------------------------------------------------------------------
# Random data generation
# ---------------------------------------------------------------------------

def _generate_data(
    num_rows: int = NUM_ROWS,
    null_fraction: float = NULL_FRACTION,
    seed: int = RANDOM_SEED,
) -> dict[str, list]:
    """Return a dict  column_name → list[values | None]."""
    rng = random.Random(seed)

    def _with_nulls(values: list) -> list:
        return [None if rng.random() < null_fraction else v for v in values]

    def _rand_string() -> str:
        length = rng.randint(0, 100)
        return "".join(
            rng.choices(string.ascii_letters + string.digits + " ", k=length)
        )

    def _rand_fixed_bytes() -> bytes:
        return bytes(rng.getrandbits(8) for _ in range(FIXED_BYTE_LEN))

    return {
        "col_bool": _with_nulls([rng.choice([True, False])
                                 for _ in range(num_rows)]),
        "col_int32": _with_nulls([rng.randint(-(2**31), 2**31 - 1)
                                 for _ in range(num_rows)]),
        "col_int64": _with_nulls([rng.randint(-(2**63), 2**63 - 1)
                                  for _ in range(num_rows)]),
        "col_float32": _with_nulls([rng.uniform(-1e6, 1e6)
                                    for _ in range(num_rows)]),
        "col_float64": _with_nulls([rng.uniform(-1e15, 1e15)
                                    for _ in range(num_rows)]),
        "col_string": _with_nulls([_rand_string()
                                   for _ in range(num_rows)]),
        "col_fixedbin": _with_nulls([_rand_fixed_bytes()
                                     for _ in range(num_rows)]),
    }


def _build_table(data: dict[str, list]) -> pa.Table:
    arrays = []
    for col_name, pa_type, *_ in COLUMNS:
        arrays.append(pa.array(data[col_name], type=pa_type))
    return pa.table(
        {col_name: arr for (col_name, *_), arr in zip(COLUMNS, arrays)}
    )


# ---------------------------------------------------------------------------
# Encryption / decryption helpers
# ---------------------------------------------------------------------------

def _kms_connection_config() -> pe.KmsConnectionConfig:
    keys = {FOOTER_KEY_NAME: FOOTER_KEY_VALUE}
    for _, _, key_name, key_value in COLUMNS:
        keys[key_name] = key_value
    return pe.KmsConnectionConfig(custom_kms_conf=keys)


def _dbpa_configuration_properties() -> dict:
    agent_library_path = os.environ.get(
        "DBPA_LIBRARY_PATH",
        "libdbpsLocalAgent.so"
    )

    props: dict = {
        "EXTERNAL_PROTECT_V1": {
            "agent_library_path": agent_library_path,
            "agent_init_timeout_ms": "15000",
            "agent_encrypt_timeout_ms": "35000",
            "agent_decrypt_timeout_ms": "35000",
        }
    }

    if "remote" in agent_library_path.lower():
        config_file_name = os.environ.get(
            "DBPA_CONFIG_FILE_NAME", "test_connection_config_file.json"
        )
        for candidate in [
            config_file_name,
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         config_file_name),
        ]:
            if os.path.exists(candidate):
                props["EXTERNAL_PROTECT_V1"][
                    "connection_config_file_path"
                ] = candidate
                break
        else:
            raise FileNotFoundError(
                f"Configuration file [{config_file_name}] not found"
            )

    return props


def _encryption_config() -> pe.ExternalEncryptionConfiguration:
    per_column = {
        col_name: {
            "encryption_algorithm": "EXTERNAL_PROTECT_V1",
            "encryption_key": key_name,
        }
        for col_name, _, key_name, _ in COLUMNS
    }
    return pe.ExternalEncryptionConfiguration(
        footer_key=FOOTER_KEY_NAME,
        column_keys={},
        encryption_algorithm="AES_GCM_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits=128,
        plaintext_footer=True,
        per_column_encryption=per_column,
        app_context={"user_id": "roundtrip_correctness", "location": "test"},
        configuration_properties=_dbpa_configuration_properties(),
    )


def _decryption_config() -> pe.ExternalDecryptionConfiguration:
    return pe.ExternalDecryptionConfiguration(
        cache_lifetime=datetime.timedelta(minutes=2.0),
        app_context={"user_id": "roundtrip_correctness", "location": "test"},
        configuration_properties=_dbpa_configuration_properties(),
    )


# ---------------------------------------------------------------------------
# Write / read
# ---------------------------------------------------------------------------

def _write_encrypted(
    table: pa.Table,
    path: str,
    *,
    use_dictionary: bool,
    compression: str,
    data_page_version: str,
) -> None:
    crypto_factory = pe.CryptoFactory(_kms_client_factory)
    encryption_properties = crypto_factory.external_file_encryption_properties(
        _kms_connection_config(), _encryption_config()
    )
    pq.write_table(
        table,
        path,
        use_dictionary=use_dictionary,
        compression=compression,
        data_page_version=data_page_version,
        encryption_properties=encryption_properties,
    )


def _read_encrypted(path: str) -> pa.Table:
    crypto_factory = pe.CryptoFactory(_kms_client_factory)
    decryption_properties = crypto_factory.external_file_decryption_properties(
        _kms_connection_config(), _decryption_config()
    )
    return pq.ParquetFile(
        path, decryption_properties=decryption_properties
    ).read()


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _compare_tables(
    original: pa.Table, decrypted: pa.Table
) -> list[tuple[str, bool, str]]:
    """Compare two tables column-by-column.

    Returns a list of (column_name, passed, detail) tuples.
    """
    results: list[tuple[str, bool, str]] = []

    for col_name in original.column_names:
        orig_col = original.column(col_name).combine_chunks()
        dec_col = decrypted.column(col_name).combine_chunks()

        if orig_col.equals(dec_col):
            results.append((col_name, True, "OK"))
            continue

        # Dig into the first few mismatches for diagnostics.
        parts: list[str] = []
        if len(orig_col) != len(dec_col):
            parts.append(
                f"length mismatch: {len(orig_col)} vs {len(dec_col)}"
            )

        mismatches = 0
        for i in range(min(len(orig_col), len(dec_col))):
            o = orig_col[i].as_py()
            d = dec_col[i].as_py()
            if o != d:
                parts.append(f"row {i}: {o!r} vs {d!r}")
                mismatches += 1
                if mismatches >= 3:
                    break

        results.append(
            (col_name, False, "; ".join(parts) if parts else "unknown diff")
        )

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 80)
    print("DBPA Encryption Roundtrip Correctness Verification")
    print("=" * 80)

    # ---- Generate data ----
    print(
        f"\nGenerating {NUM_ROWS} rows of test data "
        f"({len(COLUMNS)} columns, ~{NULL_FRACTION * 100:.0f} % nulls) ..."
    )
    data = _generate_data()
    original_table = _build_table(data)
    print(f"Table schema:\n{original_table.schema}\n")

    # ---- Build test matrix ----
    combos = list(
        itertools.product(
            DICTIONARY_OPTIONS, COMPRESSION_OPTIONS, PAGE_VERSION_OPTIONS
        )
    )
    total = len(combos)
    print(
        f"Testing {total} combinations  "
        f"({len(DICTIONARY_OPTIONS)} dict  x  "
        f"{len(COMPRESSION_OPTIONS)} compress  x  "
        f"{len(PAGE_VERSION_OPTIONS)} page_ver)\n"
    )

    passed = 0
    failed = 0
    failures: list[str] = []
    combo_results: list[bool] = []  # True=passed, False=failed per combo

    with tempfile.TemporaryDirectory() as tmpdir:
        for idx, (use_dict, compression, page_ver) in enumerate(combos, 1):
            label = (
                f"[{idx:>2}/{total}] dict={str(use_dict):<5}  "
                f"compress={compression:<6}  page={page_ver}"
            )
            print(f"  {label} ... ", end="", flush=True)

            parquet_path = os.path.join(tmpdir, f"test_{idx}.parquet")

            try:
                _write_encrypted(
                    original_table,
                    parquet_path,
                    use_dictionary=use_dict,
                    compression=compression,
                    data_page_version=page_ver,
                )

                decrypted_table = _read_encrypted(parquet_path)

                col_results = _compare_tables(original_table, decrypted_table)
                all_ok = all(ok for _, ok, _ in col_results)

                if all_ok:
                    print("PASSED")
                    passed += 1
                    combo_results.append(True)
                else:
                    print("FAILED")
                    failed += 1
                    combo_results.append(False)
                    for col_name, ok, detail in col_results:
                        if not ok:
                            msg = f"    {label} -- {col_name}: {detail}"
                            print(msg)
                            failures.append(msg)

            except Exception as exc:
                print("ERROR")
                failed += 1
                combo_results.append(False)
                msg = f"    {label} -- Exception: {exc}"
                print(msg)
                failures.append(msg)

    # ---- Summary ----
    print()
    print("=" * 80)
    print(
        f"RESULTS: {passed} passed, {failed} failed "
        f"out of {total} combinations"
    )
    print(f"  Data types tested : "
          f"{', '.join(c[0] for c in COLUMNS)}")
    print(f"  Rows per table    : {NUM_ROWS}")
    print(f"  Null fraction     : ~{NULL_FRACTION * 100:.0f} %")
    print(f"\n  Test matrix ({total} combinations):")
    for i, (use_dict, compression, page_ver) in enumerate(combos):
        status = "PASS" if combo_results[i] else "FAIL"
        print(f"    {i + 1:>2}. dict={str(use_dict):<5}  "
              f"compress={compression:<6}  page={page_ver}  -> {status}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f)
        print("=" * 80)
        sys.exit(1)
    else:
        print("\nAll roundtrip correctness verifications passed!")
        print("=" * 80)
        sys.exit(0)


if __name__ == "__main__":
    main()
