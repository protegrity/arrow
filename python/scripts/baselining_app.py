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
baselining_app.py

Benchmark Parquet Arrow encryption performance for:
- AES (built-in Parquet encryption) using a dummy KMS client
- EXTERNAL_DBPA_V1 (external DBPA encryption) using a local agent library

Creates a synthetic dataset with a single string column (default: 10k rows,
~50 chars per value), writes an encrypted parquet to an in-memory buffer,
and reports avg time + top-10 slowest runs.

Optionally, use an input CSV file instead of synthetic data.
Assumptions for CSV input:
- The CSV has exactly 1 column
- There is no header row
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import heapq
import os
import platform
import random
import string
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe


# --------------------------------------------------------------------------------------
# Dummy KMS (same idea as python/scripts/base_app.py)


class FooKmsClient(pe.KmsClient):
    def __init__(self, kms_connection_config: pe.KmsConnectionConfig):
        pe.KmsClient.__init__(self)
        self.master_keys_map = kms_connection_config.custom_kms_conf

    def wrap_key(self, key_bytes: bytes, master_key_identifier: str) -> bytes:
        master_key_bytes = self.master_keys_map[master_key_identifier].encode("utf-8")
        joint_key = b"".join([master_key_bytes, key_bytes])
        return base64.b64encode(joint_key)

    def unwrap_key(self, wrapped_key: bytes, master_key_identifier: str) -> bytes:
        expected_master = self.master_keys_map[master_key_identifier]
        decoded_key = base64.b64decode(wrapped_key)
        master_key_bytes = decoded_key[:16]
        decrypted_key = decoded_key[16:]
        if expected_master == master_key_bytes.decode("utf-8"):
            return decrypted_key
        raise ValueError(
            f"Bad master key used [{master_key_bytes!r}] - [{decrypted_key!r}]"
        )


def _kms_client_factory(kms_connection_config: pe.KmsConnectionConfig) -> FooKmsClient:
    return FooKmsClient(kms_connection_config)


def _get_kms_connection_config(
    footer_key_name: str, col_key_name: str
) -> pe.KmsConnectionConfig:
    # The dummy KMS above expects these master key strings to be 16 bytes long.
    return pe.KmsConnectionConfig(
        custom_kms_conf={
            footer_key_name: "012footer_secret",
            col_key_name: "column_secret001",
        }
    )


# --------------------------------------------------------------------------------------
# External DBPA config (local agent only)


def _default_local_agent_library_name() -> str:
    if platform.system() == "Linux":
        return "libdbpsLocalAgent.so"
    return "libdbpsLocalAgent.dylib"


def _get_dbpa_configuration_properties() -> Dict[str, Dict[str, str]]:
    # Local agent only for now (remote support can be added later).
    agent_library_path = os.environ.get("DBPA_LIBRARY_PATH")
    if not agent_library_path:
        agent_library_path = _default_local_agent_library_name()

    return {
        "EXTERNAL_DBPA_V1": {
            "agent_library_path": agent_library_path,
            "agent_init_timeout_ms": "15000",
            "agent_encrypt_timeout_ms": "35000",
            "agent_decrypt_timeout_ms": "35000",
        }
    }


# --------------------------------------------------------------------------------------
# Benchmark helpers


@dataclass(frozen=True)
class Scenario:
    use_dictionary: bool
    compression: str
    data_page_version: Optional[str] = None


def _scenario_from_id(scenario_id: int) -> Scenario:
    # Mirrors python/scripts/base_app.py scenarios (write behavior only).
    if scenario_id == 1:
        return Scenario(use_dictionary=False, compression="NONE")
    if scenario_id == 2:
        return Scenario(use_dictionary=True, compression="SNAPPY")
    if scenario_id == 3:
        return Scenario(use_dictionary=True, compression="NONE")
    if scenario_id == 4:
        return Scenario(use_dictionary=False, compression="SNAPPY", data_page_version="1.0")
    if scenario_id == 5:
        return Scenario(use_dictionary=False, compression="SNAPPY", data_page_version="2.0")
    if scenario_id == 6:
        return Scenario(use_dictionary=False, compression="GZIP", data_page_version="2.0")
    raise ValueError(f"Invalid scenario ID: {scenario_id}")


def _build_synthetic_table(rows: int, str_len: int, seed: int) -> pa.Table:
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    values = ["".join(rng.choices(alphabet, k=str_len)) for _ in range(rows)]
    return pa.Table.from_pydict({"payload": pa.array(values, type=pa.string())})


def _iter_payload_batches_from_input_file(
    *,
    input_file: str,
    max_rows: Optional[int],
) -> Iterable[pa.RecordBatch]:
    """
    Stream a CSV input file as RecordBatches with a single string column named 'payload'.

    This is designed to avoid materializing huge inputs (e.g. 100M strings) in memory.
    """
    if max_rows is not None and max_rows < 0:
        raise ValueError("--max-rows must be >= 0")

    if max_rows == 0:
        return iter(())

    remaining = max_rows

    # Configure as "no header, single column" by providing a column name explicitly.
    # This ensures the first row is treated as data.
    reader = pacsv.open_csv(
        input_file,
        read_options=pacsv.ReadOptions(column_names=["payload"])
    )
    while True:
        try:
            batch = reader.read_next_batch()
        except StopIteration:
            break
        arr = batch.column(0)
        if not pa.types.is_string(arr.type):
            arr = arr.cast(pa.string())
        if remaining is not None and batch.num_rows > remaining:
            arr = arr.slice(0, remaining)
        yield pa.RecordBatch.from_arrays([arr], names=["payload"])
        if remaining is not None:
            remaining -= min(batch.num_rows, remaining)
            if remaining <= 0:
                break
    return


def _read_payload_table_from_input_file(
    *,
    input_file: str,
    max_rows: Optional[int],
) -> pa.Table:
    """
    Read a CSV input file as a fully materialized Table with a single string column named
    'payload'.

    This uses `pyarrow.csv.read_csv(...)` (eager), matching the approach used in
    `protegrity_benchmark_app.py`. This is useful when you want your benchmark timing to
    focus on Parquet write+encrypt rather than CSV streaming/parsing per-iteration.
    """
    if max_rows is not None and max_rows < 0:
        raise ValueError("--max-rows must be >= 0")

    if max_rows == 0:
        return pa.Table.from_pydict({"payload": pa.array([], type=pa.string())})

    tbl = pacsv.read_csv(
        input_file,
        read_options=pacsv.ReadOptions(column_names=["payload"]),
    )

    # Normalize (defensive) to a single string column named "payload".
    if tbl.num_columns != 1:
        raise ValueError(f"Expected 1 column, got {tbl.num_columns}: {tbl.schema.names}")
    if not pa.types.is_string(tbl.column(0).type):
        tbl = tbl.set_column(0, "payload", tbl.column(0).cast(pa.string()))

    if max_rows is not None and tbl.num_rows > max_rows:
        tbl = tbl.slice(0, max_rows)
    return tbl


def _write_once_to_memory(
    table: pa.Table,
    encryption_properties: Any,
    scenario: Scenario,
) -> None:
    sink = pa.BufferOutputStream()
    kwargs: Dict[str, Any] = {
        "encryption_properties": encryption_properties,
        "use_dictionary": scenario.use_dictionary,
        "compression": scenario.compression,
    }
    if scenario.data_page_version is not None:
        kwargs["data_page_version"] = scenario.data_page_version
    pq.write_table(table, sink, **kwargs)
    # Ensure everything is materialized.
    sink.getvalue()


def _write_once_to_file(
    table: pa.Table,
    encryption_properties: Any,
    scenario: Scenario,
    output_file: str,
) -> None:
    kwargs: Dict[str, Any] = {
        "encryption_properties": encryption_properties,
        "use_dictionary": scenario.use_dictionary,
        "compression": scenario.compression,
    }
    if scenario.data_page_version is not None:
        kwargs["data_page_version"] = scenario.data_page_version
    pq.write_table(table, output_file, **kwargs)


def _write_once_to_memory_from_payload_batches(
    payload_batches: Iterable[pa.RecordBatch],
    encryption_properties: Any,
    scenario: Scenario,
) -> int:
    sink = pa.BufferOutputStream()
    schema = pa.schema([pa.field("payload", pa.string())])
    writer_kwargs: Dict[str, Any] = {
        "encryption_properties": encryption_properties,
        "use_dictionary": scenario.use_dictionary,
        "compression": scenario.compression,
    }
    if scenario.data_page_version is not None:
        writer_kwargs["data_page_version"] = scenario.data_page_version

    rows_written = 0
    writer = pq.ParquetWriter(sink, schema, **writer_kwargs)
    try:
        for batch in payload_batches:
            # Normalize (defensive) to a single string column named "payload".
            if batch.num_columns != 1:
                raise ValueError(
                    f"Expected 1 column in batch, got {batch.num_columns}: {batch.schema.names}"
                )
            arr = batch.column(0)
            if not pa.types.is_string(arr.type):
                arr = arr.cast(pa.string())
            batch = pa.RecordBatch.from_arrays([arr], names=["payload"])
            writer.write_batch(batch)
            rows_written += batch.num_rows
    finally:
        writer.close()

    # Ensure everything is materialized.
    sink.getvalue()
    return rows_written


def _benchmark_write_encrypt(
    *,
    label: str,
    write_once: Callable[[], int],
    encryption_properties: Any,
    scenario: Scenario,
    iterations: int,
    warmup: int,
    include_warmup_in_results: bool,
) -> Tuple[float, List[float], int]:
    # Keep stats in O(1) memory:
    # - running sum/count for avg
    # - min-heap of size 10 for top-10 slowest
    total_ms = 0.0
    count = 0
    top10_slowest_heap: List[float] = []
    rows_used: Optional[int] = None

    def _record_sample(sample_ms: float) -> None:
        nonlocal total_ms, count, top10_slowest_heap
        total_ms += sample_ms
        count += 1
        if len(top10_slowest_heap) < 10:
            heapq.heappush(top10_slowest_heap, sample_ms)
        else:
            # Keep only the 10 largest values.
            if sample_ms > top10_slowest_heap[0]:
                heapq.heapreplace(top10_slowest_heap, sample_ms)

    if include_warmup_in_results:
        for _ in range(warmup):
            t0 = time.perf_counter_ns()
            rows = write_once()
            t1 = time.perf_counter_ns()
            _record_sample((t1 - t0) / 1_000_000.0)
            if rows_used is None:
                rows_used = rows
    else:
        # Warmup runs (not recorded).
        for _ in range(warmup):
            rows = write_once()
            if rows_used is None:
                rows_used = rows

    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        rows = write_once()
        t1 = time.perf_counter_ns()
        _record_sample((t1 - t0) / 1_000_000.0)
        if rows_used is None:
            rows_used = rows

    avg_ms = (total_ms / count) if count else 0.0
    top10_slowest_ms = sorted(top10_slowest_heap, reverse=True)

    return avg_ms, top10_slowest_ms, (rows_used or 0)


# --------------------------------------------------------------------------------------
# Encryption property builders


def _build_aes_encryption_properties(
    *,
    footer_key_name: str,
    col_key_name: str,
    col_name: str,
    plaintext_footer: bool,
    encryption_algorithm: str,
    cache_lifetime_minutes: float,
    data_key_length_bits: int,
) -> Any:
    kms_connection_config = _get_kms_connection_config(footer_key_name, col_key_name)
    encryption_config = pe.EncryptionConfiguration(
        footer_key=footer_key_name,
        column_keys={col_key_name: [col_name]},
        encryption_algorithm=encryption_algorithm,
        cache_lifetime=_dt.timedelta(minutes=cache_lifetime_minutes),
        data_key_length_bits=data_key_length_bits,
        plaintext_footer=plaintext_footer,
    )
    crypto_factory = pe.CryptoFactory(_kms_client_factory)
    return crypto_factory.file_encryption_properties(kms_connection_config, encryption_config)


def _build_external_dbpa_encryption_properties(
    *,
    footer_key_name: str,
    col_key_name: str,
    col_name: str,
    plaintext_footer: bool,
    file_level_encryption_algorithm: str,
    cache_lifetime_minutes: float,
    data_key_length_bits: int,
) -> Any:
    kms_connection_config = _get_kms_connection_config(footer_key_name, col_key_name)

    external_encryption_config = pe.ExternalEncryptionConfiguration(
        footer_key=footer_key_name,
        # Default algorithm for non-per-column columns (we only have one column).
        encryption_algorithm=file_level_encryption_algorithm,
        column_keys={},
        cache_lifetime=_dt.timedelta(minutes=cache_lifetime_minutes),
        data_key_length_bits=data_key_length_bits,
        plaintext_footer=plaintext_footer,
        per_column_encryption={
            col_name: {
                "encryption_algorithm": "EXTERNAL_DBPA_V1",
                "encryption_key": col_key_name,
            }
        },
        app_context={
            "app": "base_app_baselining",
            "user_id": "benchmark",
            "location": "local",
        },
        configuration_properties=_get_dbpa_configuration_properties(),
    )

    crypto_factory = pe.CryptoFactory(_kms_client_factory)
    return crypto_factory.external_file_encryption_properties(
        kms_connection_config, external_encryption_config
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark Parquet encryption: AES vs EXTERNAL_DBPA_V1 (local agent)."
    )
    parser.add_argument(
        "--input-file",
        default=None,
        help=(
            "Optional CSV file path (1 column, no header) to use as input instead of generating synthetic data."
        ),
    )
    parser.add_argument(
        "--output-mode",
        choices=("file", "memory"),
        default="file",
        help=(
            "Where to write the Parquet output. "
            "'file' writes to disk (matches protegrity_benchmark_app.py). "
            "'memory' writes to an in-memory buffer (original behavior)."
        ),
    )
    parser.add_argument(
        "--output-file",
        default="baselining.parquet",
        help="Output Parquet path when --output-mode=file.",
    )
    parser.add_argument(
        "--skip-dbpa",
        action="store_true",
        default=False,
        help="Skip EXTERNAL_DBPA_V1 (DBPA) benchmark and only run AES.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Optional maximum number of rows to use from the input (default: use all).",
    )
    parser.add_argument("--rows", type=int, default=10_000)
    parser.add_argument("--str-len", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument(
        "--include-warmup-in-results",
        action="store_true",
        default=False,
        help="Include warmup rounds in timing statistics (default: excluded).",
    )
    parser.add_argument(
        "--scenario-id",
        type=int,
        default=int(os.getenv("BASE_APP_SCENARIO_ID", "5")),
        help="Matches base_app.py scenarios (default: env BASE_APP_SCENARIO_ID or 5).",
    )
    parser.add_argument(
        "--plaintext-footer",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep footer plaintext to focus timing on column encryption.",
    )
    parser.add_argument("--cache-lifetime-min", type=float, default=2.0)
    parser.add_argument("--data-key-length-bits", type=int, default=128)
    parser.add_argument(
        "--aes-algorithm",
        default="AES_GCM_CTR_V1",
        help="Parquet encryption algorithm name for AES benchmark.",
    )
    parser.add_argument(
        "--file-level-algorithm",
        default="AES_GCM_V1",
        help="Default file-level algorithm used in ExternalEncryptionConfiguration.",
    )
    args = parser.parse_args()

    # IMPORTANT: for large inputs (e.g. 100M strings), materializing a full Table can
    # easily exhaust memory. When --input-file is provided we stream batches.
    table: Optional[pa.Table] = None
    if args.input_file is None:
        table = _build_synthetic_table(args.rows, args.str_len, args.seed)
    else:
        # We always benchmark Parquet writing via `write_table(table, ...)` for consistency,
        # and we read the CSV eagerly (matching protegrity_benchmark_app.py).
        table = _read_payload_table_from_input_file(
            input_file=args.input_file,
            max_rows=args.max_rows,
        )
    scenario = _scenario_from_id(args.scenario_id)

    footer_key_name = "footer_key"
    col_key_name = "col_key"
    col_name = "payload"

    setup_lines: List[str] = []
    if args.input_file:
        setup_lines.append(f"input_file={args.input_file} max_rows={args.max_rows}")
        assert table is not None
        setup_lines.append(
            f"csv_read_mode=eager rows={table.num_rows} iterations={args.iterations} warmup={args.warmup}"
        )
    else:
        setup_lines.append(
            f"rows={args.rows} str_len={args.str_len} iterations={args.iterations} warmup={args.warmup}"
        )
    setup_lines.append(f"include_warmup_in_results={args.include_warmup_in_results}")
    setup_lines.append(
        f"scenario_id={args.scenario_id} use_dictionary={scenario.use_dictionary} "
        f"compression={scenario.compression} data_page_version={scenario.data_page_version}"
    )
    setup_lines.append(
        f"plaintext_footer={args.plaintext_footer} cache_lifetime_min={args.cache_lifetime_min} "
        f"data_key_length_bits={args.data_key_length_bits}"
    )
    setup_lines.append(f"AES algorithm={args.aes_algorithm}")
    setup_lines.append("EXTERNAL DBPA algorithm=EXTERNAL_DBPA_V1 (local agent only)")
    setup_lines.append("DBPA_LIBRARY_PATH=" + os.environ.get("DBPA_LIBRARY_PATH", "(not set)"))
    setup_lines.append(
        f"output_mode={args.output_mode}"
        + (f" output_file={args.output_file}" if args.output_mode == "file" else "")
    )
    setup_lines.append(f"skip_dbpa={args.skip_dbpa}")

    print("\n------------------------------------------------------------")
    print("Parquet encryption baselining")
    print("------------------------------------------------------------")
    for line in setup_lines:
        print(line)
    print("------------------------------------------------------------")

    aes_props = _build_aes_encryption_properties(
        footer_key_name=footer_key_name,
        col_key_name=col_key_name,
        col_name=col_name,
        plaintext_footer=args.plaintext_footer,
        encryption_algorithm=args.aes_algorithm,
        cache_lifetime_minutes=args.cache_lifetime_min,
        data_key_length_bits=args.data_key_length_bits,
    )

    dbpa_props = None
    if not args.skip_dbpa:
        dbpa_props = _build_external_dbpa_encryption_properties(
            footer_key_name=footer_key_name,
            col_key_name=col_key_name,
            col_name=col_name,
            plaintext_footer=args.plaintext_footer,
            file_level_encryption_algorithm=args.file_level_algorithm,
            cache_lifetime_minutes=args.cache_lifetime_min,
            data_key_length_bits=args.data_key_length_bits,
        )

    assert table is not None

    def write_once_aes() -> int:
        if args.output_mode == "file":
            _write_once_to_file(table, aes_props, scenario, args.output_file)
        else:
            _write_once_to_memory(table, aes_props, scenario)
        return table.num_rows

    aes_avg_ms, aes_top10_ms, aes_rows_used = _benchmark_write_encrypt(
        label=f"AES ({args.aes_algorithm})",
        write_once=write_once_aes,
        encryption_properties=aes_props,
        scenario=scenario,
        iterations=args.iterations,
        warmup=args.warmup,
        include_warmup_in_results=args.include_warmup_in_results,
    )

    dbpa_avg_ms = 0.0
    dbpa_top10_ms: List[float] = []
    dbpa_rows_used = 0
    if not args.skip_dbpa:
        assert dbpa_props is not None

        def write_once_dbpa() -> int:
            if args.output_mode == "file":
                _write_once_to_file(table, dbpa_props, scenario, args.output_file)
            else:
                _write_once_to_memory(table, dbpa_props, scenario)
            return table.num_rows

        dbpa_avg_ms, dbpa_top10_ms, dbpa_rows_used = _benchmark_write_encrypt(
            label="EXTERNAL_DBPA_V1 (local agent)",
            write_once=write_once_dbpa,
            encryption_properties=dbpa_props,
            scenario=scenario,
            iterations=args.iterations,
            warmup=args.warmup,
            include_warmup_in_results=args.include_warmup_in_results,
        )

    runs_measured = args.iterations + (args.warmup if args.include_warmup_in_results else 0)
    print("\n------------------------------------------------------------")
    print("Run configuration")
    print("------------------------------------------------------------")
    for line in setup_lines:
        print(line)
    print("------------------------------------------------------------")
    print("\n------------------------------------------------------------")
    print("Benchmark results (write + encrypt, ms)")
    print("------------------------------------------------------------")
    rows_used = aes_rows_used or dbpa_rows_used
    print(f"rows_used: {rows_used}")
    print(f"AES ({args.aes_algorithm})")
    print(f"  runs_measured: {runs_measured} (warmup: {args.warmup}, included: {args.include_warmup_in_results})")
    print(f"  avg_ms: {aes_avg_ms:.3f}")
    print("  top10_slowest_ms: " + ", ".join(f"{x:.3f}" for x in aes_top10_ms))
    if not args.skip_dbpa:
        print()
        print("EXTERNAL_DBPA_V1 (local agent)")
        print(f"  runs_measured: {runs_measured} (warmup: {args.warmup}, included: {args.include_warmup_in_results})")
        print(f"  avg_ms: {dbpa_avg_ms:.3f}")
        print("  top10_slowest_ms: " + ", ".join(f"{x:.3f}" for x in dbpa_top10_ms))
        if aes_avg_ms > 0.0:
            delta_pct = ((dbpa_avg_ms - aes_avg_ms) / aes_avg_ms) * 100.0
            relation = "slower" if delta_pct > 0 else "faster" if delta_pct < 0 else "the same"
            print()
            print(
                f"DBPA vs AES (avg_ms): {delta_pct:+.2f}% ({relation}; AES is baseline)"
            )
        else:
            print()
            print("DBPA vs AES (avg_ms): N/A (AES avg_ms is 0)")
    print("------------------------------------------------------------")


if __name__ == "__main__":
    main()

