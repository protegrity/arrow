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

"""Tests for the Python ParquetCryptoProvider bindings (block path and
footer signing). Unlike test_external_encryption.py, these tests do not
depend on the external DBPA agent library.
"""

import base64
import datetime

import pytest
import pyarrow
import pyarrow.parquet as pq

ppe = pytest.importorskip(
    "pyarrow.parquet.encryption",
    reason="pyarrow.parquet.encryption not available "
           "(built without PARQUET_REQUIRE_ENCRYPTION=ON)",
)


def _xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class XorKmsClient(ppe.KmsClient):
    """Trivial KmsClient: "wraps" a key by XOR-ing it with the master key.

    key_metadata is stored on disk and threaded through Cython's frombytes()
    (UTF-8 decode) elsewhere in the stack, so the wrapped key must be encoded
    as ASCII-safe text -- base64, matching FooKmsClient in
    test_external_encryption.py -- not raw XOR bytes.
    """

    def __init__(self, kms_connection_config):
        ppe.KmsClient.__init__(self)
        self.master_keys_map = kms_connection_config.custom_kms_conf

    def wrap_key(self, key_bytes, master_key_identifier):
        master_key = self.master_keys_map[master_key_identifier].encode("utf-8")
        return base64.b64encode(_xor_bytes(key_bytes, master_key))

    def unwrap_key(self, wrapped_key, master_key_identifier):
        master_key = self.master_keys_map[master_key_identifier].encode("utf-8")
        return _xor_bytes(base64.b64decode(wrapped_key), master_key)


class XorParquetCryptoProvider(ppe.ParquetCryptoProvider):
    """Block path + footer signing via XOR -- deterministic and reversible,
    good enough to prove the Python callback plumbing actually runs, not a
    real cipher."""

    def __init__(self):
        ppe.ParquetCryptoProvider.__init__(self)
        self.encrypt_block_calls = 0
        self.decrypt_block_calls = 0
        self.sign_footer_calls = 0
        self.verify_footer_signature_calls = 0

    def encrypt_block(self, plaintext, key_metadata, column_path,
                      app_context, module_aad, dek):
        self.encrypt_block_calls += 1
        return _xor_bytes(plaintext, dek)

    def decrypt_block(self, ciphertext, key_metadata, column_path,
                      app_context, module_aad, dek):
        self.decrypt_block_calls += 1
        return _xor_bytes(ciphertext, dek)

    def sign_footer(self, footer_bytes, key_metadata, column_path,
                    app_context, footer_aad, dek):
        self.sign_footer_calls += 1
        return _xor_bytes(footer_aad + footer_bytes, dek)

    def verify_footer_signature(self, footer_bytes, stored_signature, key_metadata,
                                column_path, app_context, footer_aad, dek):
        self.verify_footer_signature_calls += 1
        return _xor_bytes(footer_aad + footer_bytes, dek) == stored_signature


def _get_table():
    return pyarrow.Table.from_pydict({
        "id": [1, 2, 3, 4, 5],
        "name": ["alice", "bob", "carol", "dave", "erin"],
    })


def _get_kms_connection_config():
    return ppe.KmsConnectionConfig(
        custom_kms_conf={
            "Footer_DE": "footer_master_key01",
            "ColumnMD_DE": "column_master_key1",
        }
    )


def test_plaintext_footer_signing_round_trip(tmp_path):
    """Real E2E: write and read a Parquet file with plaintext_footer=True and
    EXTERNAL_PROTECT_V1, using a real Python ParquetCryptoProvider (not a mock
    on the C++ side) -- proves sign_footer()/verify_footer_signature() are
    actually invoked through the real dispatch chain."""
    table = _get_table()
    path = tmp_path / "plaintext_footer_python_provider.parquet"

    provider = XorParquetCryptoProvider()
    crypto_factory = ppe.CryptoFactory(lambda cfg: XorKmsClient(cfg))
    kms_config = _get_kms_connection_config()

    encryption_config = ppe.ExternalEncryptionConfiguration(
        footer_key="Footer_DE",
        column_keys={"ColumnMD_DE": ["id", "name"]},
        encryption_algorithm="EXTERNAL_PROTECT_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits=128,
        plaintext_footer=True,
    )
    encryption_properties = crypto_factory.external_file_encryption_properties(
        kms_config, encryption_config, provider)

    pq.write_table(table, path, encryption_properties=encryption_properties,
                   compression="none")

    assert provider.sign_footer_calls > 0
    assert provider.encrypt_block_calls > 0

    decryption_config = ppe.ExternalDecryptionConfiguration()
    decryption_properties = crypto_factory.external_file_decryption_properties(
        kms_config, decryption_config, provider)

    read_table = pq.read_table(path, decryption_properties=decryption_properties)
    assert read_table.equals(table)
    assert provider.verify_footer_signature_calls > 0
    assert provider.decrypt_block_calls > 0


def test_plaintext_footer_tampered_signature_rejected(tmp_path):
    """A corrupted on-disk footer signature must be rejected, not silently
    accepted -- proves verify_footer_signature() is actually enforced, not
    just called."""
    table = _get_table()
    path = tmp_path / "plaintext_footer_tampered.parquet"

    provider = XorParquetCryptoProvider()
    crypto_factory = ppe.CryptoFactory(lambda cfg: XorKmsClient(cfg))
    kms_config = _get_kms_connection_config()

    encryption_config = ppe.ExternalEncryptionConfiguration(
        footer_key="Footer_DE",
        column_keys={"ColumnMD_DE": ["id", "name"]},
        encryption_algorithm="EXTERNAL_PROTECT_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits=128,
        plaintext_footer=True,
    )
    encryption_properties = crypto_factory.external_file_encryption_properties(
        kms_config, encryption_config, provider)
    pq.write_table(table, path, encryption_properties=encryption_properties,
                   compression="none")

    # Flip a byte inside the footer signature blob -- the last 8 bytes of any
    # Parquet file are the 4-byte footer length + "PAR1" magic, not part of
    # the signature, so corrupt a byte just before those instead of the very
    # last byte.
    data = bytearray(path.read_bytes())
    data[-9] ^= 0xFF
    path.write_bytes(bytes(data))

    decryption_config = ppe.ExternalDecryptionConfiguration()
    decryption_properties = crypto_factory.external_file_decryption_properties(
        kms_config, decryption_config, provider)

    with pytest.raises(Exception):
        pq.read_table(path, decryption_properties=decryption_properties)
