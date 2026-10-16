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
footer signing)."""

import datetime

import pytest
import pyarrow
import pyarrow.parquet as pq

ppe = pytest.importorskip(
    "pyarrow.parquet.encryption",
    reason="pyarrow.parquet.encryption not available "
           "(built without PARQUET_REQUIRE_ENCRYPTION=ON)",
)

from pyarrow.tests.parquet.crypto_provider_utils import (  # noqa: E402
    XorKmsClient, XorParquetCryptoProvider)

pytestmark = [
    pytest.mark.parquet_encryption,
    pytest.mark.parquet
]


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


def _write_with_provider(provider, path):
    crypto_factory = ppe.CryptoFactory(lambda cfg: XorKmsClient(cfg))
    encryption_config = ppe.ExternalEncryptionConfiguration(
        footer_key="Footer_DE",
        column_keys={"ColumnMD_DE": ["id", "name"]},
        encryption_algorithm="EXTERNAL_PROTECT_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits=128,
        plaintext_footer=True,
    )
    encryption_properties = crypto_factory.external_file_encryption_properties(
        _get_kms_connection_config(), encryption_config, provider)
    pq.write_table(_get_table(), path, encryption_properties=encryption_properties,
                   compression="none")


def _decryption_properties(provider):
    crypto_factory = ppe.CryptoFactory(lambda cfg: XorKmsClient(cfg))
    return crypto_factory.external_file_decryption_properties(
        _get_kms_connection_config(), ppe.ExternalDecryptionConfiguration(),
        provider)


# The round trip with a signed plaintext footer (sign_footer() and
# verify_footer_signature() called through the real dispatch chain) is covered by
# test_external_encryption.py::test_external_file_level_algorithm_round_trip.


def test_plaintext_footer_tampered_signature_rejected(tmp_path):
    """A corrupted on-disk footer signature must be rejected, not silently
    accepted -- proves verify_footer_signature() is actually enforced, not
    just called."""
    path = tmp_path / "plaintext_footer_tampered.parquet"
    provider = XorParquetCryptoProvider()
    _write_with_provider(provider, path)

    # Flip a byte inside the footer signature blob -- the last 8 bytes of any
    # Parquet file are the 4-byte footer length + "PAR1" magic, not part of
    # the signature, so corrupt a byte just before those instead of the very
    # last byte.
    data = bytearray(path.read_bytes())
    data[-9] ^= 0xFF
    path.write_bytes(bytes(data))

    with pytest.raises(Exception):
        pq.read_table(path, decryption_properties=_decryption_properties(provider))


def test_abstract_provider_methods_raise_not_implemented(tmp_path):
    """A provider that does not override the callbacks must fail the write."""
    provider = ppe.ParquetCryptoProvider()
    with pytest.raises(NotImplementedError):
        _write_with_provider(provider, tmp_path / "abstract_provider.parquet")


def test_provider_must_return_bytes(tmp_path):
    class StringProvider(XorParquetCryptoProvider):
        def encrypt_block(self, plaintext, key_metadata, column_path,
                          app_context, module_aad, dek):
            return "not bytes"

        def sign_footer(self, footer_bytes, key_metadata, column_path,
                        app_context, footer_aad, dek):
            return "not bytes"

    with pytest.raises(Exception, match="must return bytes"):
        _write_with_provider(StringProvider(), tmp_path / "string_provider.parquet")


def test_provider_exception_fails_read(tmp_path):
    path = tmp_path / "failing_decrypt.parquet"
    _write_with_provider(XorParquetCryptoProvider(), path)

    class FailingProvider(XorParquetCryptoProvider):
        def decrypt_block(self, ciphertext, key_metadata, column_path,
                          app_context, module_aad, dek):
            raise RuntimeError("provider decrypt failed")

    decryption_properties = _decryption_properties(FailingProvider())

    with pytest.raises(Exception, match="provider decrypt failed"):
        pq.read_table(path, decryption_properties=decryption_properties)
