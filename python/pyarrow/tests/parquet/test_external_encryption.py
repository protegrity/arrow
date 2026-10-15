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

"""Tests for the external encryption configuration and for files that mix
AES columns with columns encrypted by a ParquetCryptoProvider
(EXTERNAL_PROTECT_V1)."""

import datetime
import json
import re

import pytest
import pyarrow
import pyarrow.parquet as pp

# Skip the entire module at collection time if the encryption extension was not
# compiled (i.e. PARQUET_REQUIRE_ENCRYPTION=OFF).
ppe = pytest.importorskip(
    "pyarrow.parquet.encryption",
    reason="pyarrow.parquet.encryption not available "
           "(built without PARQUET_REQUIRE_ENCRYPTION=ON)",
)

from pyarrow.tests.parquet.crypto_provider_utils import (  # noqa: E402
    XorParquetCryptoProvider, xor_kms_client_factory)

kms_client_factory = xor_kms_client_factory

APP_CONTEXT = {"user_id": "Picard1701", "location": "Presidio"}

# Columns that reach the provider; every other column is AES encrypted or plain.
EXTERNAL_COLUMNS = {"price", "customer_name"}


def get_data_table(num_rows=1000):
    return pyarrow.Table.from_pydict({
        "orderId": list(range(1024, 1024 + num_rows)),
        "productId": [(i * 7) % 6548 for i in range(num_rows)],
        "price": [i * 0.25 for i in range(num_rows)],
        "vat": [None if i % 9 == 0 else i * 0.05 for i in range(num_rows)],
        "customer_name": [None if i % 7 == 0 else f"customer_{i}"
                          for i in range(num_rows)],
    })


def get_kms_connection_config():
    return ppe.KmsConnectionConfig(
        custom_kms_conf={
            "footer_key": "012footer_secret",
            "orderid_key": "column_secret001",
            "productid_key": "column_secret002",
            "price_key": "column_secret003",
            "customer_key": "column_secret004",
            "vat_key": "column_secret005",
        }
    )


def get_encryption_config():
    return ppe.EncryptionConfiguration(
        footer_key="footer_key",
        column_keys={
            "orderid_key": ["orderId"],
            "productid_key": ["productId"]
        },
        encryption_algorithm="AES_GCM_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits=128,
        plaintext_footer=True
    )


def get_encryption_properties():
    crypto_factory = ppe.CryptoFactory(kms_client_factory)
    return crypto_factory.file_encryption_properties(
        get_kms_connection_config(), get_encryption_config())


def get_decryption_properties():
    crypto_factory = ppe.CryptoFactory(kms_client_factory)
    return crypto_factory.file_decryption_properties(
        get_kms_connection_config(),
        ppe.DecryptionConfiguration(cache_lifetime=datetime.timedelta(minutes=10.0)))


def mixed_per_column_encryption():
    """orderId uses AES_GCM_CTR_V1, price and customer_name use the provider.
    productId is encrypted through column_keys, vat is not encrypted."""
    return {
        "orderId": {
            "encryption_algorithm": "AES_GCM_CTR_V1",
            "encryption_key": "orderid_key"
        },
        "price": {
            "encryption_algorithm": "EXTERNAL_PROTECT_V1",
            "encryption_key": "price_key"
        },
        "customer_name": {
            "encryption_algorithm": "EXTERNAL_PROTECT_V1",
            "encryption_key": "customer_key"
        },
    }


def get_external_encryption_config(
        encryption_algorithm="AES_GCM_V1", plaintext_footer=True,
        per_column_encryption=None, column_keys=None):
    if per_column_encryption is None:
        per_column_encryption = mixed_per_column_encryption()
    if column_keys is None:
        column_keys = {"productid_key": ["productId"]}
    return ppe.ExternalEncryptionConfiguration(
        footer_key="footer_key",
        column_keys=column_keys,
        encryption_algorithm=encryption_algorithm,
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits=128,
        plaintext_footer=plaintext_footer,
        per_column_encryption=per_column_encryption,
        app_context=APP_CONTEXT,
    )


def get_external_encryption_properties(provider, **kwargs):
    crypto_factory = ppe.CryptoFactory(kms_client_factory)
    return crypto_factory.external_file_encryption_properties(
        get_kms_connection_config(), get_external_encryption_config(**kwargs),
        provider)


def get_external_decryption_config():
    return ppe.ExternalDecryptionConfiguration(
        cache_lifetime=datetime.timedelta(minutes=10.0),
        app_context=APP_CONTEXT,
    )


def get_external_decryption_properties(provider):
    crypto_factory = ppe.CryptoFactory(kms_client_factory)
    return crypto_factory.external_file_decryption_properties(
        get_kms_connection_config(), get_external_decryption_config(), provider)


def write_parquet(table, location, encryption_properties, **write_kwargs):
    pp.write_table(table, location, encryption_properties=encryption_properties,
                   **write_kwargs)


def read_parquet(location, decryption_properties, **read_kwargs):
    reader = pp.ParquetFile(location, decryption_properties=decryption_properties)
    return reader.read(**read_kwargs)


def round_trip_encryption_and_decryption(
        tmp_path, encryption_properties, decryption_properties, **write_kwargs):
    data_table = get_data_table()
    parquet_path = tmp_path / "test.parquet"
    write_parquet(data_table, parquet_path, encryption_properties, **write_kwargs)

    read_data_table = read_parquet(parquet_path, decryption_properties)
    assert read_data_table.equals(data_table)
    assert read_data_table.num_rows == data_table.num_rows
    assert read_data_table.num_columns == data_table.num_columns
    assert read_data_table.schema.equals(data_table.schema)
    assert read_data_table.column_names == data_table.column_names
    return parquet_path


# Configuration objects


def test_encryption_configuration_properties():
    """Test the standard EncryptionConfiguration properties to avoid regressions."""

    config = ppe.EncryptionConfiguration(
        footer_key="footer-key-name",
        column_keys={
            "key_1": ["a"],
        },
        encryption_algorithm="EXTERNAL_PROTECT_V1",
        plaintext_footer=True,
        double_wrapping=True,
        cache_lifetime=datetime.timedelta(minutes=5.0),
        internal_key_material=True,
        data_key_length_bits=256
    )

    assert isinstance(config, ppe.EncryptionConfiguration)

    assert config.footer_key == "footer-key-name"
    assert config.column_keys == {
        "key_1": ["a"]
    }
    assert config.encryption_algorithm == "EXTERNAL_PROTECT_V1"
    assert config.plaintext_footer is True
    assert config.double_wrapping is True
    assert config.cache_lifetime == datetime.timedelta(minutes=5.0)
    assert config.internal_key_material is True
    assert config.data_key_length_bits == 256


def test_external_encryption_configuration_properties():
    """Test the ExternalEncryptionConfig including external-specific fields."""

    external_encryption_config = get_external_encryption_config()
    assert isinstance(
        external_encryption_config, ppe.ExternalEncryptionConfiguration)

    assert external_encryption_config.footer_key == "footer_key"
    assert external_encryption_config.column_keys == {
        "productid_key": ["productId"]
    }
    assert external_encryption_config.encryption_algorithm == "AES_GCM_V1"
    assert external_encryption_config.plaintext_footer is True
    assert external_encryption_config.double_wrapping is True
    assert external_encryption_config.cache_lifetime == datetime.timedelta(
        minutes=2.0)
    assert external_encryption_config.internal_key_material is True
    assert external_encryption_config.data_key_length_bits == 128
    assert external_encryption_config.app_context == APP_CONTEXT
    assert external_encryption_config.per_column_encryption == \
        mixed_per_column_encryption()


def test_external_encryption_app_context_default_is_empty():
    config = ppe.ExternalEncryptionConfiguration(footer_key="key")
    assert config.app_context == {}
    assert config.per_column_encryption == {}


def test_external_encryption_app_context_invalid_json():
    """Ensure app_context raises TypeError for non-JSON-serializable input."""
    with pytest.raises(
        TypeError,
        match="Failed to serialize app_context: {'invalid': {1, 2, 3}}"
    ):
        ppe.ExternalEncryptionConfiguration(
            footer_key="key",
            app_context={"invalid": set([1, 2, 3])}  # sets are not JSON-serializable
        )


def test_external_encryption_per_column_encryption_invalid_algorithm():
    """Ensure invalid encryption_algorithm raises a ValueError or is rejected."""

    with pytest.raises(ValueError, match="Invalid cipher name: INVALID"):
        ppe.ExternalEncryptionConfiguration(
            footer_key="key",
            per_column_encryption={
                "a": {
                    "encryption_algorithm": "INVALID",
                    "encryption_key": "some_key"
                }
            }
        )


def test_external_encryption_per_column_encryption_new_algorithm():
    """Ensure new encryption_algorithm is accepted."""

    config = ppe.ExternalEncryptionConfiguration(
        footer_key="key",
        per_column_encryption={
            "a": {
                "encryption_algorithm": "EXTERNAL_PROTECT_V1",
                "encryption_key": "key_2"
            }
        }
    )
    assert config.per_column_encryption["a"]["encryption_algorithm"] == \
        "EXTERNAL_PROTECT_V1"


def test_external_encryption_per_column_encryption_missing_key():
    with pytest.raises(
            ValueError, match="Each column must have 'encryption_key' \\(string\\)."):
        ppe.ExternalEncryptionConfiguration(
            footer_key="key",
            per_column_encryption={
                "a": {"encryption_algorithm": "AES_GCM_V1"}
            }
        )


def test_external_encryption_rejects_none_values():
    """Ensure None values are rejected."""
    config = ppe.ExternalEncryptionConfiguration(footer_key="key")

    with pytest.raises(TypeError, match="per_column_encryption cannot be None"):
        config.per_column_encryption = None

    # None is not JSON-serializable
    with pytest.raises(ValueError, match="app_context must be JSON-serializable"):
        config.app_context = None


def test_external_configurations_have_no_configuration_properties():
    """The external configurations take no configuration_properties."""
    with pytest.raises(TypeError):
        ppe.ExternalEncryptionConfiguration(
            footer_key="key", configuration_properties={})
    with pytest.raises(TypeError):
        ppe.ExternalDecryptionConfiguration(configuration_properties={})
    assert not hasattr(ppe.ExternalEncryptionConfiguration(footer_key="key"),
                       "configuration_properties")
    assert not hasattr(ppe.ExternalDecryptionConfiguration(),
                       "configuration_properties")


def test_decryption_configuration_properties():
    """Test the standard DecryptionConfiguration properties to avoid regressions."""

    config = ppe.DecryptionConfiguration()
    config.cache_lifetime = datetime.timedelta(minutes=5.0)

    assert isinstance(config, ppe.DecryptionConfiguration)
    assert config.cache_lifetime == datetime.timedelta(minutes=5.0)


def test_external_decryption_configuration_properties():
    """Test the ExternalDecryptionConfiguration properties
      including external-specific fields."""

    external_decryption_config = get_external_decryption_config()
    assert isinstance(
        external_decryption_config, ppe.ExternalDecryptionConfiguration)
    assert external_decryption_config.cache_lifetime == datetime.timedelta(
        minutes=10.0)
    assert external_decryption_config.app_context == APP_CONTEXT


def test_external_decryption_configuration_app_context():
    config = ppe.ExternalDecryptionConfiguration()
    assert config.app_context == {}

    config.app_context = {"a": 1}
    assert config.app_context == {"a": 1}

    with pytest.raises(ValueError, match="app_context must be JSON-serializable"):
        config.app_context = None

    with pytest.raises(TypeError, match="Failed to serialize app_context"):
        config.app_context = {"invalid": set([1, 2, 3])}


# Creating file encryption and decryption properties


def test_external_file_encryption_properties_rejects_column_in_two_places():
    """Ensure a column cannot be defined in both column_keys
    and per_column_encryption."""
    config = ppe.ExternalEncryptionConfiguration(
        footer_key="footer_key",
        column_keys={"orderid_key": ["a"]},
        per_column_encryption={"a": {
            "encryption_algorithm": "AES_GCM_V1",
            "encryption_key": "key_2"
        }},
    )
    factory = ppe.CryptoFactory(kms_client_factory)
    with pytest.raises(
        OSError,
        match=re.escape("Multiple keys defined for column [a]")
    ):
        factory.external_file_encryption_properties(
            get_kms_connection_config(), config)


def _decryption_properties_without_provider():
    crypto_factory = ppe.CryptoFactory(kms_client_factory)
    return crypto_factory.external_file_decryption_properties(
        get_kms_connection_config(), get_external_decryption_config())


def _encryption_properties_without_external_columns():
    # No provider is needed when no column uses EXTERNAL_PROTECT_V1.
    return get_external_encryption_properties(
        None, per_column_encryption={
            "orderId": {
                "encryption_algorithm": "AES_GCM_CTR_V1",
                "encryption_key": "orderid_key"
            }})


@pytest.mark.parametrize("make_properties, class_name", [
    (lambda: get_external_encryption_properties(XorParquetCryptoProvider()),
     "ExternalFileEncryptionProperties"),
    (_encryption_properties_without_external_columns,
     "ExternalFileEncryptionProperties"),
    (lambda: get_external_decryption_properties(XorParquetCryptoProvider()),
     "ExternalFileDecryptionProperties"),
    (_decryption_properties_without_provider,
     "ExternalFileDecryptionProperties"),
], ids=["encryption", "encryption_without_external_columns",
        "decryption", "decryption_without_provider"])
def test_external_file_properties_type(make_properties, class_name):
    """The classes are not exported from the public modules (they live in
    pyarrow._parquet), so check the name of the returned object."""
    assert make_properties().__class__.__name__ == class_name


def test_standard_properties_reject_external_configurations():
    """An external configuration passed to the standard methods would silently lose
    its per-column algorithms and application context."""
    crypto_factory = ppe.CryptoFactory(kms_client_factory)

    with pytest.raises(TypeError, match="external_file_encryption_properties"):
        crypto_factory.file_encryption_properties(
            get_kms_connection_config(), get_external_encryption_config())

    with pytest.raises(TypeError, match="external_file_decryption_properties"):
        crypto_factory.file_decryption_properties(
            get_kms_connection_config(), get_external_decryption_config())


def test_external_file_encryption_properties_requires_provider_for_external_column():
    with pytest.raises(OSError, match="parquet_crypto_provider must be set"):
        get_external_encryption_properties(None)


def test_external_file_level_algorithm_requires_provider():
    """With EXTERNAL_PROTECT_V1 as the file-level algorithm, the footer and every
    column in column_keys go through the provider."""
    with pytest.raises(
            OSError,
            match="parquet_crypto_provider must be set when using the "
                  "EXTERNAL_PROTECT_V1 algorithm"):
        get_external_encryption_properties(
            None, encryption_algorithm="EXTERNAL_PROTECT_V1",
            per_column_encryption={
                "orderId": {
                    "encryption_algorithm": "AES_GCM_CTR_V1",
                    "encryption_key": "orderid_key"
                },
            })


# Round trips


def test_read_and_write_standard_encryption(tmp_path):
    # Test a roundtrip encryption and decryption using standard encryption.
    round_trip_encryption_and_decryption(tmp_path, get_encryption_properties(),
                                         get_decryption_properties())


# The write scenarios of the original external encryption example: the defaults
# (SNAPPY + dictionary encoding), plain encoding without compression, and data page
# version 2.0.
WRITE_SCENARIOS = {
    "defaults": {},
    "plain_uncompressed": {"use_dictionary": False, "compression": "NONE"},
    "data_page_v2": {"data_page_version": "2.0"},
    "gzip_data_page_v2": {"data_page_version": "2.0", "compression": "GZIP"},
    "byte_stream_split": {"use_dictionary": False, "compression": "NONE",
                          "use_byte_stream_split": ["price"]},
}


@pytest.mark.parametrize("plaintext_footer", [True, False])
@pytest.mark.parametrize("encryption_algorithm", ["AES_GCM_V1", "AES_GCM_CTR_V1"])
@pytest.mark.parametrize("write_kwargs", WRITE_SCENARIOS.values(),
                         ids=WRITE_SCENARIOS.keys())
def test_read_and_write_external_encryption(
        tmp_path, write_kwargs, encryption_algorithm, plaintext_footer):
    """Mixed file: AES columns, columns encrypted by the provider and a plain
    column. Only the provider columns may reach the provider."""
    provider = XorParquetCryptoProvider()
    encryption_properties = get_external_encryption_properties(
        provider, encryption_algorithm=encryption_algorithm,
        plaintext_footer=plaintext_footer)

    round_trip_encryption_and_decryption(
        tmp_path, encryption_properties, get_external_decryption_properties(provider),
        **write_kwargs)

    assert provider.encrypt_block_calls > 0
    assert provider.decrypt_block_calls > 0
    assert provider.column_paths == EXTERNAL_COLUMNS
    assert [json.loads(context) for context in provider.app_contexts] == [APP_CONTEXT]


@pytest.mark.parametrize("plaintext_footer", [True, False])
def test_external_file_level_algorithm_round_trip(tmp_path, plaintext_footer):
    """productId uses the file-level algorithm, which is EXTERNAL_PROTECT_V1. The
    footer is signed (plaintext footer) or encrypted (encrypted footer) by the
    provider."""
    provider = XorParquetCryptoProvider()
    encryption_properties = get_external_encryption_properties(
        provider, encryption_algorithm="EXTERNAL_PROTECT_V1",
        plaintext_footer=plaintext_footer,
        per_column_encryption={
            "orderId": {
                "encryption_algorithm": "AES_GCM_CTR_V1",
                "encryption_key": "orderid_key"
            },
        })

    round_trip_encryption_and_decryption(
        tmp_path, encryption_properties, get_external_decryption_properties(provider))

    # The footer ("") and the column metadata of every column follow the file-level
    # algorithm, so the provider also sees orderId even though its pages use AES.
    assert provider.column_paths == {"", "productId", "orderId"}
    if plaintext_footer:
        assert provider.sign_footer_calls > 0
        assert provider.verify_footer_signature_calls > 0


def test_external_encryption_all_columns_external(tmp_path):
    provider = XorParquetCryptoProvider()
    table = get_data_table()
    per_column_encryption = {
        name: {"encryption_algorithm": "EXTERNAL_PROTECT_V1",
               "encryption_key": key}
        for name, key in [("orderId", "orderid_key"), ("productId", "productid_key"),
                          ("price", "price_key"), ("vat", "vat_key"),
                          ("customer_name", "customer_key")]
    }
    encryption_properties = get_external_encryption_properties(
        provider, per_column_encryption=per_column_encryption, column_keys={})

    path = round_trip_encryption_and_decryption(
        tmp_path, encryption_properties, get_external_decryption_properties(provider))

    assert provider.column_paths == set(table.column_names)
    # The plaintext values must not be readable on disk.
    assert b"customer_1" not in path.read_bytes()


def test_external_encrypted_columns_are_not_plaintext_on_disk(tmp_path):
    provider = XorParquetCryptoProvider()
    path = round_trip_encryption_and_decryption(
        tmp_path, get_external_encryption_properties(provider),
        get_external_decryption_properties(provider),
        use_dictionary=False, compression="NONE")
    assert b"customer_1" not in path.read_bytes()


def test_plaintext_footer_metadata_readable_without_decryption_properties(tmp_path):
    provider = XorParquetCryptoProvider()
    table = get_data_table()
    path = tmp_path / "plaintext_footer.parquet"
    write_parquet(table, path, get_external_encryption_properties(
        provider, plaintext_footer=True))

    metadata = pp.read_metadata(path)
    assert metadata.num_rows == table.num_rows
    assert metadata.num_columns == table.num_columns
    assert metadata.schema.to_arrow_schema().names == table.column_names


def test_encrypted_footer_requires_decryption_properties(tmp_path):
    provider = XorParquetCryptoProvider()
    path = tmp_path / "encrypted_footer.parquet"
    write_parquet(get_data_table(), path, get_external_encryption_properties(
        provider, plaintext_footer=False))

    with pytest.raises(OSError):
        pp.read_metadata(path)


def test_reading_aes_columns_does_not_require_provider(tmp_path):
    provider = XorParquetCryptoProvider()
    table = get_data_table()
    path = tmp_path / "mixed.parquet"
    write_parquet(table, path, get_external_encryption_properties(provider))

    decryption_properties = _decryption_properties_without_provider()

    provider.reset()
    columns = ["orderId", "productId", "vat"]
    read_table = read_parquet(path, decryption_properties, columns=columns)
    assert read_table.equals(table.select(columns))
    assert provider.decrypt_block_calls == 0

    with pytest.raises(OSError, match="parquet_crypto_provider must be set"):
        read_parquet(path, decryption_properties)


def test_provider_is_only_called_for_selected_external_columns(tmp_path):
    provider = XorParquetCryptoProvider()
    table = get_data_table()
    path = tmp_path / "mixed.parquet"
    write_parquet(table, path, get_external_encryption_properties(provider))
    decryption_properties = get_external_decryption_properties(provider)

    provider.reset()
    read_table = read_parquet(path, decryption_properties, columns=["price"])
    assert read_table.equals(table.select(["price"]))
    assert provider.column_paths == {"price"}

    provider.reset()
    read_table = read_parquet(path, decryption_properties, columns=["orderId", "vat"])
    assert read_table.equals(table.select(["orderId", "vat"]))
    assert provider.decrypt_block_calls == 0


def test_decrypting_with_standard_properties_fails(tmp_path):
    provider = XorParquetCryptoProvider()
    path = tmp_path / "mixed.parquet"
    write_parquet(get_data_table(), path, get_external_encryption_properties(provider))

    with pytest.raises(OSError):
        read_parquet(path, get_decryption_properties())


def test_external_encryption_with_multiple_row_groups(tmp_path):
    provider = XorParquetCryptoProvider()
    round_trip_encryption_and_decryption(
        tmp_path, get_external_encryption_properties(provider),
        get_external_decryption_properties(provider), row_group_size=128)
    assert provider.column_paths == EXTERNAL_COLUMNS
