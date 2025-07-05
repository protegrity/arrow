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
import pytest
from datetime import timedelta

import pyarrow as pa
try:
    import pyarrow.parquet as pq
    import pyarrow.parquet.encryption as pe
except ImportError:
    pq = None
    pe = None
else:
    from pyarrow.tests.parquet.encryption import (
        InMemoryKmsClient, verify_file_encrypted)


PARQUET_NAME = 'encrypted_table.in_mem.parquet'
FOOTER_KEY = b"0123456789112345"
FOOTER_KEY_NAME = "footer_key"
COL_KEY = b"1234567890123450"
COL_KEY_NAME = "col_key"


# Marks all of the tests in this module
# Ignore these with pytest ... -m 'not parquet_encryption'
# Ignore these with pytest ... -m 'not parquet'
pytestmark = [
    pytest.mark.parquet_encryption,
    pytest.mark.parquet
]


@pytest.fixture(scope='module')
def data_table():
    data_table = pa.Table.from_pydict({
        'a': pa.array([1, 2, 3]),
        'b': pa.array(['a', 'b', 'c']),
        'c': pa.array(['x', 'y', 'z'])
    })
    return data_table


@pytest.fixture(scope='module')
def basic_encryption_config():
    basic_encryption_config = pe.EncryptionConfiguration(
        footer_key=FOOTER_KEY_NAME,
        column_keys={
            COL_KEY_NAME: ["a", "b"],
        })
    return basic_encryption_config


def setup_encryption_environment(custom_kms_conf):
    """
    Sets up and returns the KMS connection configuration and crypto factory
    based on provided KMS configuration parameters.
    """
    kms_connection_config = pe.KmsConnectionConfig(custom_kms_conf=custom_kms_conf)

    def kms_factory(kms_connection_configuration):
        return InMemoryKmsClient(kms_connection_configuration)

    # Create our CryptoFactory
    crypto_factory = pe.CryptoFactory(kms_factory)

    return kms_connection_config, crypto_factory


def write_encrypted_file(path, data_table, footer_key_name, col_key_name,
                         footer_key, col_key, encryption_config):
    """
    Writes an encrypted parquet file based on the provided parameters.
    """
    # Setup the custom KMS configuration with provided keys
    custom_kms_conf = {
        footer_key_name: footer_key.decode("UTF-8"),
        col_key_name: col_key.decode("UTF-8"),
    }

    # Setup encryption environment
    kms_connection_config, crypto_factory = setup_encryption_environment(
        custom_kms_conf)

    # Write the encrypted parquet file
    write_encrypted_parquet(path, data_table, encryption_config,
                            kms_connection_config, crypto_factory)

    return kms_connection_config, crypto_factory


def test_encrypted_parquet_write_read(tempdir, data_table):
    """Write an encrypted parquet, verify it's encrypted, and then read it."""
    path = tempdir / PARQUET_NAME

    # Encrypt the footer with the footer key,
    # encrypt column `a` and column `b` with another key,
    # keep `c` plaintext
    encryption_config = pe.EncryptionConfiguration(
        footer_key=FOOTER_KEY_NAME,
        column_keys={
            COL_KEY_NAME: ["a", "b"],
        },
        encryption_algorithm = "EXTERNAL_V1",
        plaintext_footer=True,
        cache_lifetime=timedelta(minutes=5.0),
        data_key_length_bits=256)

    kms_connection_config, crypto_factory = write_encrypted_file(
        path, data_table, FOOTER_KEY_NAME, COL_KEY_NAME, FOOTER_KEY, COL_KEY,
        encryption_config)

    verify_file_encrypted(path)

    # Read with decryption properties
    decryption_config = pe.DecryptionConfiguration(
        cache_lifetime=timedelta(minutes=5.0))
    result_table = read_encrypted_parquet(
        path, decryption_config, kms_connection_config, crypto_factory)
    assert data_table.equals(result_table)


def write_encrypted_parquet(path, table, encryption_config,
                            kms_connection_config, crypto_factory):
    file_encryption_properties = crypto_factory.file_encryption_properties(
        kms_connection_config, encryption_config)
    assert file_encryption_properties is not None
    with pq.ParquetWriter(
            path, table.schema,
            encryption_properties=file_encryption_properties) as writer:
        writer.write_table(table)


def read_encrypted_parquet(path, decryption_config,
                           kms_connection_config, crypto_factory):
    file_decryption_properties = crypto_factory.file_decryption_properties(
        kms_connection_config, decryption_config)
    assert file_decryption_properties is not None
    meta = pq.read_metadata(
        path, decryption_properties=file_decryption_properties)
    assert meta.num_columns == 3
    schema = pq.read_schema(
        path, decryption_properties=file_decryption_properties)
    assert len(schema.names) == 3

    result = pq.ParquetFile(
        path, decryption_properties=file_decryption_properties)
    return result.read(use_threads=True)


