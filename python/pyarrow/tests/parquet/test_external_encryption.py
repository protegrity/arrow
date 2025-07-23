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
from datetime import  timedelta
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe
PARQUET_NAME = 'encrypted_table.in_mem.parquet'
FOOTER_KEY = b"0123456789112345"
FOOTER_KEY_NAME = "footer_key"
COL_KEY = b"1234567890123450"
COL_KEY_NAME = "col_key"

def test_encrypted_external_config(tempdir):
    """Write an encrypted parquet, verify it's encrypted, and then read it."""

    config = pe.EncryptionConfiguration(
        footer_key=FOOTER_KEY_NAME,
        column_keys={
            COL_KEY_NAME: ["a", "b"],
        },
        encryption_algorithm="AES_GCM_V1",
        cache_lifetime=timedelta(minutes=5.0),
        data_key_length_bits=256)

    assert isinstance(config, pe.EncryptionConfiguration)

    config = pe.ExternalEncryptionConfig(
        user_id="Picard1701",
        column_encryption={
            "a": {
                "encryption_algorithm": "AES_GCM",
                "encryption_key": "key_1"
            },
            "b": {
                "encryption_algorithm": "EXTERNAL",
                "encryption_key": "key_n"
            }
        },
        app_context={
            "user_id": "Picard1701",
            "location": "Presidio"
        },
        connection_config={
            "config_file": "path/to/config/file",
            "config_file_decryption_key": "some_key"
        }
    )
    assert isinstance(config, pe.ExternalEncryptionConfig)

    #print(config.column_encryption)
    #print(config.app_context)
    #print(config.connection_config)