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

"""Test doubles for the external encryption tests.

Imports pyarrow.parquet.encryption unconditionally, so test modules must
pytest.importorskip() this module.
"""

import base64
import threading

import pyarrow.parquet.encryption as ppe


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class XorKmsClient(ppe.KmsClient):
    """Trivial KmsClient: "wraps" a key by XOR-ing it with the master key.

    The wrapped key is stored in the file as text, so it is base64 encoded.
    """

    def __init__(self, kms_connection_config):
        ppe.KmsClient.__init__(self)
        self.master_keys_map = kms_connection_config.custom_kms_conf

    def wrap_key(self, key_bytes, master_key_identifier):
        master_key = self.master_keys_map[master_key_identifier].encode("utf-8")
        return base64.b64encode(xor_bytes(key_bytes, master_key))

    def unwrap_key(self, wrapped_key, master_key_identifier):
        master_key = self.master_keys_map[master_key_identifier].encode("utf-8")
        return xor_bytes(base64.b64decode(wrapped_key), master_key)


def xor_kms_client_factory(kms_connection_config):
    return XorKmsClient(kms_connection_config)


class XorParquetCryptoProvider(ppe.ParquetCryptoProvider):
    """Block path and footer signing via XOR: deterministic and reversible, enough
    to prove the Python callbacks run. Not a real cipher.

    Records every call so tests can check which columns reached the provider and
    which application context it received.
    """

    def __init__(self):
        ppe.ParquetCryptoProvider.__init__(self)
        self._lock = threading.Lock()
        self.encrypt_block_calls = 0
        self.decrypt_block_calls = 0
        self.sign_footer_calls = 0
        self.verify_footer_signature_calls = 0
        self.column_paths = set()
        self.app_contexts = set()

    def _record(self, counter, column_path, app_context):
        with self._lock:
            setattr(self, counter, getattr(self, counter) + 1)
            self.column_paths.add(column_path)
            self.app_contexts.add(app_context)

    def encrypt_block(self, plaintext, key_metadata, column_path,
                      app_context, module_aad, dek):
        self._record("encrypt_block_calls", column_path, app_context)
        return xor_bytes(plaintext, dek)

    def decrypt_block(self, ciphertext, key_metadata, column_path,
                      app_context, module_aad, dek):
        self._record("decrypt_block_calls", column_path, app_context)
        return xor_bytes(ciphertext, dek)

    def sign_footer(self, footer_bytes, key_metadata, column_path,
                    app_context, footer_aad, dek):
        self._record("sign_footer_calls", column_path, app_context)
        return xor_bytes(footer_aad + footer_bytes, dek)

    def verify_footer_signature(self, footer_bytes, stored_signature, key_metadata,
                                column_path, app_context, footer_aad, dek):
        self._record("verify_footer_signature_calls", column_path, app_context)
        return xor_bytes(footer_aad + footer_bytes, dek) == stored_signature

    def reset(self):
        with self._lock:
            self.encrypt_block_calls = 0
            self.decrypt_block_calls = 0
            self.sign_footer_calls = 0
            self.verify_footer_signature_calls = 0
            self.column_paths = set()
            self.app_contexts = set()
