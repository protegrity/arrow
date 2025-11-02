"""
use_external_dbpa_encryption.py

Use this script as a guide to use the external DBPA encryption library.
Current supported options are used.
"""

import base64
import pyarrow.parquet.encryption as ppe

"""
A sample KMS client that uses a map of master keys to wrap and unwrap keys.
"""
class FooKmsClient(ppe.KmsClient):

    def __init__(self, kms_connection_config):
        ppe.KmsClient.__init__(self)
        self.master_keys_map = kms_connection_config.custom_kms_conf
    
    def wrap_key(self, key_bytes, master_key_identifier):
        master_key_bytes = self.master_keys_map[master_key_identifier].encode('utf-8')
        joint_key = b"".join([master_key_bytes, key_bytes])
        return base64.b64encode(joint_key)

    def unwrap_key(self, wrapped_key, master_key_identifier):
        expected_master = self.master_keys_map[master_key_identifier]
        decoded_key = base64.b64decode(wrapped_key)
        master_key_bytes = decoded_key[:16]
        decrypted_key = decoded_key[16:]
        if (expected_master == master_key_bytes.decode('utf-8')):
            return decrypted_key
        raise ValueError(f"Bad master key used [{master_key_bytes}] - [{decrypted_key}]")

def kms_client_factory(kms_connection_config):
    return FooKmsClient(kms_connection_config)

if __name__ == "__main__":
    print("Using external DBPA encryption in Parquet Arrow")
    pass