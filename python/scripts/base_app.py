"""
base_app.py

@author sbrenes
"""

import base64
import datetime
import os
import pyarrow
import pyarrow.parquet as pp
import pyarrow.parquet.encryption as ppe

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


def write_parquet(table, location, encryption_config=None):
    encryption_properties = None

    if encryption_config:
        crypto_factory = ppe.CryptoFactory(kms_client_factory)
        encryption_properties = crypto_factory.external_file_encryption_properties(
            get_kms_connection_config(), encryption_config)

    #writer = pp.ParquetWriter(location, table.schema, encryption_properties=encryption_properties)
    #writer.write_table(table)

    pp.write_table(table, location, use_dictionary=True,
        encryption_properties=encryption_properties, 
        compression="NONE",
        use_byte_stream_split=False)#,
        #column_encoding={
        #    "orderId": "PLAIN",
        #    "productId": "PLAIN",
        #    "price": "PLAIN",
        #    "vat": "PLAIN"
        #})


def encrypted_data_and_footer_sample(data_table):
    parquet_path = "sample.parquet"
    encryption_config = get_external_encryption_config()
    write_parquet(data_table, parquet_path,
                  encryption_config=encryption_config)
    print(f"Written to [{parquet_path}]")


def create_and_encrypt_parquet():
    sample_data = {
        "orderId": [1001, 1002, 1003],
        "productId": [152, 268, 6548],
        "price": [3.25, 6.48, 2.12],
        "vat": [0.0, 0.2, 0.05],
        "customer_name": ["Alice", "Bob", "Charlotte"]
    }
    data_table = pyarrow.Table.from_pydict(sample_data)

    print("\nWriting parquet.")

    encrypted_data_and_footer_sample(data_table)


def read_and_print_parquet():
    print("\n-----------------------------------------------\nNow reading parquet file")
    parquet_path = "sample.parquet"

    metadata = pp.read_metadata(parquet_path)
    print("\nMetadata:")
    print(metadata)
    print("\n")

    decryption_config = get_external_decryption_config()
    read_data_table = read_parquet(parquet_path,
                                   decryption_config=decryption_config)
    data_frame = read_data_table.to_pandas()
    print("\Decrypted data:")
    print(data_frame.head())
    print("\n")


def read_parquet(location, decryption_config=None, read_metadata=False):
    decryption_properties = None

    if decryption_config:
        crypto_factory = ppe.CryptoFactory(kms_client_factory)
        decryption_properties = crypto_factory.external_file_decryption_properties(
            get_kms_connection_config(), decryption_config)
    
    if read_metadata:
        metadata = pp.read_metadata(location, decryption_properties=decryption_properties)
        return metadata

    data_table = pp.ParquetFile(location, decryption_properties=decryption_properties).read()
    return data_table


def get_kms_connection_config():
    return ppe.KmsConnectionConfig(
        custom_kms_conf={
            "footer_key": "012footer_secret",
            "orderid_key": "column_secret001",
            "productid_key": "column_secret002",
            "price_key": "column_secret003",
            "customer_key": "column_secret004"
        }
    )

def get_external_encryption_config(plaintext_footer=True):
    return ppe.ExternalEncryptionConfiguration(
        footer_key = "footer_key",
        column_keys = {
            "productid_key": ["productId"]
        },
        encryption_algorithm = "AES_GCM_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits = 128,
        plaintext_footer=plaintext_footer,
        per_column_encryption = {
            "orderId": {
                "encryption_algorithm": "EXTERNAL_DBPA_V1",
                "encryption_key": "orderid_key"
            },
            "price": {
                "encryption_algorithm": "EXTERNAL_DBPA_V1", #"AES_GCM_CTR_V1",
                "encryption_key": "price_key"
            },
            "customer_name": {
                "encryption_algorithm": "EXTERNAL_DBPA_V1",
                "encryption_key": "customer_key"
            }
        },
        app_context = {
            "user_id": "Picard1701",
            "location": "Presidio"
        },
        connection_config = get_dbpa_connection_config()
    )

def get_encryption_config(plaintext_footer=True):
    return ppe.EncryptionConfiguration(
        footer_key = "footer_key",
        column_keys = {
            "orderid_key": ["orderId"],
            "productid_key": ["productId"]
        },
        encryption_algorithm = "AES_GCM_CTR_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits = 128,
        plaintext_footer=plaintext_footer
    )

def get_decryption_config():
    return ppe.DecryptionConfiguration(cache_lifetime=datetime.timedelta(minutes=2.0))

def get_external_decryption_config():
    return ppe.ExternalDecryptionConfiguration(
        cache_lifetime=datetime.timedelta(minutes=2.0),
        app_context = {
            "user_id": "Picard1701",
            "location": "Presidio"
        },
        connection_config = get_dbpa_connection_config()
    )

def get_dbpa_connection_config():
    #we read the name of the external DBPA agent library from the environment variable DBPA_LIBRARY_PATH.
    #if not available, we use the default to 'libDBPATestAgent.so'.
    #this library performs key-indenpendent, XOR encryption/decryption, and is built as part of the Parquet Arrow tests.
    #It is located in cpp/src/parquet/encryption/external/dbpa_test_agent.cc
    agent_library_path = os.environ.get('DBPA_LIBRARY_PATH', 'libDBPATestAgent.so')
    script_directory = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_directory, 'test_connection_config_file.json')

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Connection config file not found at [${config_path}]")

    connection_config = {
        "EXTERNAL_DBPA_V1": {
            "agent_library_path": agent_library_path,
            "connection_config_file_path": config_path,
            "init_timeout_ms": "15000",
            "encrypt_timeout_ms": "35000",
            "decrypt_timeout_ms": "35000"
        }
    }

    #server_url is not needed by 'libDBPATestAgent.so'
    server_url = os.environ.get('DBPA_SERVER_URL')

    if server_url is not None:
        connection_config["EXTERNAL_DBPA_V1"]["server_url"] = server_url

    return connection_config


if __name__ == "__main__":
    create_and_encrypt_parquet()
    read_and_print_parquet()
    print("\nPlayground finished!\n")
