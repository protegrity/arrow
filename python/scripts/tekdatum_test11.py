import base64
import datetime
import time
import pyarrow
import pyarrow.parquet as pp
import pyarrow.parquet.encryption as ppe
import json
from pyarrow.parquet import ParquetFile
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
        master_key_bytes = expected_master.encode('utf-8')  # Use this to get the correct length
        decoded_key = base64.b64decode(wrapped_key)

        prefix_len = len(master_key_bytes)
        actual_prefix = decoded_key[:prefix_len]
        decrypted_key = decoded_key[prefix_len:]

        if actual_prefix == master_key_bytes:
            return decrypted_key
        raise ValueError(f"Bad master key used [{actual_prefix}] - [{decrypted_key}]")


def kms_client_factory(kms_connection_config):
    return FooKmsClient(kms_connection_config)


def write_parquet(table, location, encryption_config=None):
    encryption_properties = None

    if encryption_config:
        crypto_factory = ppe.CryptoFactory(kms_client_factory)
        encryption_properties = crypto_factory.file_encryption_properties(
            get_kms_connection_config(), encryption_config)

    writer = pp.ParquetWriter(
        location,
        table.schema,
        encryption_properties=encryption_properties,
        compression='NONE'
    )

    # Enforce chunking into row groups of 5 rows each
    for batch in table.to_batches(max_chunksize=5):
        writer.write_table(pyarrow.Table.from_batches([batch]))

    writer.close()


def encrypted_data_and_footer_sample(data_table):
    parquet_path = "sample12.parquet"
    encryption_config = get_encryption_config()
    write_parquet(data_table, parquet_path, encryption_config=encryption_config)
    print(f"Written to [{parquet_path}]")

# Function to generate a 10KB string
def generate_10kb_string():
    return "A" * 10240  # 10 KB = 10 * 1024 bytes

def create_and_encrypt_parquet(shared_10kb_string):
    sample_data = {
        "transport_mode": [
            "Automobile", "Public Bus", "Electric Bicycle", "Motor Scooter",
            "High-Speed Train", "Underground Subway", "Light Rail Transit",
            "Commercial Airplane", "Private Helicopter", "Passenger Ferry",
            "Cruise Ship", "Licensed Taxicab", "Ride-Sharing Service",
            "Electric Kick Scooter", "All-Terrain Skateboard", "Pedestrian Walking",
            "Equestrian Horseback Riding", "Suspended Cable Car",
            "Hot Air Balloon Ride", "Orbital Spacecraft"
        ],
        "price": [
            1.25, 1.50, 2.15, 2.99, 3.10,
            3.85, 4.25, 4.99, 5.45, 5.99,
            6.75, 6.80, 7.35, 7.90, 8.40,
            8.95, 9.30, 9.85, 10.20, 999.99
        ],
        "order": list(range(1, 21)),
        "available": [
            True, True, True, False, True,
            True, False, True, False, True,
            True, True, False, True, True,
            True, True, False, False, False
        ],
        "json_column": [shared_10kb_string for _ in range(20)]

    }
    data_table = pyarrow.Table.from_pydict(sample_data)

    print("\nPyarrow table with transport_mode, price, and json_column created. Writing encrypted parquet file.")

    encrypted_data_and_footer_sample(data_table)

    print("\nPlayground finished!\n")


def get_kms_connection_config():
    return ppe.KmsConnectionConfig(
        custom_kms_conf={
            "transport_key": "transport_secret_123",
            "price_key": "price_secret_456",
            "order_key": "order_secret_789",
            "available_key": "available_secret_abc",
            "footer_key": "footer_secret",
            "json_key": "json_secret_123"
        }
    )


def get_encryption_config(plaintext_footer=False):
    return ppe.EncryptionConfiguration(
        footer_key="footer_key",
        column_keys={
            "transport_key": ["transport_mode"],
            "price_key": ["price"],
            "order_key": ["order"],
            "available_key": ["available"],
            "json_key": ["json_column"]  # Add json_key encryption
        },
        encryption_algorithm="AES_GCM_V1",
        cache_lifetime=datetime.timedelta(minutes=2),
        data_key_length_bits=128,
        plaintext_footer=plaintext_footer
    )

def read_encrypted_parquet(parquet_path):
    crypto_factory = ppe.CryptoFactory(kms_client_factory)
    decryption_props = crypto_factory.file_decryption_properties(get_kms_connection_config())

    pf = pp.ParquetFile(parquet_path, decryption_properties=decryption_props)
    table = pf.read()

    # Print column names
    print("Columns:", table.column_names)

    # Print each row
    num_rows = table.num_rows
    for i in range(num_rows):
        row = {name: table[name][i].as_py() for name in table.column_names}
        print(f"Row {i + 1}: {row}")


if __name__ == "__main__":
    shared_10kb_string = generate_10kb_string()

    encrypt_start = time.perf_counter()
    create_and_encrypt_parquet(shared_10kb_string)
    encrypt_end = time.perf_counter()
    
    print("\nReading back encrypted file...")

    read_start = time.perf_counter()
    read_encrypted_parquet("sample12.parquet")
    read_end = time.perf_counter()

    encrypt_duration = encrypt_end - encrypt_start
    read_duration = read_end - read_start
    print(f"\nEncryption duration: {encrypt_duration:.4f} seconds")
    print(f"Read duration: {read_duration:.4f} seconds")