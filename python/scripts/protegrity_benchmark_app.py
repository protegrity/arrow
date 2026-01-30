from base64 import b64decode, b64encode
from os import environ
from platform import system
from pyarrow.csv import read_csv, ReadOptions
from pyarrow.parquet import ParquetFile, read_metadata, write_table
from pyarrow.parquet.encryption import CryptoFactory, ExternalDecryptionConfiguration, ExternalEncryptionConfiguration, KmsClient, KmsConnectionConfig
from time import time


file_name = "random_names_100MM.txt"

class Protegrity(KmsClient):
    def __init__(
        self,
        kms_connection_config
    ):
        KmsClient.__init__(self)
        # Dummy KMS: map from master_key_identifier -> 16-byte master key string
        # (same approach as `FooKmsClient` in `base_app.py`).
        self.master_keys_map = kms_connection_config.custom_kms_conf
        
    def wrap_key(
        self,
        key_bytes,
        master_key_identifier
    ):
        master_key_bytes = self.master_keys_map[master_key_identifier].encode("utf-8")
        joint_key = b"".join([master_key_bytes, key_bytes])
        return b64encode(joint_key)

    def unwrap_key(
        self,
        wrapped_key,
        master_key_identifier
    ):
        expected_master = self.master_keys_map[master_key_identifier]
        decoded_key = b64decode(wrapped_key)
        master_key_bytes = decoded_key[:16]
        decrypted_key = decoded_key[16:]
        if expected_master == master_key_bytes.decode("utf-8"):
            return decrypted_key
        raise ValueError(
            f"Bad master key used [{master_key_bytes}] - [{decrypted_key}]"
        )


def get_kms_connection_config():
    # Dummy KMS: provide a 16-byte "master key" per key identifier used below.
    # Note: values must be exactly 16 bytes to match `unwrap_key()` slicing.
    return KmsConnectionConfig(custom_kms_conf={
        "aws_km_key_id1": "0123456789abcdef",
        "aws_km_key_id2": "fedcba9876543210",
    })


def kms_client_factory(kms_connection_config):
    return Protegrity(kms_connection_config=kms_connection_config)


def get_configuration_properties():
    return {
        "EXTERNAL_DBPA_V1": {
            "agent_decrypt_timeout_ms": "35000",
            "agent_encrypt_timeout_ms": "35000",
            "agent_init_timeout_ms": "15000",
            "agent_library_path": environ.get(
                "DBPA_LIBRARY_PATH", 
                "libDBPATestAgent.so" if system() == "Linux" else "libDBPATestAgent.dylib"
            )
        }
    }


crypto_factory = CryptoFactory(kms_client_factory=kms_client_factory)

decryption_properties = crypto_factory.external_file_decryption_properties(
    decryption_config=ExternalDecryptionConfiguration(
        app_context={"user_id": "abc.xyz"},
        configuration_properties=get_configuration_properties(),
    ),
    kms_connection_config=get_kms_connection_config()
)

encryption_properties = crypto_factory.external_file_encryption_properties(
    # Note: key identifiers must exist in `get_kms_connection_config().custom_kms_conf`.
    external_encryption_config=ExternalEncryptionConfiguration(
        app_context={"user_id": "abc.xyz"},
        configuration_properties=get_configuration_properties(),
        footer_key="aws_km_key_id1",
        per_column_encryption={
            "full_name": {
               "encryption_algorithm": "EXTERNAL_DBPA_V1", # AES_GCM_CTR_V1, EXTERNAL_DBPA_V1
               "encryption_key": "aws_km_key_id2"
            }
        },
        plaintext_footer=False
    ), 
    kms_connection_config=get_kms_connection_config()
)

sample_data = read_csv(
    input_file=file_name, 
    read_options=ReadOptions(column_names=["full_name"])
)

with open(file="start_time.txt", mode="w") as file:
    file.write(str(object=time()))
print("#######################################################################################################")
print("Writing to protegrity.parquet...")
write_table(
    compression="NONE",
    encryption_properties=encryption_properties,
    table=sample_data,
    use_dictionary=False,
    where="protegrity.parquet"
)
print("Written to protegrity.parquet")
print("#######################################################################################################")

# print("#######################################################################################################")
# print("Reading metadata...")
# print(read_metadata(
#     decryption_properties=decryption_properties,
#     where="protegrity.parquet"))
# print("Read metadata")
# print("#######################################################################################################")

# print("#######################################################################################################")
# print("Reading protegrity.parquet...")
# print(ParquetFile(
#     decryption_properties=decryption_properties, 
#     source="protegrity.parquet"
# ).read())
# print("Read protegrity.parquet")
print("#######################################################################################################")
with open(file="end_time.txt", mode="w") as file:
    file.write(str(object=time()))
