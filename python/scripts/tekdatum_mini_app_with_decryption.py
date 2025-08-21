"""
tekdatum_mini_app_with_decryption.py

Extended version that demonstrates both encryption and decryption
with external encryption using the new bindings.

@author sbrenes (original)
@author assistant (updated with decryption)
"""

import base64
import datetime
import os
import sys
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
    """Write parquet file with optional external encryption."""
    external_encryption_properties = None

    if encryption_config:
        crypto_factory = ppe.CryptoFactory(kms_client_factory)
        external_encryption_properties = crypto_factory.external_file_encryption_properties(
            get_kms_connection_config(), encryption_config, get_external_encryption_config(),
            get_external_connection_config())
        
        print("--------------------------")
        print("External Encryption Properties Created:")
        print("Type:", type(external_encryption_properties))
        print("MRO (class + superclasses):")
        for cls in type(external_encryption_properties).mro():
            print("  ", cls)
        print("--------------------------")

    writer = pp.ParquetWriter(location, table.schema,
                              encryption_properties=external_encryption_properties)
    writer.write_table(table)
    print(f"✅ Successfully wrote encrypted parquet file: {location}")


def create_sample_data():
    """Create sample data for testing."""
    sample_data = {
        "orderId": [1001, 1002, 1003, 1004, 1005],
        "productId": [152, 268, 6548, 789, 456],
        "price": [3.25, 6.48, 2.12, 9.99, 15.50],
        "vat": [0.0, 0.2, 0.05, 0.1, 0.15],
        "customer_name": ["Alice", "Bob", "Charlie", "Diana", "Eve"],
        "order_date": ["2024-01-15", "2024-01-16", "2024-01-17", "2024-01-18", "2024-01-19"]
    }    
    return pyarrow.Table.from_pydict(sample_data)


def create_and_encrypt_parquet():
    """Create and encrypt a parquet file with external encryption."""
    print("\n" + "="*60)
    print("STEP 1: CREATING AND ENCRYPTING PARQUET FILE")
    print("="*60)
    
    data_table = create_sample_data()
    print(f"✅ Created sample data table with {len(data_table)} rows and {len(data_table.schema)} columns")
    print(f"   Schema: {[field.name for field in data_table.schema]}")
    
    parquet_path = "sample_external_encrypted.parquet"
    encryption_config = get_encryption_config()
    
    print(f"\n🔐 Encrypting with EXTERNAL_V1 algorithm...")
    write_parquet(data_table, parquet_path, encryption_config=encryption_config)
    
    return parquet_path


def test_external_decryption_bindings():
    """Test the new external decryption bindings."""
    print("\n" + "="*60)
    print("STEP 2: TESTING EXTERNAL DECRYPTION BINDINGS")
    print("="*60)
    
    try:
        # Create configurations
        kms_connection_config = get_kms_connection_config()
        decryption_config = get_decryption_config()
        external_encryption_config = get_external_encryption_config()
        external_connection_config = get_external_connection_config()
        
        print("✅ Created configurations:")
        print(f"   - KMS Connection Config: {kms_connection_config}")
        print(f"   - Decryption Config: {decryption_config}")
        print(f"   - External Encryption Config: {external_encryption_config}")
        print(f"   - External Connection Config: {external_connection_config}")
        
        # Create crypto factory
        crypto_factory = ppe.CryptoFactory(kms_client_factory)
        
        print("✅ Created crypto factory with KMS client")
        
        # Test the new external decryption method
        print("\n🔓 Testing external_file_decryption_properties() method...")
        external_decryption_properties = crypto_factory.external_file_decryption_properties(
            kms_connection_config,
            decryption_config,
            external_encryption_config,
            external_connection_config
        )
        
        print("✅ Successfully created external decryption properties!")
        print(f"   Type: {type(external_decryption_properties)}")
        print(f"   Properties: {external_decryption_properties}")
        
        # Print basic info about the properties
        print(f"   - Properties object created successfully")
        
        return external_decryption_properties
        
    except Exception as e:
        print(f"❌ Failed to create external decryption properties: {e}")
        print(f"   Error type: {type(e).__name__}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return None


def read_with_external_decryption(parquet_path, external_decryption_properties):
    """Read parquet file using external decryption properties."""
    print(f"\n📖 Reading file with external decryption: {parquet_path}")
    
    try:
        # Read metadata first
        print("   Reading metadata...")
        metadata = pp.read_metadata(parquet_path, decryption_properties=external_decryption_properties)
        print(f"   ✅ Metadata read successfully")
        print(f"   - Num row groups: {metadata.num_row_groups}")
        print(f"   - Num columns: {metadata.num_columns}")
        print(f"   - Total rows: {metadata.num_rows}")
        
        # Print encryption info from metadata
        print(f"   - Created by: {metadata.created_by}")
        
        # Read the actual data
        print("   Reading data...")
        data_table = pp.ParquetFile(parquet_path, decryption_properties=external_decryption_properties).read()
        
        print(f"   ✅ Data read successfully!")
        print(f"   - Retrieved {len(data_table)} rows")
        print(f"   - Retrieved {len(data_table.schema)} columns")
        
        return data_table
        
    except Exception as e:
        print(f"   ❌ Failed to read with external decryption: {e}")
        print(f"   Error type: {type(e).__name__}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return None


def read_with_regular_decryption(parquet_path):
    """Read parquet file using regular decryption as fallback."""
    print(f"\n📖 Reading file with regular decryption (fallback): {parquet_path}")
    
    try:
        decryption_config = get_decryption_config()
        crypto_factory = ppe.CryptoFactory(kms_client_factory)
        decryption_properties = crypto_factory.file_decryption_properties(
            get_kms_connection_config(), decryption_config)
        
        # Read metadata first
        print("   Reading metadata...")
        metadata = pp.read_metadata(parquet_path, decryption_properties=decryption_properties)
        print(f"   ✅ Metadata read successfully")
        
        # Read the actual data
        print("   Reading data...")
        data_table = pp.ParquetFile(parquet_path, decryption_properties=decryption_properties).read()
        
        print(f"   ✅ Data read successfully with regular decryption!")
        print(f"   - Retrieved {len(data_table)} rows")
        
        return data_table
        
    except Exception as e:
        print(f"   ❌ Failed to read with regular decryption: {e}")
        print(f"   Error type: {type(e).__name__}")
        return None


def compare_data(original_data, decrypted_data, method_name):
    """Compare original and decrypted data."""
    print(f"\n🔍 Comparing data ({method_name}):")
    
    if original_data is None or decrypted_data is None:
        print("   ❌ Cannot compare - missing data")
        return False
    
    try:
        # Convert to pandas for easier comparison
        original_df = original_data.to_pandas()
        decrypted_df = decrypted_data.to_pandas()
        
        print(f"   Original shape: {original_df.shape}")
        print(f"   Decrypted shape: {decrypted_df.shape}")
        
        # Print first and last 20 characters of data for debugging
        original_str = str(original_df.to_string())
        decrypted_str = str(decrypted_df.to_string())
        
        print(f"   Original data (first 50 chars):\n\t\t\t'{original_str[:50]}'")
        print(f"   Original data (last 50 chars):\n\t\t\t'{original_str[-50:]}'")
        print(f"   Decrypted data (first 50 chars):\n\t\t\t'{decrypted_str[:50]}'")
        print(f"   Decrypted data (last 50 chars):\n\t\t\t'{decrypted_str[-50:]}'")
        
        # Check if shapes match
        if original_df.shape != decrypted_df.shape:
            print("   ❌ Shapes don't match!")
            return False
        
        # Check if data matches
        if original_df.equals(decrypted_df):
            print("   ✅ Data matches perfectly!")
            return True
        else:
            print("   ❌ Data doesn't match!")
            print("   Original data:")
            print(original_df.head())
            print("   Decrypted data:")
            print(decrypted_df.head())
            return False
            
    except Exception as e:
        print(f"   ❌ Error during comparison: {e}")
        return False


def read_and_print_parquet(parquet_path, original_data):
    """Read and compare parquet file using different decryption methods."""
    print("\n" + "="*60)
    print("STEP 3: READING AND COMPARING ENCRYPTED FILE")
    print("="*60)
    
    # Test external decryption bindings first
    external_decryption_properties = test_external_decryption_bindings()
    
    if external_decryption_properties:
        # Try reading with external decryption
        external_data = read_with_external_decryption(parquet_path, external_decryption_properties)
        
        if external_data is not None:
            # Compare with original
            external_success = compare_data(original_data, external_data, "External Decryption")
            
            if external_success:
                print("\n🎉 SUCCESS: External decryption worked perfectly!")
                print("   Data was successfully encrypted and decrypted using external encryption.")
                return True
            else:
                print("\n⚠️  External decryption completed but data doesn't match.")
        else:
            print("\n⚠️  External decryption failed.")
    else:
        print("\n⚠️  Could not create external decryption properties.")
    
    # # Fallback to regular decryption
    # print("\n🔄 Falling back to regular decryption...")
    # regular_data = read_with_regular_decryption(parquet_path)
    
    # if regular_data is not None:
    #     regular_success = compare_data(original_data, regular_data, "Regular Decryption")
        
    #     if regular_success:
    #         print("\n✅ SUCCESS: Regular decryption worked!")
    #         print("   Note: This suggests the file was encrypted with standard encryption, not external.")
    #         return True
    #     else:
    #         print("\n❌ Regular decryption also failed to match data.")
    # else:
    #     print("\n❌ Regular decryption also failed.")
    
    return False


def cleanup_files(parquet_path):
    """Clean up test files."""
    print("\n" + "="*60)
    print("STEP 4: CLEANUP")
    print("="*60)
    
    try:
        if os.path.exists(parquet_path):
            os.remove(parquet_path)
            print(f"✅ Removed test file: {parquet_path}")
        else:
            print(f"⚠️  Test file not found: {parquet_path}")
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")


def get_kms_connection_config():
    return ppe.KmsConnectionConfig(
        custom_kms_conf={
            "footer_key": "012footer_secret",
            "orderid_key": "column_secret001",
            "productid_key": "column_secret002"
        }
    )


def get_encryption_config(plaintext_footer=True):
    return ppe.EncryptionConfiguration(
        footer_key = "footer_key",
        column_keys = {
            "orderid_key": ["orderId"],
            "productid_key": ["productId"]
        },
        encryption_algorithm = "EXTERNAL_V1",
        cache_lifetime=datetime.timedelta(minutes=2.0),
        data_key_length_bits = 128,
        plaintext_footer=plaintext_footer
    )

def get_external_encryption_config():
    return ppe.ExternalEncryptionConfiguration(
        user_id = "Picard_NCC1701_E",
        # These are temporarily defined as strings for the mini app example. They should be
        # regular dictionaries.
        ext_column_keys = "\"keyId\": \"NumericID001\"",
        app_context = get_application_context_string()
    )

def get_application_context_string():
    schema1 = "    \"column_schema\" = {\n      \"database\": \"public\",\n      \"schema\":"
    schema2 = " \"Federation\",\n      \"table\": \"Customers\",\n    },"
    location1 = "\n    \"location\": {\n      \"country\": \"US\",\n      \"region\": \"CA\","
    location2 = "\n      \"lat\": 37.7749,\n      \"lon\": -122.4191\n    }"
    return schema1 + schema2 + location1 + location2

def get_external_connection_config():
    return ppe.ExternalConnectionConfiguration(
        config_path = "path/to/deck/ten/forward.config"
    )

def get_decryption_config():
    return ppe.DecryptionConfiguration(
        cache_lifetime=datetime.timedelta(minutes=2.0),
        # Note: The decryption algorithm should match the encryption algorithm
        # For external encryption, this should be EXTERNAL_V1
        # However, DecryptionConfiguration doesn't have an algorithm parameter
        # The algorithm is determined by the encrypted file metadata
    )


def main():
    """Main function to run the complete test workflow."""
    print("🚀 Tekdatum Mini App with External Decryption - Extended Version")
    print("This demonstrates the complete encrypt/decrypt cycle with external encryption.")
    print("="*80)
    
    try:
        # Step 1: Create and encrypt
        original_data = create_sample_data()
        parquet_path = create_and_encrypt_parquet()
        
        # Step 2: Read and compare
        success = read_and_print_parquet(parquet_path, original_data)
        
        # Step 3: Cleanup
        cleanup_files(parquet_path)
        
        # Summary
        print("\n" + "="*80)
        print("FINAL SUMMARY")
        print("="*80)
        
        if success:
            print("🎉 SUCCESS: Complete encrypt/decrypt cycle completed successfully!")
            print("   The external decryption bindings are working correctly.")
        else:
            print("💥 FAILURE: The encrypt/decrypt cycle encountered issues.")
            print("   This may indicate problems with the external decryption implementation.")
            print("   Check the logs above for specific error details.")
        
        print("\n📋 Test completed!")
        
    except Exception as e:
        print(f"\n💥 CRITICAL ERROR: {e}")
        print(f"   Error type: {type(e).__name__}")
        print("   Check the implementation and try again.")
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
