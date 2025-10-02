// What license shall we use for this file?

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <map>
#include <optional>

#include "parquet/encryption/encryption.h"
#include "parquet/encryption/external_dbpa_encryption.h"
#include "parquet/encryption/external/test_utils.h"
#include "parquet/encryption/encoding_properties.h"

/// TODO(sbrenes): Add proper testing. Right now we are just going to test that the
/// encryptor and decryptor are created and that the plaintext is returned as the ciphertext.

namespace parquet::encryption::test {

class ExternalDBPAEncryptorAdapterTest : public ::testing::Test {
 protected:
  void SetUp() override {

    // this library will use heuristics to load "libDBPATestAgent.so", needed for tests here.
    std::string library_path = parquet::encryption::external::test::TestUtils::GetTestLibraryPath();

    app_context_ = 
      "{\"user_id\": \"abc123\", \"location\": {\"lat\": 9.7489, \"lon\": -83.7534}}";
    connection_config_ = {
      {"config_path", "path/to/file"}, 
      {"agent_library_path", library_path}
    };
  }

  std::unique_ptr<ExternalDBPAEncryptorAdapter> CreateEncryptor(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id, 
    Type::type data_type, Compression::type compression_type, Encoding::type encoding_type) {
    return ExternalDBPAEncryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, 
      compression_type, encoding_type, app_context_, 
      connection_config_, std::nullopt);
  }

  std::unique_ptr<ExternalDBPADecryptorAdapter> CreateDecryptor(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id, 
    Type::type data_type, Compression::type compression_type, Encoding::type encoding_type) {
    return ExternalDBPADecryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, 
      compression_type, {encoding_type}, app_context_, 
      connection_config_, std::nullopt);
  }

  void RoundtripEncryption(
      ParquetCipher::type algorithm, std::string column_name, std::string key_id, 
      Type::type data_type, Compression::type compression_type, Encoding::type encoding_type,
      std::string plaintext) {
    std::unique_ptr<ExternalDBPAEncryptorAdapter> encryptor = ExternalDBPAEncryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, 
      compression_type, encoding_type, app_context_, 
      connection_config_, std::nullopt);

    // Create a simple EncodingProperties for testing using the builder pattern
    EncodingPropertiesBuilder builder;
    builder.ColumnPath("test_column")
            .PhysicalType(data_type)
            .CompressionCodec(compression_type)
            .PageType(parquet::PageType::DATA_PAGE_V2)
            .PageV2DefinitionLevelsByteLength(10)
            .PageV2RepetitionLevelsByteLength(10)
            .PageV2NumNulls(10)
            .PageV2IsCompressed(true)
            .DataPageMaxDefinitionLevel(10)
            .DataPageMaxRepetitionLevel(1)
            .PageEncoding(encoding_type)
            .DataPageNumValues(100) 
            .Build();

    encryptor->UpdateEncodingProperties(builder.Build());

    int32_t expected_ciphertext_length = plaintext.size();

    std::shared_ptr<ResizableBuffer> ciphertext_buffer = AllocateBuffer(
      ::arrow::default_memory_pool(), expected_ciphertext_length);
    int32_t encryption_length = encryptor->EncryptWithManagedBuffer(
      str2span(plaintext), ciphertext_buffer.get());  
    ASSERT_EQ(expected_ciphertext_length, encryption_length);

    std::string ciphertext_str(ciphertext_buffer->data(), ciphertext_buffer->data() + encryption_length);

    // We know this uses XOR encryption. Therefore, the ciphertext is the same as the plaintext.
    // XOR encrytion encrypts each byte of the plaintext with 0xAA.
    // See external/dbpa_test_agent.cc for the implementation.

    // Assert that plaintext and ciphertext have the same length
    ASSERT_EQ(plaintext.size(), ciphertext_str.size());

    std::unique_ptr<ExternalDBPADecryptorAdapter> decryptor = ExternalDBPADecryptorAdapter::Make(
      algorithm, column_name, key_id, data_type,
      compression_type, {encoding_type}, app_context_,
      connection_config_, std::nullopt);

    decryptor->UpdateEncodingProperties(builder.Build());

    int32_t expected_plaintext_length = ciphertext_str.size();
    std::shared_ptr<ResizableBuffer> plaintext_buffer = AllocateBuffer(
      ::arrow::default_memory_pool(), expected_plaintext_length);
    int32_t decryption_length = decryptor->DecryptWithManagedBuffer(
      str2span(ciphertext_str), plaintext_buffer.get());
    ASSERT_EQ(expected_plaintext_length, decryption_length);

    std::string plaintext_str(
      plaintext_buffer->data(), plaintext_buffer->data() + decryption_length);

    // Assert that the decrypted plaintext matches the original plaintext
    ASSERT_EQ(plaintext, plaintext_str);
  }
  
protected:
 std::string empty_string = "";
 std::string app_context_;
 std::map<std::string, std::string> connection_config_;
};

TEST_F(ExternalDBPAEncryptorAdapterTest, RoundtripEncryptionSucceeds) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;
  std::string plaintext = "Jean-Luc Picard";

  RoundtripEncryption(
    algorithm, column_name, key_id, data_type, compression_type, encoding_type, plaintext);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, SignedFooterEncryptionThrowsException) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;
  std::unique_ptr<ExternalDBPAEncryptorAdapter> encryptor = CreateEncryptor(
    algorithm, column_name, key_id, data_type, compression_type, encoding_type);
  std::vector<uint8_t> encrypted_footer(10, '\0');
  EXPECT_THROW(encryptor->SignedFooterEncrypt(
    str2span(/*footer*/""), str2span(/*key*/""), str2span(/*aad*/""), str2span(/*nonce*/""),
    encrypted_footer), ParquetException);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, EncryptWithoutUpdateEncodingPropertiesThrows) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  auto encryptor = ExternalDBPAEncryptorAdapter::Make(
    algorithm, column_name, key_id, data_type, compression_type, encoding_type,
    app_context_, connection_config_, std::nullopt);

  std::string plaintext = "abc";
  std::shared_ptr<ResizableBuffer> ciphertext_buffer = AllocateBuffer(
    ::arrow::default_memory_pool(), 0);
  EXPECT_THROW(
    encryptor->EncryptWithManagedBuffer(
      str2span(plaintext), ciphertext_buffer.get()),
    ParquetException);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, DecryptWithoutUpdateEncodingPropertiesThrows) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  auto decryptor = ExternalDBPADecryptorAdapter::Make(
    algorithm, column_name, key_id, data_type, compression_type, {encoding_type},
    app_context_, connection_config_, std::nullopt);

  std::string ciphertext = "xyz";
  std::shared_ptr<ResizableBuffer> plaintext_buffer = AllocateBuffer(
    ::arrow::default_memory_pool(), 0);
  EXPECT_THROW(
    decryptor->DecryptWithManagedBuffer(
      str2span(ciphertext), plaintext_buffer.get()),
    ParquetException);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, EncryptorUnsupportedAlgorithmThrows) {
  // Use AES_GCM_V1 (unsupported) to verify the adapter rejects algorithms other than EXTERNAL_DBPA_V1
  ParquetCipher::type unsupported_algo = ParquetCipher::AES_GCM_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  EXPECT_THROW(
    CreateEncryptor(unsupported_algo, column_name, key_id, data_type, compression_type, encoding_type),
    ParquetException);

  // Also test AES_GCM_CTR_V1
  unsupported_algo = ParquetCipher::AES_GCM_CTR_V1;
  EXPECT_THROW(
    CreateEncryptor(unsupported_algo, column_name, key_id, data_type, compression_type, encoding_type),
    ParquetException);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, DecryptorUnsupportedAlgorithmThrows) {
  // Use AES_GCM_V1 (unsupported) to verify the adapter rejects algorithms other than EXTERNAL_DBPA_V1
  ParquetCipher::type unsupported_algo = ParquetCipher::AES_GCM_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  EXPECT_THROW(
    ExternalDBPADecryptorAdapter::Make(
      unsupported_algo, column_name, key_id, data_type, compression_type, {encoding_type},
      app_context_, connection_config_, std::nullopt),
    ParquetException);

  // Also test AES_GCM_CTR_V1
  unsupported_algo = ParquetCipher::AES_GCM_CTR_V1;
  EXPECT_THROW(
    ExternalDBPADecryptorAdapter::Make(
      unsupported_algo, column_name, key_id, data_type, compression_type, {encoding_type},
      app_context_, connection_config_, std::nullopt),
    std::exception);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, EncryptorMissingLibraryPathThrows) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  std::map<std::string, std::string> bad_config = { {"config_path", "path/to/file"} };
  std::string app_context = "{}";

  EXPECT_THROW(
    ExternalDBPAEncryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, compression_type, encoding_type,
      app_context, bad_config, std::nullopt),
  std::exception);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, EncryptorInvalidLibraryPathThrows) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  std::map<std::string, std::string> bad_config = {
    {"agent_library_path", "/definitely/not/a/real/libDBPA.so"}
  };
  std::string app_context = "{}";

  EXPECT_THROW(
    ExternalDBPAEncryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, compression_type, encoding_type,
      app_context, bad_config, std::nullopt),
    std::exception);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, DecryptorMissingLibraryPathThrows) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  std::map<std::string, std::string> bad_config = { {"config_path", "path/to/file"} };
  std::string app_context = "{}";

  EXPECT_THROW(
    ExternalDBPADecryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, compression_type, {encoding_type},
      app_context, bad_config, std::nullopt),
    std::exception);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, DecryptorInvalidLibraryPathThrows) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;

  std::map<std::string, std::string> bad_config = {
    {"agent_library_path", "/definitely/not/a/real/libDBPA.so"}
  };
  std::string app_context = "{}";

  EXPECT_THROW(
    ExternalDBPADecryptorAdapter::Make(
      algorithm, column_name, key_id, data_type, compression_type, {encoding_type},
      app_context, bad_config, std::nullopt),
    std::exception);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, DecryptWithWrongKeyIdFails) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string correct_key_id = "employee_name_key";
  std::string wrong_key_id = "wrong_key_id";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;
  std::string app_context = "{}";
  std::map<std::string, std::string> config = {
    {"agent_library_path", parquet::encryption::external::test::TestUtils::GetTestLibraryPath()}
  };

  auto encryptor = ExternalDBPAEncryptorAdapter::Make(
    algorithm, column_name, correct_key_id, data_type, compression_type, encoding_type,
    app_context, config, std::nullopt);

  // Build encoding properties
  EncodingPropertiesBuilder builder;
  builder.ColumnPath("test_column")
         .PhysicalType(data_type)
         .CompressionCodec(compression_type)
         .PageType(parquet::PageType::DATA_PAGE_V2)
         .PageV2DefinitionLevelsByteLength(10)
         .PageV2RepetitionLevelsByteLength(10)
         .PageV2NumNulls(10)
         .PageV2IsCompressed(true)
         .DataPageMaxDefinitionLevel(10)
         .DataPageMaxRepetitionLevel(1)
         .PageEncoding(encoding_type)
         .DataPageNumValues(100)
         .Build();

  encryptor->UpdateEncodingProperties(builder.Build());

  std::string plaintext = "Sensitive Data";
  int32_t ct_len = encryptor->CiphertextLength(plaintext.size());
  std::shared_ptr<ResizableBuffer> ciphertext_buffer = AllocateBuffer(
    ::arrow::default_memory_pool(), 0);

  std::string empty;
  int32_t enc_len = encryptor->EncryptWithManagedBuffer(
    str2span(plaintext), ciphertext_buffer.get());
  ASSERT_EQ(ct_len, enc_len);

  std::string ciphertext_str(ciphertext_buffer->data(), ciphertext_buffer->data() + enc_len);

  auto decryptor = ExternalDBPADecryptorAdapter::Make(
    algorithm, column_name, wrong_key_id, data_type, compression_type, {encoding_type},
    app_context, config, std::nullopt);

  decryptor->UpdateEncodingProperties(builder.Build());

  int32_t pt_len = decryptor->PlaintextLength(ciphertext_str.size());
  std::shared_ptr<ResizableBuffer> plaintext_buffer = AllocateBuffer(
    ::arrow::default_memory_pool(), 0);

  bool threw = false;
  int32_t dec_len = 0;
  try {
    dec_len = decryptor->DecryptWithManagedBuffer(
      str2span(ciphertext_str), plaintext_buffer.get());
    ASSERT_EQ(pt_len, dec_len);
  } catch (const ParquetException&) {
    threw = true;
  }

  if (!threw) {
    std::string decrypted(plaintext_buffer->data(), plaintext_buffer->data() + dec_len);
    ASSERT_NE(plaintext, decrypted);
  }
}

TEST_F(ExternalDBPAEncryptorAdapterTest, EncryptCallShouldFail) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;
  std::string plaintext = "Jean-Luc Picard";
  std::vector<uint8_t> ciphertext_buffer(plaintext.size(), '\0');

  std::unique_ptr<ExternalDBPAEncryptorAdapter> encryptor = CreateEncryptor(
    algorithm, column_name, key_id, data_type, compression_type, encoding_type);
  ASSERT_FALSE(encryptor->CanCalculateCiphertextLength());
  EXPECT_THROW(
    encryptor->Encrypt(
      str2span(plaintext), str2span(/*key*/""), str2span(/*aad*/""), ciphertext_buffer),
    ParquetException);
}

TEST_F(ExternalDBPAEncryptorAdapterTest, DecryptCallShouldFail) {
  ParquetCipher::type algorithm = ParquetCipher::EXTERNAL_DBPA_V1;
  std::string column_name = "employee_name";
  std::string key_id = "employee_name_key";
  Type::type data_type = Type::BYTE_ARRAY;
  Compression::type compression_type = Compression::UNCOMPRESSED;
  Encoding::type encoding_type = Encoding::PLAIN;
  std::string ciphertext = "Jean-Luc Picard";
  std::vector<uint8_t> plaintext_buffer(ciphertext.size(), '\0');

  std::unique_ptr<ExternalDBPADecryptorAdapter> decryptor = CreateDecryptor(
    algorithm, column_name, key_id, data_type, compression_type, encoding_type);
  ASSERT_FALSE(decryptor->CanCalculatePlaintextLength());
  EXPECT_THROW(
    decryptor->Decrypt(
      str2span(ciphertext), str2span(/*key*/""), str2span(/*aad*/""), plaintext_buffer),
    ParquetException);
}

}  // namespace parquet::encryption::test
