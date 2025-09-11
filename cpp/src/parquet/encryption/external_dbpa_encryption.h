// What license shall we use for this file?

#pragma once

#include <map>
#include <memory>
#include <vector>

#include "parquet/encryption/external/third_party/dbpa_interface.h"

#include "parquet/encryption/encryptor_interface.h"
#include "parquet/encryption/decryptor_interface.h"
#include "parquet/encryption/column_chunk_properties.h"

#include "parquet/metadata.h"
#include "parquet/types.h"

using dbps::external::DataBatchProtectionAgentInterface;

namespace parquet::encryption {

/// Call an external Data Batch Protection Agent (DBPA) to encrypt data.
class ExternalDBPAEncryptorAdapter : public EncryptorInterface {
 public:
  static std::unique_ptr<ExternalDBPAEncryptorAdapter> Make(
      ParquetCipher::type algorithm, std::string column_name,
      std::string key_id, Type::type data_type, Compression::type compression_type,
      Encoding::type encoding_type, std::string app_context,
      std::map<std::string, std::string> connection_config);

  static std::unique_ptr<ExternalDBPAEncryptorAdapter> Make(
        ParquetCipher::type algorithm,
        std::unique_ptr<ColumnChunkProperties> column_chunk_metadata_info,
        std::string key_id,
        std::string app_context,
        std::map<std::string, std::string> connection_config);

  ~ExternalDBPAEncryptorAdapter() = default;

  /// The size of the ciphertext, for this cipher and the specified plaintext length.
  [[nodiscard]] int32_t CiphertextLength(int64_t plaintext_len) const override;

  /// We follow the EncryptorInterface specification, but the key and aad are not used.
  int32_t Encrypt(::arrow::util::span<const uint8_t> plaintext,
                  ::arrow::util::span<const uint8_t> key,
                  ::arrow::util::span<const uint8_t> aad,
                  ::arrow::util::span<uint8_t> ciphertext) override;

  /// Encrypts plaintext footer, in order to compute footer signature (tag).
  int32_t SignedFooterEncrypt(::arrow::util::span<const uint8_t> footer,
                              ::arrow::util::span<const uint8_t> key,
                              ::arrow::util::span<const uint8_t> aad,
                              ::arrow::util::span<const uint8_t> nonce,
                              ::arrow::util::span<uint8_t> encrypted_footer) override;
 
 private:
    //agent_instance is assumed to be initialized at the time of construction. 
    //no initialization nor checks to verify that it is initialized are performed.
//    ExternalDBPAEncryptorAdapter(std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance);

    ExternalDBPAEncryptorAdapter(
      ParquetCipher::type algorithm, std::string column_name,
      std::string key_id, Type::type data_type, Compression::type compression_type,
      Encoding::type encoding_type, std::string app_context,
      std::map<std::string, std::string> connection_config,
      std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance);

    ///This is a second private constructor. It demonstrates how a lot of the 
    //arguments required in the original constructor are available
    //in the column_chunk_properties object.
    ExternalDBPAEncryptorAdapter(
      ParquetCipher::type algorithm, 
      std::unique_ptr<ColumnChunkProperties> column_chunk_properties,
      std::string key_id,
      std::string app_context,
      std::map<std::string, std::string> connection_config,
      std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance);

    int32_t InvokeExternalEncrypt(
      ::arrow::util::span<const uint8_t> plaintext, ::arrow::util::span<uint8_t> ciphertext);
    
    ParquetCipher::type algorithm_;
    std::string column_name_;
    std::string key_id_;
    Type::type data_type_;
    Compression::type compression_type_;
    Encoding::type encoding_type_;
    std::string app_context_;
    std::map<std::string, std::string> connection_config_;
    
    std::unique_ptr<dbps::external::DataBatchProtectionAgentInterface> agent_instance_;
    std::unique_ptr<ColumnChunkProperties> column_chunk_properties_;
};

/// Factory for ExternalDBPAEncryptorAdapter instances. The cache exists while the write
/// operation is open, and is used to guarantee the lifetime of the encryptor.
class ExternalDBPAEncryptorAdapterFactory {
  public:
    ExternalDBPAEncryptorAdapter* GetEncryptor(
      ParquetCipher::type algorithm, const ColumnChunkMetaDataBuilder* column_chunk_properties,
      ExternalFileEncryptionProperties* external_file_encryption_properties);

  private:
    std::map<std::string, std::unique_ptr<ExternalDBPAEncryptorAdapter>> encryptor_cache_;
};

/// Call an external Data Batch Protection Agent (DBPA) to decrypt data.
/// connection configuration provided.
class ExternalDBPADecryptorAdapter : public DecryptorInterface {
 public:
  static std::unique_ptr<ExternalDBPADecryptorAdapter> Make(
      ParquetCipher::type algorithm, std::string column_name,
      std::string key_id, Type::type data_type, Compression::type compression_type,
      std::vector<Encoding::type> encoding_types, std::string app_context,
      std::map<std::string, std::string> connection_config);
  
  ~ExternalDBPADecryptorAdapter() = default;

  /// The size of the plaintext, for this cipher and the specified ciphertext length.
  [[nodiscard]] int32_t PlaintextLength(int32_t ciphertext_len) const override;

  /// The size of the ciphertext, for this cipher and the specified plaintext length.
  [[nodiscard]] int32_t CiphertextLength(int32_t plaintext_len) const override;

  /// We follow the DecryptorInterface specification, but the key and aad are not used.
  /// The caller is responsible for ensuring that the plaintext buffer is at least as
  /// large as PlaintextLength(ciphertext_len).
  int32_t Decrypt(::arrow::util::span<const uint8_t> ciphertext,
                  ::arrow::util::span<const uint8_t> key,
                  ::arrow::util::span<const uint8_t> aad,
                  ::arrow::util::span<uint8_t> plaintext) override;

  private:
    //agent_instance is assumed to be initialized at the time of construction. 
    //no initialization nor checks to verify that it is initialized are performed.
    ExternalDBPADecryptorAdapter(
      ParquetCipher::type algorithm, std::string column_name,
      std::string key_id, Type::type data_type, Compression::type compression_type,
      std::vector<Encoding::type> encoding_types, std::string app_context,
      std::map<std::string, std::string> connection_config,
      std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance);
    
    int32_t InvokeExternalDecrypt(
      ::arrow::util::span<const uint8_t> ciphertext, ::arrow::util::span<uint8_t> plaintext);
    
    ParquetCipher::type algorithm_;
    std::string column_name_;
    std::string key_id_;
    Type::type data_type_;
    Compression::type compression_type_;
    // Set of all encodings used for this column. Comes directly from the column chunk metadata.
    std::vector<Encoding::type> encoding_types_;
    std::string app_context_;
    std::map<std::string, std::string> connection_config_;

    std::unique_ptr<dbps::external::DataBatchProtectionAgentInterface> agent_instance_;
};

/// Factory for ExternalDBPADecryptorAdapter instances. No cache exists for decryptors.
class ExternalDBPADecryptorAdapterFactory {
  public:
    std::unique_ptr<DecryptorInterface> GetDecryptor(
      ParquetCipher::type algorithm, const ColumnCryptoMetaData* crypto_metadata,
      const ColumnChunkMetaData* column_chunk_metadata,
      ExternalFileDecryptionProperties* external_file_decryption_properties);
};

}  // namespace parquet::encryption
