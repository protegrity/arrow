// What license shall we use for this file?

#pragma once

#include <map>
#include <optional>
#include <memory>
#include <vector>

#include "parquet/encryption/external/third_party/dbpa_interface.h"

#include "parquet/encryption/encryptor_interface.h"
#include "parquet/encryption/decryptor_interface.h"
#include "parquet/encryption/encoding_properties.h"
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
      std::map<std::string, std::string> connection_config,
      std::optional<int> datatype_length);

  ~ExternalDBPAEncryptorAdapter() = default;

  /// Signal whether the encryptor can calculate a valid ciphertext length before performing
  /// encryption.
  [[nodiscard]] bool CanCalculateCiphertextLength() const override { return false; }

  /// The size of the ciphertext, for this cipher and the specified plaintext length.
  [[nodiscard]] int32_t CiphertextLength(int64_t plaintext_len) const override;

  /// Encryption not supported as we cannot calculate the ciphertext before encryption.
  int32_t Encrypt(::arrow::util::span<const uint8_t> plaintext,
                  ::arrow::util::span<const uint8_t> key,
                  ::arrow::util::span<const uint8_t> aad,
                  ::arrow::util::span<uint8_t> ciphertext) override {
     std::stringstream ss;
     ss << "Encrypt is not supported in ExternalDBPAEncryptorAdapter, ";
     ss << "use EncryptWithManagedBuffer instead";
      throw ParquetException(ss.str());
  }

  /// Encrypt the plaintext and leave the results in the ciphertext buffer.
  /// The buffer will be resized to the appropriate size by the agent during encryption.
  int32_t EncryptWithManagedBuffer(::arrow::util::span<const uint8_t> plaintext,
                                  ::arrow::ResizableBuffer* ciphertext) override;

  /// Encrypts plaintext footer, in order to compute footer signature (tag).
  int32_t SignedFooterEncrypt(::arrow::util::span<const uint8_t> footer,
                              ::arrow::util::span<const uint8_t> key,
                              ::arrow::util::span<const uint8_t> aad,
                              ::arrow::util::span<const uint8_t> nonce,
                              ::arrow::util::span<uint8_t> encrypted_footer) override;

  void UpdateEncodingProperties(std::unique_ptr<EncodingProperties> encoding_properties) override;
 
 private:
    //agent_instance is assumed to be initialized at the time of construction. 
    //no initialization nor checks to verify that it is initialized are performed.

    ExternalDBPAEncryptorAdapter(
      ParquetCipher::type algorithm, std::string column_name,
      std::string key_id, Type::type data_type, Compression::type compression_type,
      Encoding::type encoding_type, std::optional<int> datatype_length, std::string app_context,
      std::map<std::string, std::string> connection_config,
      std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance);

    int32_t InvokeExternalEncrypt(
      ::arrow::util::span<const uint8_t> plaintext, 
      ::arrow::ResizableBuffer* ciphertext,
      std::map<std::string, std::string> encoding_attrs);
    
    ParquetCipher::type algorithm_;
    std::string column_name_;
    std::string key_id_;
    Type::type data_type_;
    Compression::type compression_type_;
    Encoding::type encoding_type_;
    std::optional<int> datatype_length_;
    std::string app_context_;
    std::map<std::string, std::string> connection_config_;
    
    std::unique_ptr<dbps::external::DataBatchProtectionAgentInterface> agent_instance_;
    
    std::unique_ptr<EncodingProperties> encoding_properties_;
    bool encoding_properties_updated_ = false;
};

/// Factory for ExternalDBPAEncryptorAdapter instances. The cache exists while the write
/// operation is open, and is used to guarantee the lifetime of the encryptor.
class ExternalDBPAEncryptorAdapterFactory {
  public:
    ExternalDBPAEncryptorAdapter* GetEncryptor(
      ParquetCipher::type algorithm, const ColumnChunkMetaDataBuilder* column_chunk_metadata,
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
      std::map<std::string, std::string> connection_config,
      std::optional<int> datatype_length);
  
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

  void UpdateEncodingProperties(std::unique_ptr<EncodingProperties> encoding_properties) override;

  private:
    //agent_instance is assumed to be initialized at the time of construction. 
    //no initialization nor checks to verify that it is initialized are performed.
    ExternalDBPADecryptorAdapter(
      ParquetCipher::type algorithm, std::string column_name,
      std::string key_id, Type::type data_type, Compression::type compression_type,
      std::vector<Encoding::type> encoding_types, std::optional<int> datatype_length, std::string app_context,
      std::map<std::string, std::string> connection_config,
      std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance);
    
    int32_t InvokeExternalDecrypt(
      ::arrow::util::span<const uint8_t> ciphertext, 
      ::arrow::util::span<uint8_t> plaintext,
      std::map<std::string, std::string> encoding_attrs);
    
    ParquetCipher::type algorithm_;
    std::string column_name_;
    std::string key_id_;
    Type::type data_type_;
    Compression::type compression_type_;
    // Set of all encodings used for this column. Comes directly from the column chunk metadata.
    std::vector<Encoding::type> encoding_types_;
    std::optional<int> datatype_length_;
    std::string app_context_;
    std::map<std::string, std::string> connection_config_;

    std::unique_ptr<dbps::external::DataBatchProtectionAgentInterface> agent_instance_;

    std::unique_ptr<EncodingProperties> encoding_properties_;
    bool encoding_properties_updated_ = false;
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
