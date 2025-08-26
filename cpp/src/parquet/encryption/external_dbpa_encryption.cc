// What license shall we use for this file?

#include <iostream>
#include <iomanip>

#include "parquet/encryption/external_dbpa_encryption.h"

/// TODO(sbrenes): Add proper implementation. Right now we are just going to return
/// the plaintext as the ciphertext.

namespace parquet::encryption {

ExternalDBPAEncryptorAdapter::ExternalDBPAEncryptorAdapter(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id,
    Type::type data_type, Compression::type compression_type, Encoding::type encoding_type,
    std::string app_context, std::map<std::string, std::string> connection_config)
    : algorithm_(algorithm), column_name_(column_name), key_id_(key_id),
      data_type_(data_type), compression_type_(compression_type),
      encoding_type_(encoding_type), app_context_(app_context),
      connection_config_(connection_config) {}
  
std::unique_ptr<ExternalDBPAEncryptorAdapter> ExternalDBPAEncryptorAdapter::Make(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id,
    Type::type data_type, Compression::type compression_type, Encoding::type encoding_type,
    std::string app_context, std::map<std::string, std::string> connection_config) {
  return std::make_unique<ExternalDBPAEncryptorAdapter>(
      algorithm, column_name, key_id, data_type, compression_type, encoding_type,
      app_context, connection_config);
}

int32_t ExternalDBPAEncryptorAdapter::CiphertextLength(int64_t plaintext_len) const {
  //return plaintext_len;
  int32_t result = static_cast<int32_t>(plaintext_len);
  return result;
}
  
int32_t ExternalDBPAEncryptorAdapter::Encrypt(
    ::arrow::util::span<const uint8_t> plaintext, ::arrow::util::span<const uint8_t> key,
    ::arrow::util::span<const uint8_t> aad, ::arrow::util::span<uint8_t> ciphertext) {
  //return CallExternalDBPA(plaintext, ciphertext);
  std::vector<uint8_t> ciphertext_data(plaintext.size());
  for (size_t i = 0; i < plaintext.size(); ++i) {
    ciphertext_data[i] = plaintext[i] ^ 0xAA;
  }

  if (ciphertext.size() < ciphertext_data.size()) {
    throw ParquetException("Ciphertext buffer too small for encrypted result");
  }

  std::copy(ciphertext_data.begin(), ciphertext_data.end(), ciphertext.begin());
  return static_cast<int32_t>(ciphertext_data.size());
}

int32_t ExternalDBPAEncryptorAdapter::SignedFooterEncrypt(
    ::arrow::util::span<const uint8_t> footer, ::arrow::util::span<const uint8_t> key,
    ::arrow::util::span<const uint8_t> aad, ::arrow::util::span<const uint8_t> nonce,
    ::arrow::util::span<uint8_t> encrypted_footer) {
      std::cout << "\n\n!!!!!!!!!!!!!!!!\nYOU BETTER NOT!!!!!!!!\n\n" << std::endl;
  return CallExternalDBPA(footer, encrypted_footer);
}

int32_t ExternalDBPAEncryptorAdapter::CallExternalDBPA(
    ::arrow::util::span<const uint8_t> plaintext, ::arrow::util::span<uint8_t> ciphertext) {
  std::cout << "\n*-*-*- START: ExternalDBPAEncryptor::Encrypt Hello World! *-*-*-" << std::endl;
  std::cout << "Encryption Algorithm: [" << algorithm_ << "]" << std::endl;
  std::cout << "Column Name: [" << column_name_ << "]" << std::endl;
  std::cout << "Key ID: [" << key_id_ << "]" << std::endl;
  std::cout << "Data Type: [" << data_type_ << "]" << std::endl;
  std::cout << "Compression Type: [" << compression_type_ << "]" << std::endl;
  std::cout << "Encoding Type: [" << encoding_type_ << "]" << std::endl;
  std::cout << "App Context: [" << app_context_ << "]" << std::endl;
  std::cout << "Connection Config:" << std::endl;
  for (const auto& [key, value] : connection_config_) {
    std::cout << "  [" << key << "]: [" << value << "]" << std::endl;
  }

  std::copy(plaintext.begin(), plaintext.end(), ciphertext.begin());

  std::cout << "[DEBUG] First 16 bytes of plaintext data: ";
  for (size_t i = 0; i < std::min(size_t(16), plaintext.size()); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') 
              << static_cast<int>(plaintext[i]) << " ";
  }

  std::cout << "\n" << std::endl;

  std::string plaintext_str(plaintext.begin(), plaintext.end());
  std::string ciphertext_str(ciphertext.begin(), ciphertext.end());
  std::cout << "Plaintext: [" << plaintext_str << "]" << std::endl;
  std::cout << "Ciphertext: [" << ciphertext_str << "]" << std::endl;
  std::cout << "*-*-*- END: ExternalDBPAEncryptor::Encrypt Hello World! *-*-*-\n" << std::endl;

  std::cout << "\n\nEncrypt!!! [" << column_name_ << "]" << std::endl;
  std::cout << "Plaintext size: [" << plaintext.size() << "]" << std::endl;
  std::cout << "Ciphertext size (returning): [" << ciphertext.size() << "]\n\n" << std::endl;
  return ciphertext.size();
}

ExternalDBPAEncryptorAdapter* ExternalDBPAEncryptorAdapterFactory::GetEncryptor(
    ParquetCipher::type algorithm, const ColumnChunkMetaDataBuilder* column_chunk_metadata,
    ExternalFileEncryptionProperties* external_file_encryption_properties) {
  if (column_chunk_metadata == nullptr) {
    throw ParquetException("External DBPA encryption requires column chunk metadata");
  }
  auto column_path = column_chunk_metadata->descr()->path();
  if (encryptor_cache_.find(column_path->ToDotString()) == encryptor_cache_.end()) {
    auto connection_config = external_file_encryption_properties->connection_config();
    if (connection_config.find(algorithm) == connection_config.end()) {
      throw ParquetException("External DBPA encryption requires its connection configuration");
    }

    auto column_encryption_properties = external_file_encryption_properties
        ->column_encryption_properties(column_path->ToDotString());
    if (column_encryption_properties == nullptr) {
      std::stringstream ss;
      ss << "External DBPA encryption requires column encryption properties for column ["
         << column_path->ToDotString() << "]";
      throw ParquetException(ss.str());
    }

    auto data_type = column_chunk_metadata->descr()->physical_type();
    auto compression_type = column_chunk_metadata->properties()->compression(column_path);
    auto encoding_type = column_chunk_metadata->properties()->encoding(column_path);
    auto app_context = external_file_encryption_properties->app_context();
    auto connection_config_for_algorithm = connection_config.at(algorithm);
    auto key_id = column_encryption_properties->key_metadata();

    encryptor_cache_[column_path->ToDotString()] = ExternalDBPAEncryptorAdapter::Make(
        algorithm, column_path->ToDotString(), key_id, data_type, compression_type,
        encoding_type, app_context, connection_config_for_algorithm);
  }

  return encryptor_cache_[column_path->ToDotString()].get();
}

ExternalDBPADecryptorAdapter::ExternalDBPADecryptorAdapter(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id,
    Type::type data_type, Compression::type compression_type,
    std::vector<Encoding::type> encoding_types, std::string app_context,
    std::map<std::string, std::string> connection_config)
    : algorithm_(algorithm), column_name_(column_name), key_id_(key_id),
      data_type_(data_type), compression_type_(compression_type),
      encoding_types_(encoding_types), app_context_(app_context),
      connection_config_(connection_config) {}

std::unique_ptr<ExternalDBPADecryptorAdapter> ExternalDBPADecryptorAdapter::Make(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id,
    Type::type data_type, Compression::type compression_type,
    std::vector<Encoding::type> encoding_types, std::string app_context,
    std::map<std::string, std::string> connection_config) {
  return std::make_unique<ExternalDBPADecryptorAdapter>(
      algorithm, column_name, key_id, data_type, compression_type, encoding_types,
      app_context, connection_config);
}

int32_t ExternalDBPADecryptorAdapter::PlaintextLength(int32_t ciphertext_len) const {
  int32_t result = static_cast<int32_t>(ciphertext_len);
  return result;
}

int32_t ExternalDBPADecryptorAdapter::CiphertextLength(int32_t plaintext_len) const {
  int32_t result = static_cast<int32_t>(plaintext_len);
  return result;
}

int32_t ExternalDBPADecryptorAdapter::Decrypt(
    ::arrow::util::span<const uint8_t> ciphertext, ::arrow::util::span<const uint8_t> key,
    ::arrow::util::span<const uint8_t> aad, ::arrow::util::span<uint8_t> plaintext) {
  //return CallExternalDBPA(ciphertext, plaintext);
  std::vector<uint8_t> plaintext_data(ciphertext.size());
  for (size_t i = 0; i < ciphertext.size(); ++i) {
    plaintext_data[i] = ciphertext[i] ^ 0xAA;
  }
  if (plaintext.size() < plaintext_data.size()) {
    throw ParquetException("Plaintext buffer too small for decrypted result");
  }

  std::copy(plaintext_data.begin(), plaintext_data.end(), plaintext.begin());
  return static_cast<int32_t>(plaintext_data.size());
}

int32_t ExternalDBPADecryptorAdapter::CallExternalDBPA(
    ::arrow::util::span<const uint8_t> ciphertext, ::arrow::util::span<uint8_t> plaintext) {
  std::cout << "\n*-*-*- START: ExternalDBPADecryptor::Decrypt Hello World! *-*-*-" << std::endl;
  std::cout << "Decryption Algorithm: [" << algorithm_ << "]" << std::endl;
  std::cout << "Column Name: [" << column_name_ << "]" << std::endl;
  std::cout << "Key ID: [" << key_id_ << "]" << std::endl;
  std::cout << "Data Type: [" << data_type_ << "]" << std::endl;
  std::cout << "Compression Type: [" << compression_type_ << "]" << std::endl;
  std::cout << "Encoding Types: [";
  for (const auto& encoding_type : encoding_types_) {
    std::cout << encoding_type << " ";
  }
  std::cout << "]" << std::endl;
  std::cout << "App Context: [" << app_context_ << "]" << std::endl;
  std::cout << "Connection Config:" << std::endl;
  for (const auto& [key, value] : connection_config_) {
    std::cout << "  [" << key << "]: [" << value << "]" << std::endl;
  }

  std::copy(ciphertext.begin(), ciphertext.end(), plaintext.begin());

  std::cout << "[DEBUG] First 16 bytes of decrypted data: ";
  for (size_t i = 0; i < std::min(size_t(16), plaintext.size()); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') 
              << static_cast<int>(plaintext[i]) << " ";
  }

  std::cout << "\n" << std::endl;


  std::string plaintext_str(plaintext.begin(), plaintext.end());
  std::string ciphertext_str(ciphertext.begin(), ciphertext.end());
  std::cout << "Plaintext: [" << plaintext_str << "]" << std::endl;
  std::cout << "Ciphertext: [" << ciphertext_str << "]" << std::endl;
  std::cout << "*-*-*- END: ExternalDBPADecryptor::Decrypt Hello World! *-*-*-\n" << std::endl;

  std::cout << "\n\nDecrypt!!! [" << column_name_ << "]" << std::endl;
  std::cout << "Ciphertext size: [" << ciphertext.size() << "]" << std::endl;
  std::cout << "Plaintext size (returning): [" << plaintext.size() << "]\n\n" << std::endl;
  return plaintext.size();
}

std::unique_ptr<DecryptorInterface> ExternalDBPADecryptorAdapterFactory::GetDecryptor(
  ParquetCipher::type algorithm, const ColumnCryptoMetaData* crypto_metadata,
  const ColumnChunkMetaData* column_chunk_metadata,
  ExternalFileDecryptionProperties* external_file_decryption_properties) {
    std::lock_guard<std::mutex> lock(factory_mutex_);
    if (column_chunk_metadata == nullptr || crypto_metadata == nullptr) {
      throw ParquetException("External DBPA decryption requires column chunk and crypto metadata");
    }
    auto connection_config = external_file_decryption_properties->connection_config();
    if (connection_config.find(algorithm) == connection_config.end()) {
      throw ParquetException("External DBPA decryption requires its connection configuration");
    }
    auto column_path = column_chunk_metadata->descr()->path();
    auto data_type = column_chunk_metadata->descr()->physical_type();
    auto compression_type = column_chunk_metadata->compression();
    auto encoding_types = column_chunk_metadata->encodings();
    auto app_context = external_file_decryption_properties->app_context();
    auto connection_config_for_algorithm = connection_config.at(algorithm);
    auto key_metadata =crypto_metadata->key_metadata();
    
    return ExternalDBPADecryptorAdapter::Make(
        algorithm, column_path->ToDotString(), key_metadata, data_type, compression_type,
        encoding_types, app_context, connection_config_for_algorithm);
 }

}  // namespace parquet::encryption
