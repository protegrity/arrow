// What license shall we use for this file?

#include <iostream>
#include <map>
#include <optional>
#include <memory>

#include "parquet/encryption/external_dbpa_encryption.h"
#include "parquet/encryption/key_metadata.h"
#include "parquet/encryption/external/loadable_encryptor_utils.h"
#include "parquet/encryption/external/dbpa_enum_utils.h"
#include "parquet/encryption/external/dbpa_executor.h"
#include "parquet/exception.h"
#include "parquet/types.h"

using parquet::encryption::external::LoadableEncryptorUtils;
using parquet::encryption::external::DBPAEnumUtils;
using parquet::encryption::external::DBPAExecutor;

using dbps::external::EncryptionResult;
using dbps::external::DecryptionResult;

namespace parquet::encryption {

// Utility function to load and initialize a DataBatchProtectionAgentInterface instance
// Shared between the encryptor and decryptor.
std::unique_ptr<dbps::external::DataBatchProtectionAgentInterface> LoadAndInitializeAgent(
    const std::string& column_name,
    const std::map<std::string, std::string>& connection_config,
    const std::string& app_context,
    const std::string& key_id,
    Type::type data_type,
    Compression::type compression_type,
    std::optional<int> datatype_length) {
  
  // Load a new DataBatchProtectionAgentInterface instance from the shared library
  std::cout << "[DEBUG] Loading agent from library..." << std::endl;

  const std::string SHARED_LIBRARY_PATH_KEY = "agent_library_path";
  
  // Step 1: Get path to the shared library  
  auto it = connection_config.find(SHARED_LIBRARY_PATH_KEY);
  if (it == connection_config.end()) {
    auto const msg = "Required configuration key '" + SHARED_LIBRARY_PATH_KEY + "' not found in connection_config";
    std::cout << "[ERROR] " << msg << std::endl;
    throw ParquetException(msg);
  }
  auto library_path = it->second;
  std::cout << "[DEBUG] library_path = " << library_path << std::endl;

  // Step 2: Load an instance of the DataBatchProtectionAgentInterface
  std::cout << "[DEBUG] Loading agent instance from library..." << std::endl;
  auto agent_instance = LoadableEncryptorUtils::LoadFromLibrary(library_path);
  if (!agent_instance) {
    std::cout << "[ERROR] Failed to create instance of DataBatchProtectionAgentInterface" << std::endl;
    throw ParquetException("Failed to create instance of DataBatchProtectionAgentInterface");
  }        
  std::cout << "[DEBUG] Successfully loaded agent_instance" << std::endl;

  std::cout << "[DEBUG] Wrapping agent in DBPAExecutor" << std::endl;

  //Step 3: Wrap the agent in a DBPAExecutor.
  //operations will timeout, exceptions will be re-thrown.
  //TODO: figure out timeouts and how to configure them(read them from app_config/connection_config?)
  //https://github.com/protegrity/arrow/issues/151

  std::cout << "[DEBUG] Wrapping Agent in DBPAExecutor" << std::endl;

  const int64_t init_timeout_ms    = 10*1000; //10 seconds
  const int64_t encrypt_timeout_ms = 30*1000; //30 seconds
  const int64_t decrypt_timeout_ms = 30*1000; //30 seconds.

  auto executor_wrapped_agent = std::make_unique<DBPAExecutor>(
    /*agent*/ std::move(agent_instance), 
    /*init_timeout_ms*/ init_timeout_ms, 
    /*encrypt_timeout_ms*/  encrypt_timeout_ms, 
    /*decrypt_timeout_ms*/ decrypt_timeout_ms
  );

  // Step 4: Initialize the agent.
  std::cout << "[DEBUG] Initializing agent instance" << std::endl;

  executor_wrapped_agent->init(
    /*column_name*/ column_name,
    /*connection_config*/ connection_config,
    /*app_context*/ app_context,
    /*column_key_id*/ key_id,
    /*data_type*/ DBPAEnumUtils::ParquetTypeToDBPA(data_type), 
    /*datatype_length*/ datatype_length,
    /*compression_type*/ DBPAEnumUtils::ArrowCompressionToDBPA(compression_type)
  ); //LoadAndInitializeAgent()
  
  std::cout << "[DEBUG] Successfully initialized agent instance" << std::endl;

  return executor_wrapped_agent;
}

//this is a private constructor, invoked from Make()
//at this point, the agent_instance is assumed to be initialized.
ExternalDBPAEncryptorAdapter::ExternalDBPAEncryptorAdapter(
  ParquetCipher::type algorithm, std::string column_name, std::string key_id,
  Type::type data_type, Compression::type compression_type, Encoding::type encoding_type,
  std::string app_context, std::map<std::string, std::string> connection_config,
  std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance)
  : algorithm_(algorithm), column_name_(column_name), key_id_(key_id),
    data_type_(data_type), compression_type_(compression_type),
    encoding_type_(encoding_type), app_context_(app_context),
    connection_config_(connection_config),
    agent_instance_(std::move(agent_instance)) {
}
  
std::unique_ptr<ExternalDBPAEncryptorAdapter> ExternalDBPAEncryptorAdapter::Make(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id,
    Type::type data_type, Compression::type compression_type, Encoding::type encoding_type,
    std::string app_context, std::map<std::string, std::string> connection_config,
    std::optional<int> datatype_length) {

        //TODO: figure out logging
        std::cout << "[DEBUG] ExternalDBPAEncryptorAdapter::Make() -- Make()" << std::endl;
        std::cout << "[DEBUG]   algorithm = " << algorithm << std::endl;
        std::cout << "[DEBUG]   column_name = " << column_name << std::endl;
        std::cout << "[DEBUG]   key_id = " << key_id << std::endl;
        std::cout << "[DEBUG]   data_type = " << data_type << std::endl;
        std::cout << "[DEBUG]   compression_type = " << compression_type << std::endl;
        std::cout << "[DEBUG]   encoding_type = " << encoding_type << std::endl;
        std::cout << "[DEBUG]   app_context = " << app_context << std::endl;
        std::cout << "[DEBUG]   connection_config:" << std::endl;
        for (const auto& [key, value] : connection_config) {
          std::cout << "[DEBUG]    " << key << " = " << value << std::endl;
        }

        std::cout << "[DEBUG] ExternalDBPAEncryptorAdapter::ExternalDBPAEncryptorAdapter() -- loading and initializing agent" << std::endl;
        // Load and initialize the agent using the utility function
        auto agent_instance = LoadAndInitializeAgent(
          column_name, connection_config, app_context, key_id, data_type, compression_type, datatype_length);

        //if we got to this point, the agent was initialized successfully
        std::cout << "[DEBUG] ExternalDBPAEncryptorAdapter::ExternalDBPAEncryptorAdapter() -- creating ExternalDBPAEncryptorAdapter" << std::endl;

        // create the instance of the ExternalDBPAEncryptorAdapter
        auto result = std::unique_ptr<ExternalDBPAEncryptorAdapter>(
          new ExternalDBPAEncryptorAdapter(
            /*algorithm*/ algorithm,
            /*column_name*/ column_name,
            /*key_id*/ key_id,
            /*data_type*/ data_type,
            /*compression_type*/ compression_type,
            /*encoding_type*/ encoding_type,
            /*app_context*/ app_context,
            /*connection_config*/ connection_config,
            /*agent_instance*/ std::move(agent_instance))
        );

        std::cout << "[DEBUG] ExternalDBPAEncryptorAdapter created successfully" << std::endl;

        return result;
  }

int32_t ExternalDBPAEncryptorAdapter::CiphertextLength(int64_t plaintext_len) const {
  std::cout << "ExternalDBPAEncryptorAdapter::CiphertextLength" << std::endl;
  std::cout << "  plaintext_len = " << plaintext_len << std::endl;
  int return_value = plaintext_len;
  std::cout << "  return_value = " << return_value << std::endl;
  return plaintext_len;
}

void ExternalDBPAEncryptorAdapter::UpdateEncryptionParams(std::unique_ptr<ColumnChunkProperties> column_chunk_properties) {
  std::cout << "ExternalDBPAEncryptorAdapter::UpdateEncryptionParams" << std::endl;
  updated_column_chunk_properties_ = std::move(column_chunk_properties);
  encryption_params_updated_ = true;
}

int32_t ExternalDBPAEncryptorAdapter::Encrypt(
    ::arrow::util::span<const uint8_t> plaintext, ::arrow::util::span<const uint8_t> key,
    ::arrow::util::span<const uint8_t> aad, ::arrow::util::span<uint8_t> ciphertext) {

  if (!encryption_params_updated_) {
    std::cout << "[ERROR] Params not updated" << std::endl;
    throw ParquetException("Params not updated");
  }

  encryption_params_updated_ = false;

  return InvokeExternalEncrypt(plaintext, ciphertext);
}

int32_t ExternalDBPAEncryptorAdapter::SignedFooterEncrypt(
    ::arrow::util::span<const uint8_t> footer, ::arrow::util::span<const uint8_t> key,
    ::arrow::util::span<const uint8_t> aad, ::arrow::util::span<const uint8_t> nonce,
    ::arrow::util::span<uint8_t> encrypted_footer) {
  return InvokeExternalEncrypt(footer, encrypted_footer);
}

int32_t ExternalDBPAEncryptorAdapter::InvokeExternalEncrypt(
    ::arrow::util::span<const uint8_t> plaintext, ::arrow::util::span<uint8_t> ciphertext) {

      std::cout << "\n*-*-*- START: ExternalDBPAEncryptor::Encrypt *-*-*-" << std::endl;
      std::cout << "Encryption Algorithm: [" << algorithm_ << "]" << std::endl;
      std::cout << "Column Name: [" << column_name_ << "]" << std::endl;
      std::cout << "Key ID: [" << key_id_ << "]" << std::endl;
      std::cout << "Data Type: [" << data_type_ << "]" << std::endl;
      std::cout << "Compression Type: [" << compression_type_ << "]" << std::endl;
      std::cout << "Encoding Type: [" << encoding_type_ << "]" << std::endl;
      std::cout << "App Context: [" << app_context_ << "]" << std::endl;
      std::cout << "Connection Config:" << std::endl;
      for (const auto& [cfg_key, cfg_value] : connection_config_) {
        std::cout << "  [" << cfg_key << "]: [" << cfg_value << "]" << std::endl;
      }
  
      std::cout << "[DEBUG] Calling agent_instance_->Encrypt..." << std::endl;
      std::map<std::string, std::string> encoding_attrs; // placeholder until wired
      std::unique_ptr<EncryptionResult> result = agent_instance_->Encrypt(plaintext, std::move(encoding_attrs));
  
      if (!result->success()) {
        std::cout << "[ERROR] Encryption failed: " << result->error_message() << std::endl;
        throw ParquetException(result->error_message());
      }
  
      std::cout << "[DEBUG] Encryption successful" << std::endl;
      std::cout << "  result size: " << result->size() << " bytes" << std::endl;
      std::cout << "  result ciphertext size: " << result->ciphertext().size() << " bytes" << std::endl;
  
      if (ciphertext.size() < result->ciphertext().size()) {
        std::cout << "[ERROR] Ciphertext buffer too small. Need " << result->ciphertext().size()
                  << " bytes, have " << ciphertext.size() << " bytes" << std::endl;
        throw ParquetException("Ciphertext buffer too small for encrypted result");
      }
  
      std::cout << "[DEBUG] Copying result to ciphertext buffer..." << std::endl;
      std::copy(result->ciphertext().begin(), result->ciphertext().end(), ciphertext.begin());
      std::cout << "[DEBUG] Encryption completed successfully" << std::endl;
  
      return static_cast<int32_t>(result->size());
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
    std::optional<int> datatype_length;
    if (data_type == Type::FIXED_LEN_BYTE_ARRAY) {
      datatype_length = column_chunk_metadata->descr()->type_length();
    }
    auto compression_type = column_chunk_metadata->properties()->compression(column_path);
    auto encoding_type = column_chunk_metadata->properties()->encoding(column_path);
    auto app_context = external_file_encryption_properties->app_context();
    auto connection_config_for_algorithm = connection_config.at(algorithm);

    std::string key_id;
    try {
      auto key_metadata = KeyMetadata::Parse(column_encryption_properties->key_metadata());
      key_id = key_metadata.key_material().master_key_id();
    } catch (const ParquetException& e) {
      // It is possible for the key metadata to only contain the key id itself, so if
      // it cannot be parsed as valid JSON, send the key id as string for the ExternalDBPA
      // to process.
      key_id = column_encryption_properties->key_metadata();
    }

    encryptor_cache_[column_path->ToDotString()] = ExternalDBPAEncryptorAdapter::Make(
        algorithm, column_path->ToDotString(), key_id, data_type, compression_type,
        encoding_type, app_context, connection_config_for_algorithm, datatype_length);
  }

  return encryptor_cache_[column_path->ToDotString()].get();
}

//private constructor, invoked from Make()
//at this point, the agent_instance is assumed to be initialized.
//TODO: consider cleaning up the signature of this private constructor. 
//      Most of the arguments are only needed by agent_instance, which is 
//      instantiated before this constructor is invoked.
ExternalDBPADecryptorAdapter::ExternalDBPADecryptorAdapter(
  ParquetCipher::type algorithm, std::string column_name, std::string key_id,
  Type::type data_type, Compression::type compression_type,
  std::vector<Encoding::type> encoding_types, std::string app_context,
  std::map<std::string, std::string> connection_config,
  std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance)
  : algorithm_(algorithm), column_name_(column_name), key_id_(key_id),
    data_type_(data_type), compression_type_(compression_type),
    encoding_types_(encoding_types), app_context_(app_context),
    connection_config_(connection_config),
    agent_instance_(std::move(agent_instance)) {
}

std::unique_ptr<ExternalDBPADecryptorAdapter> ExternalDBPADecryptorAdapter::Make(
    ParquetCipher::type algorithm, std::string column_name, std::string key_id,
    Type::type data_type, Compression::type compression_type,
    std::vector<Encoding::type> encoding_types, std::string app_context,
    std::map<std::string, std::string> connection_config,
    std::optional<int> datatype_length) {

        //TODO: figure out logging
        std::cout << "[DEBUG] ExternalDBPADecryptorAdapter::Make() -- Make()" << std::endl;
        std::cout << "[DEBUG]   algorithm = " << algorithm << std::endl;
        std::cout << "[DEBUG]   column_name = " << column_name << std::endl;
        std::cout << "[DEBUG]   key_id = " << key_id << std::endl;
        std::cout << "[DEBUG]   data_type = " << data_type << std::endl;
        std::cout << "[DEBUG]   compression_type = " << compression_type << std::endl;
        std::cout << "[DEBUG]   encoding_types = [";
        for (const auto& encoding : encoding_types) {
          std::cout << static_cast<int>(encoding) << " ";
        }
        std::cout << "]" << std::endl;
        std::cout << "[DEBUG]   app_context = " << app_context << std::endl;
        std::cout << "[DEBUG]   connection_config:" << std::endl;
        for (const auto& [key, value] : connection_config) {
          std::cout << "[DEBUG]    " << key << " = " << value << std::endl;
        }

        std::cout << "[DEBUG] ExternalDBPADecryptorAdapter::ExternalDBPADecryptorAdapter() -- loading and initializing agent" << std::endl;
        // Load and initialize the agent using the utility function
        auto agent_instance = LoadAndInitializeAgent(
            column_name, connection_config, app_context, key_id, data_type, compression_type, datatype_length);

        //if we got to this point, the agent was initialized successfully

        // create the instance of the ExternalDBPADecryptorAdapter
        auto result = std::unique_ptr<ExternalDBPADecryptorAdapter>(
          new ExternalDBPADecryptorAdapter(
            /*algorithm*/ algorithm,
            /*column_name*/ column_name,
            /*key_id*/ key_id,
            /*data_type*/ data_type,
            /*compression_type*/ compression_type,
            /*encoding_types*/ encoding_types,
            /*app_context*/ app_context,
            /*connection_config*/ connection_config,
            /*agent_instance*/ std::move(agent_instance))
        );
        std::cout << "[DEBUG] ExternalDBPADecryptorAdapter created successfully" << std::endl;

        return result;
  }

int32_t ExternalDBPADecryptorAdapter::PlaintextLength(int32_t ciphertext_len) const {
  return ciphertext_len;
}

int32_t ExternalDBPADecryptorAdapter::CiphertextLength(int32_t plaintext_len) const {
  return plaintext_len;
}

int32_t ExternalDBPADecryptorAdapter::Decrypt(
    ::arrow::util::span<const uint8_t> ciphertext, ::arrow::util::span<const uint8_t> key,
    ::arrow::util::span<const uint8_t> aad, ::arrow::util::span<uint8_t> plaintext) {

      return InvokeExternalDecrypt(ciphertext, plaintext);
}

int32_t ExternalDBPADecryptorAdapter::InvokeExternalDecrypt(
    ::arrow::util::span<const uint8_t> ciphertext, ::arrow::util::span<uint8_t> plaintext) {

      std::cout << "\n*-*-*- START: ExternalDBPADecryptor::Decrypt *-*-*-" << std::endl;
      std::cout << "Decryption Algorithm: [" << algorithm_ << "]" << std::endl;
      std::cout << "Column Name: [" << column_name_ << "]" << std::endl;
      std::cout << "Key ID: [" << key_id_ << "]" << std::endl;
      std::cout << "Data Type: [" << data_type_ << "]" << std::endl;
      std::cout << "Compression Type: [" << compression_type_ << "]" << std::endl;
      std::cout << "Encoding Types: [";
      for (const auto& encoding_type : encoding_types_) {
        std::cout << encoding_type << "\n";
      }
      std::cout << "]" << std::endl;
      std::cout << "App Context: [" << app_context_ << "]" << std::endl;
      std::cout << "Connection Config:" << std::endl;
      for (const auto& [key, value] : connection_config_) {
        std::cout << "  [" << key << "]: [" << value << "]" << std::endl;
      }
  
      std::cout << "[DEBUG] Calling agent_instance_->Decrypt..." << std::endl;
      std::map<std::string, std::string> encoding_attrs; // placeholder until wired
      std::unique_ptr<DecryptionResult> result = agent_instance_->Decrypt(ciphertext, std::move(encoding_attrs));
      
      if (!result->success()) {
        std::cout << "[ERROR] Decryption failed: " << result->error_message() << std::endl;
        throw ParquetException(result->error_message());
      }
  
      std::cout << "[DEBUG] Decryption successful" << std::endl;
      std::cout << "  result size: " << result->size() << " bytes" << std::endl;
      std::cout << "  result plaintext size: " << result->plaintext().size() << " bytes" << std::endl;
    
      if (plaintext.size() < result->plaintext().size()) {
        std::cout << "[ERROR] Plaintext buffer too small. Need " << result->plaintext().size() 
                  << " bytes, have " << plaintext.size() << " bytes" << std::endl;
        throw ParquetException("Plaintext buffer too small for decrypted result");
      }
      
      std::cout << "[DEBUG] Copying result to plaintext buffer..." << std::endl;
      std::copy(result->plaintext().begin(), result->plaintext().end(), plaintext.begin());
      std::cout << "[DEBUG] Decryption completed successfully" << std::endl;
    
      return result->size();    
  }

std::unique_ptr<DecryptorInterface> ExternalDBPADecryptorAdapterFactory::GetDecryptor(
  ParquetCipher::type algorithm, const ColumnCryptoMetaData* crypto_metadata,
  const ColumnChunkMetaData* column_chunk_metadata,
  ExternalFileDecryptionProperties* external_file_decryption_properties) {
    if (column_chunk_metadata == nullptr || crypto_metadata == nullptr) {
      throw ParquetException("External DBPA decryption requires column chunk and crypto metadata");
    }
    auto connection_config = external_file_decryption_properties->connection_config();
    if (connection_config.find(algorithm) == connection_config.end()) {
      throw ParquetException("External DBPA decryption requires its connection configuration");
    }
    auto column_path = column_chunk_metadata->descr()->path();
    auto data_type = column_chunk_metadata->descr()->physical_type();
    std::optional<int> datatype_length;
    if (data_type == Type::FIXED_LEN_BYTE_ARRAY) {
      datatype_length = column_chunk_metadata->descr()->type_length();
    }
    auto compression_type = column_chunk_metadata->compression();
    auto encoding_types = column_chunk_metadata->encodings();
    auto app_context = external_file_decryption_properties->app_context();
    auto connection_config_for_algorithm = connection_config.at(algorithm);

    std::string key_id;
    try {
      auto key_metadata = KeyMetadata::Parse(crypto_metadata->key_metadata());
      key_id = key_metadata.key_material().master_key_id();
    } catch (const ParquetException& e) {
      // It is possible for the key metadata to only contain the key id itself, so if
      // it cannot be parsed as valid JSON, send the key id as string for the ExternalDBPA
      // to process.
      key_id = crypto_metadata->key_metadata();
    }

    return ExternalDBPADecryptorAdapter::Make(
        algorithm, column_path->ToDotString(), key_id, data_type, compression_type,
        encoding_types, app_context, connection_config_for_algorithm, datatype_length);
 }

}  // namespace parquet::encryption
