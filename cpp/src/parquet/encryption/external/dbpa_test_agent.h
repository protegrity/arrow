//TODO: figure out the licensing.

#pragma once

#include <memory>
#include <string>

#include "parquet/encryption/external/borrowed/dbpa_interface.h"
#include "borrowed/span.hpp"

using tcb::span;

using dbps::external::DataBatchProtectionAgentInterface;
using dbps::external::EncryptionResult;
using dbps::external::DecryptionResult;
using dbps::external::Type;
using dbps::external::CompressionCodec;

namespace parquet::encryption::external {

// Implementation of the DataBatchProtectionAgentInterface for testing purposes.
// It is used to test library wrapper/loading code.
// Will never be used in production.
class DBPATestAgent : public DataBatchProtectionAgentInterface {
 public:
  explicit DBPATestAgent();

  void init(
      std::string column_name,
      std::map<std::string, std::string> connection_config,
      std::string app_context,
      std::string column_key_id,
      Type::type data_type,
      CompressionCodec::type compression_type) override {
    // init() intentionally left blank
  }

  std::unique_ptr<EncryptionResult> Encrypt(
      span<const uint8_t> plaintext) override;

  std::unique_ptr<DecryptionResult> Decrypt(
      span<const uint8_t> ciphertext) override;

  ~DBPATestAgent();
};

}  // namespace parquet::encryption::external 
