//TODO: figure out the licensing.

#pragma once

#include <memory>
#include <string>

#include "parquet/platform.h"
#include "parquet/encryption/external/dbpa_interface.h"

namespace parquet::encryption::external {

// Implementation of the DataBatchProtectionAgentInterface for testing purposes.
// It is not used in production.
class PARQUET_EXPORT DBPATestAgent : public DataBatchProtectionAgentInterface {
 public:
  explicit DBPATestAgent();

  void init(std::string agent_name, 
            std::string configuration,
            bool enable_logging = true);

  std::unique_ptr<EncryptionResult> Encrypt(
      span<const uint8_t> plaintext, 
      span<uint8_t> ciphertext) override;

  std::unique_ptr<DecryptionResult> Decrypt(
      span<const uint8_t> ciphertext) override;

  ~DBPATestAgent();

 private:
  std::string agent_name_;
  std::string configuration_;
  bool enable_logging_;
  bool is_initialized_;
};

}  // namespace parquet::encryption::external 
