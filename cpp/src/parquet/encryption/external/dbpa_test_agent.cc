//TODO: figure out the licensing.

#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <span>
#include <vector>

#include "parquet/exception.h"
#include "parquet/encryption/external/dbpa_test_agent.h"
#include "parquet/encryption/external/third_party/dbpa_interface.h"
#include "parquet/encryption/external/third_party/span.hpp"

template <typename T>
using span = tcb::span<T>;
using dbps::external::EncryptionResult;
using dbps::external::DecryptionResult;

namespace parquet::encryption::external {

// Concrete implementation of EncryptionResult for testing
class TestEncryptionResult : public EncryptionResult {
public:
    TestEncryptionResult(std::vector<uint8_t> data, bool success = true, 
                        std::string error_msg = "", 
                        std::map<std::string, std::string> error_fields = {})
        : ciphertext_data_(std::move(data)), success_(success), 
          error_message_(std::move(error_msg)), error_fields_(std::move(error_fields)) {}

    span<const uint8_t> ciphertext() const override {
        return span<const uint8_t>(ciphertext_data_.data(), ciphertext_data_.size());
    }

    std::size_t size() const override { return static_cast<int>(ciphertext_data_.size()); }
    bool success() const override { return success_; }
    const std::string& error_message() const override { return error_message_; }
    const std::map<std::string, std::string>& error_fields() const override { return error_fields_; }

private:
    std::vector<uint8_t> ciphertext_data_;
    bool success_;
    std::string error_message_;
    std::map<std::string, std::string> error_fields_;
};

// Concrete implementation of DecryptionResult for testing
class TestDecryptionResult : public DecryptionResult {
public:
    TestDecryptionResult(std::vector<uint8_t> data, bool success = true, 
                        std::string error_msg = "", 
                        std::map<std::string, std::string> error_fields = {})
        : plaintext_data_(std::move(data)), success_(success), 
          error_message_(std::move(error_msg)), error_fields_(std::move(error_fields)) {}

    span<const uint8_t> plaintext() const override {
        return span<const uint8_t>(plaintext_data_.data(), plaintext_data_.size());
    }

    std::size_t size() const override { return plaintext_data_.size(); }
    bool success() const override { return success_; }
    const std::string& error_message() const override { return error_message_; }
    const std::map<std::string, std::string>& error_fields() const override { return error_fields_; }

private:
    std::vector<uint8_t> plaintext_data_;
    bool success_;
    std::string error_message_;
    std::map<std::string, std::string> error_fields_;
};

DBPATestAgent::DBPATestAgent() {
}

std::unique_ptr<EncryptionResult> DBPATestAgent::Encrypt(
    span<const uint8_t> plaintext,
    std::map<std::string, std::string>) {
  
  // Simple XOR encryption for testing purposes
  // In a real implementation, this would use proper encryption
  std::vector<uint8_t> ciphertext_data(plaintext.size());
  
  for (size_t i = 0; i < plaintext.size(); ++i) {
    ciphertext_data[i] = plaintext[i] ^ 0xAA; // Simple XOR with 0xAA
  }

  return std::make_unique<TestEncryptionResult>(std::move(ciphertext_data));
}

std::unique_ptr<DecryptionResult> DBPATestAgent::Decrypt(
    span<const uint8_t> ciphertext,
    std::map<std::string, std::string>) {
  
  // Simple XOR decryption for testing purposes
  // In a real implementation, this would perform actual decryption
  std::vector<uint8_t> plaintext_data(ciphertext.size());
  
  for (size_t i = 0; i < ciphertext.size(); ++i) {
    plaintext_data[i] = ciphertext[i] ^ 0xAA; // Simple XOR with 0xAA
  }

  return std::make_unique<TestDecryptionResult>(std::move(plaintext_data));
}

DBPATestAgent::~DBPATestAgent() {
}

// Export function for creating new instances from shared library
extern "C" {
  DataBatchProtectionAgentInterface* create_new_instance() {
    return new parquet::encryption::external::DBPATestAgent();
  }
}

}  // namespace parquet::encryption::external
