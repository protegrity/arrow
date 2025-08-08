//TODO: figure out the licensing.

#pragma once

#include <memory>
#include <functional>

#include "parquet/encryption/external/dbpa_interface.h"
#include "arrow/util/span.h"

using ::arrow::util::span;

namespace parquet::encryption::external {

// Default implementation for shared library closing function
// This is passed into the constructor of DBPALibraryWrapper, 
// and is used as the default function to close the shared library.
void DefaultSharedLibraryClosingFn(void* library_handle);

// Decorator/Wrapper class for the DataBatchProtectionAgentInterface
// Its main purpose is to close the shared library when Arrow is about to destroy 
// an instance of an DBPAgent
//
// In the constructor we allow to pass a function that will be used to close the shared library.
// This simplifies testing, as we can use a mock function to avoid actually closing the shared library.
class DBPALibraryWrapper : public DataBatchProtectionAgentInterface {
 private:
  std::unique_ptr<DataBatchProtectionAgentInterface> wrapped_agent_;
  void* library_handle_;
  std::function<void(void*)> handle_closing_fn_;

 public:
  // Constructor that takes ownership of the wrapped agent
  explicit DBPALibraryWrapper(
      std::unique_ptr<DataBatchProtectionAgentInterface> agent,
      void* library_handle,
      std::function<void(void*)> handle_closing_fn = &DefaultSharedLibraryClosingFn);

  // Destructor
  // This is the main reason for the decorator/wrapper.
  // This will (a) destroy the wrapped agent, and (b) close the shared library.
  // While the wrapped_agent_ would automatically be destroyed when this object is destroyed
  // we need to explicitly destroy **before** we are able to close the shared library.
  // Doing it in a different order, may cause issues, as by unloading the library may cause the class
  // definition to be unloaded before the destructor completes, and that is likely to cause issues 
  // (such as a segfault).
  ~DBPALibraryWrapper() override;

  // Decorator implementation of Encrypt method - inlined for performance
  inline std::unique_ptr<EncryptionResult> Encrypt(
      span<const uint8_t> plaintext,
      span<uint8_t> ciphertext) override {
    return wrapped_agent_->Encrypt(plaintext, ciphertext);
  }

  // Decorator implementation of Decrypt method - inlined for performance
  inline std::unique_ptr<DecryptionResult> Decrypt(
      span<const uint8_t> ciphertext) override {
    return wrapped_agent_->Decrypt(ciphertext);
  }
};

}  // namespace parquet::encryption::external 
