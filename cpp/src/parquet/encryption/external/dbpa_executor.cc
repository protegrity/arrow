#include "parquet/encryption/external/dbpa_executor.h"
#include <dbpa_interface.h>

#include <stdexcept>
#include <iostream>
#include <future>
#include <string>

#include "arrow/util/logging.h"

namespace parquet::encryption::external {


/**
  * Utility function to execute a wrapped operation with timeout using 
  * pure C++ futures
  * @tparam Func The function type to execute
  * @tparam Args The argument types
  * @param operation_name Name of the operation for error reporting
  * @param timeout_milliseconds Timeout in milliseconds
  * @param func The function to execute
  * @param args The arguments to pass to the function
  * @return The result of the function execution
  */
template<typename Func, typename... Args>
auto ExecuteWithTimeout(const std::string& operation_name, 
                      int64_t timeout_milliseconds, 
                      Func&& func, 
                      Args&&... args) -> decltype(func(args...)) {

  // Get the return type of the function that we're executing
  using ReturnType = decltype(func(args...));
  
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Starting " << operation_name << " operation with timeout " 
                   << timeout_milliseconds << " milliseconds";
  
  auto start_time = std::chrono::steady_clock::now();
  
  // Create a future to run the operation asynchronously
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Creating async future for " << operation_name;
  auto future = std::async(std::launch::async, [&]() -> ReturnType {
    ARROW_LOG(DEBUG) << "[DBPAExecutor] Async task started for " << operation_name;
    try {
      if constexpr (std::is_void_v<ReturnType>) {
        func(args...);
        ARROW_LOG(DEBUG) << "[DBPAExecutor] Async task completed successfully for " << operation_name;
      } else {
        auto result = func(args...);
        ARROW_LOG(DEBUG) << "[DBPAExecutor] Async task completed successfully for " << operation_name;
        return result;
      }
    } 
    catch (const std::exception& e) {
      ARROW_LOG(ERROR) << "[DBPAExecutor] Async task threw exception for " << operation_name 
                       << ": " << e.what();
      throw; // Re-throw original exception
    }  // TODO: are there exceptions which are not a sub-class of std::exception?
    catch (...) {
      ARROW_LOG(ERROR) << "[DBPAExecutor] Async task threw unknown exception for " << operation_name;
      throw; // Re-throw original exception
    }
  });
  
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Future created, waiting for " << operation_name 
                   << " with timeout " << timeout_milliseconds << " milliseconds";
  
  // Wait for the function to complete or timeout.
  auto status = future.wait_for(std::chrono::milliseconds(timeout_milliseconds));
  
  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  
  if (status == std::future_status::timeout) {
    ARROW_LOG(ERROR) << "[DBPAExecutor] TIMEOUT: " << operation_name << " exceeded " 
                     << timeout_milliseconds << " milliseconds (actual: " << duration.count() << "ms)";
    throw DBPAExecutorTimeoutException(operation_name, timeout_milliseconds);
  }
  
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Future completed for " << operation_name 
                   << " in " << duration.count() << "ms, retrieving result...";
  
  try {
    // If any exceptions are thrown in the body of the function,
    // they will be re-thrown by future.get() (unchanged, no wrapping)
    // TODO: when/if logging is simplified, this block should also be simplified.
    if constexpr (std::is_void_v<ReturnType>) {
      future.get();
      ARROW_LOG(DEBUG) << "[DBPAExecutor] SUCCESS: " << operation_name << " completed successfully";
    } else {
      auto result = future.get();
      ARROW_LOG(DEBUG) << "[DBPAExecutor] SUCCESS: " << operation_name << " completed successfully";
      return result;
    }
  } catch (const std::exception& e) {
    ARROW_LOG(ERROR) << "[DBPAExecutor] EXCEPTION: " << operation_name << " failed with: " << e.what();
    throw; // Re-throw original exception
  } catch (...) {
    ARROW_LOG(ERROR) << "[DBPAExecutor] UNKNOWN EXCEPTION: " << operation_name << " failed with unknown exception";
    throw; // Re-throw original exception
  }
}
 
DBPAExecutor::DBPAExecutor(std::unique_ptr<DataBatchProtectionAgentInterface> agent,
                           int64_t init_timeout,
                           int64_t encrypt_timeout,
                           int64_t decrypt_timeout)
    : wrapped_agent_(std::move(agent)),
      init_timeout_milliseconds_(init_timeout),
      encrypt_timeout_milliseconds_(encrypt_timeout),
      decrypt_timeout_milliseconds_(decrypt_timeout) {
  
  // Ensure the wrapped agent is not null
  if (!wrapped_agent_) {
    ARROW_LOG(ERROR) << "[DBPAExecutor] ERROR: Cannot create executor with null agent";
    throw std::invalid_argument("DBPAExecutor: Cannot create executor with null agent");
  }

  ARROW_LOG(DEBUG) << "[DBPAExecutor] Constructor called with timeouts - init: " << init_timeout 
                   << "ms, encrypt: " << encrypt_timeout << "ms, decrypt: " << decrypt_timeout << "ms";
  
  // Validate timeout values
  if (init_timeout_milliseconds_ <= 0 || encrypt_timeout_milliseconds_ <= 0 || decrypt_timeout_milliseconds_ <= 0) {
    ARROW_LOG(ERROR) << "[DBPAExecutor] ERROR: Invalid timeout values - init: " << init_timeout_milliseconds_
                     << ", encrypt: " << encrypt_timeout_milliseconds_ 
                     << ", decrypt: " << decrypt_timeout_milliseconds_;
    throw std::invalid_argument("DBPAExecutor: All timeout values must be positive");
  }
  
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Constructor completed successfully";
}

void DBPAExecutor::init(
    std::string column_name,
    std::map<std::string, std::string> connection_config,
    std::string app_context,
    std::string column_key_id,
    Type::type data_type,
    std::optional<int> datatype_length,
    CompressionCodec::type compression_type,
    std::optional<std::map<std::string, std::string>> column_encryption_metadata) {

  ARROW_LOG(DEBUG) << "[DBPAExecutor] init() called for column: " << column_name 
                   << ", key_id: " << column_key_id;

  ExecuteWithTimeout("init", init_timeout_milliseconds_, 
                [this](std::string col_name, 
                       std::map<std::string, std::string> conn_config,
                       std::string app_ctx,
                       std::string col_key_id,
                       Type::type dt,
                       std::optional<int> dt_len,
                       CompressionCodec::type comp_type,
                       std::optional<std::map<std::string, std::string>> col_enc_metadata) {
                  wrapped_agent_->init(std::move(col_name), std::move(conn_config),
                                      std::move(app_ctx), std::move(col_key_id),
                                      dt, dt_len, comp_type, std::move(col_enc_metadata));
                },
                std::move(column_name), std::move(connection_config),
                std::move(app_context), std::move(column_key_id),
                data_type, datatype_length, compression_type, std::move(column_encryption_metadata));
}

std::unique_ptr<EncryptionResult> DBPAExecutor::Encrypt(
    span<const uint8_t> plaintext,
    std::map<std::string, std::string> encoding_attributes) {
  
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Encrypt() called with " << plaintext.size() << " bytes";
  
  return ExecuteWithTimeout("encrypt", encrypt_timeout_milliseconds_,
                           [this](span<const uint8_t> pt, std::map<std::string, std::string> attrs) {
                             return wrapped_agent_->Encrypt(pt, std::move(attrs));
                           },
                           plaintext, std::move(encoding_attributes));
}

std::unique_ptr<DecryptionResult> DBPAExecutor::Decrypt(
    span<const uint8_t> ciphertext,
    std::map<std::string, std::string> encoding_attributes) {
  
  ARROW_LOG(DEBUG) << "[DBPAExecutor] Decrypt() called with " << ciphertext.size() << " bytes";
  
  return ExecuteWithTimeout("decrypt", decrypt_timeout_milliseconds_,
                           [this](span<const uint8_t> ct, std::map<std::string, std::string> attrs) {
                             return wrapped_agent_->Decrypt(ct, std::move(attrs));
                           },
                           ciphertext, std::move(encoding_attributes));
}

}  // namespace parquet::encryption::external