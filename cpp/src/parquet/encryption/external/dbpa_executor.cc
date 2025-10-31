#include "parquet/encryption/external/dbpa_executor.h"
#include <dbpa_interface.h>

#include <stdexcept>
#include <iostream>
#include <future>
#include <string>

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
  
  std::cout << "[DBPAExecutor] Starting " << operation_name << " operation with timeout " 
            << timeout_milliseconds << " milliseconds" << std::endl;
  
  auto start_time = std::chrono::steady_clock::now();
  
  // Create a future to run the operation asynchronously
  std::cout << "[DBPAExecutor] Creating async future for " << operation_name << std::endl;
  auto future = std::async(std::launch::async, [&]() -> ReturnType {
    std::cout << "[DBPAExecutor] Async task started for " << operation_name << std::endl;
    try {
      if constexpr (std::is_void_v<ReturnType>) {
        func(args...);
        std::cout << "[DBPAExecutor] Async task completed successfully for " << operation_name << std::endl;
      } else {
        auto result = func(args...);
        std::cout << "[DBPAExecutor] Async task completed successfully for " << operation_name << std::endl;
        return result;
      }
    } 
    catch (const std::exception& e) {
      std::cout << "[DBPAExecutor] Async task threw exception for " << operation_name 
                << ": " << e.what() << std::endl;
      throw; // Re-throw original exception
    }  // TODO: are there exceptions which are not a sub-class of std::exception?
    catch (...) {
      std::cout << "[DBPAExecutor] Async task threw unknown exception for " << operation_name << std::endl;
      throw; // Re-throw original exception
    }
  });
  
  std::cout << "[DBPAExecutor] Future created, waiting for " << operation_name 
            << " with timeout " << timeout_milliseconds << " milliseconds" << std::endl;
  
  // Wait for the function to complete or timeout.
  auto status = future.wait_for(std::chrono::milliseconds(timeout_milliseconds));
  
  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  
  if (status == std::future_status::timeout) {
    std::cout << "[DBPAExecutor] TIMEOUT: " << operation_name << " exceeded " 
              << timeout_milliseconds << " milliseconds (actual: " << duration.count() << "ms)" << std::endl;
    throw DBPAExecutorTimeoutException(operation_name, timeout_milliseconds);
  }
  
  std::cout << "[DBPAExecutor] Future completed for " << operation_name 
            << " in " << duration.count() << "ms, retrieving result..." << std::endl;
  
  try {
    // If any exceptions are thrown in the body of the function,
    // they will be re-thrown by future.get() (unchanged, no wrapping)
    // TODO: when/if logging is simplified, this block should also be simplified.
    if constexpr (std::is_void_v<ReturnType>) {
      future.get();
      std::cout << "[DBPAExecutor] SUCCESS: " << operation_name << " completed successfully" << std::endl;
    } else {
      auto result = future.get();
      std::cout << "[DBPAExecutor] SUCCESS: " << operation_name << " completed successfully" << std::endl;
      return result;
    }
  } catch (const std::exception& e) {
    std::cout << "[DBPAExecutor] EXCEPTION: " << operation_name << " failed with: " << e.what() << std::endl;
    throw; // Re-throw original exception
  } catch (...) {
    std::cout << "[DBPAExecutor] UNKNOWN EXCEPTION: " << operation_name << " failed with unknown exception" << std::endl;
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
    std::cout << "[DBPAExecutor] ERROR: Cannot create executor with null agent" << std::endl;
    throw std::invalid_argument("DBPAExecutor: Cannot create executor with null agent");
  }

  std::cout << "[DBPAExecutor] Constructor called with timeouts - init: " << init_timeout 
            << "ms, encrypt: " << encrypt_timeout << "ms, decrypt: " << decrypt_timeout << "ms" << std::endl;
  
  // Validate timeout values
  if (init_timeout_milliseconds_ <= 0 || encrypt_timeout_milliseconds_ <= 0 || decrypt_timeout_milliseconds_ <= 0) {
    std::cout << "[DBPAExecutor] ERROR: Invalid timeout values - init: " << init_timeout_milliseconds_
              << ", encrypt: " << encrypt_timeout_milliseconds_ 
              << ", decrypt: " << decrypt_timeout_milliseconds_ << std::endl;
    throw std::invalid_argument("DBPAExecutor: All timeout values must be positive");
  }
  
  std::cout << "[DBPAExecutor] Constructor completed successfully" << std::endl;
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

  std::cout << "[DBPAExecutor] init() called for column: " << column_name 
            << ", key_id: " << column_key_id << std::endl;

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
  
  std::cout << "[DBPAExecutor] Encrypt() called with " << plaintext.size() << " bytes" << std::endl;
  
  return ExecuteWithTimeout("encrypt", encrypt_timeout_milliseconds_,
                           [this](span<const uint8_t> pt, std::map<std::string, std::string> attrs) {
                             return wrapped_agent_->Encrypt(pt, std::move(attrs));
                           },
                           plaintext, std::move(encoding_attributes));
}

std::unique_ptr<DecryptionResult> DBPAExecutor::Decrypt(
    span<const uint8_t> ciphertext,
    std::map<std::string, std::string> encoding_attributes) {
  
  std::cout << "[DBPAExecutor] Decrypt() called with " << ciphertext.size() << " bytes" << std::endl;
  
  return ExecuteWithTimeout("decrypt", decrypt_timeout_milliseconds_,
                           [this](span<const uint8_t> ct, std::map<std::string, std::string> attrs) {
                             return wrapped_agent_->Decrypt(ct, std::move(attrs));
                           },
                           ciphertext, std::move(encoding_attributes));
}

}  // namespace parquet::encryption::external