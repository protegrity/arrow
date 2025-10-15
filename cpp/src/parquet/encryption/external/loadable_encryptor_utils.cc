//TODO: figure out the licensing.

#include "parquet/encryption/external/loadable_encryptor_utils.h"
#include <dbpa_interface.h>
#include "parquet/encryption/external/dbpa_library_wrapper.h"

#include "arrow/util/io_util.h" //utils for loading shared libraries
#include "arrow/result.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <memory>

using ::arrow::Result;

namespace parquet::encryption::external {

// Function pointer type for creating encryptor instances
// This needs to match the return type of the create_new_instance function in the shared library.
typedef DataBatchProtectionAgentInterface* (*create_encryptor_t)();

//TODO: this should be private
std::unique_ptr<DataBatchProtectionAgentInterface> CreateInstance(void* library_handle) {
  auto symbol_result = arrow::internal::GetSymbol(library_handle, "create_new_instance");
  if (!symbol_result.ok()) {
    std::cerr << "Error: Cannot load symbol 'create_new_instance()': " << symbol_result.status().message() << std::endl;
    auto status = arrow::internal::CloseDynamicLibrary(library_handle);

    throw std::runtime_error("Failed to load symbol 'create_new_instance()': " + symbol_result.status().message());
  }
  
  //create_instance_fn is a function pointer to the create_new_instance function in the shared library.
  create_encryptor_t create_instance_fn = reinterpret_cast<create_encryptor_t>(symbol_result.ValueOrDie());

  // at this point, we have the create_instance function pointer (from the shared library)
  // so we can create a new instance of the DataBatchProtectionAgentInterface
  DataBatchProtectionAgentInterface* instance = create_instance_fn();

  if (instance == nullptr) {
    std::cerr << "Error: Cannot create instance of DataBatchProtectionAgentInterface" << std::endl;
    auto status = arrow::internal::CloseDynamicLibrary(library_handle);
    throw std::runtime_error("Failed to create instance of DataBatchProtectionAgentInterface");
  }

  auto instance_ptr = std::unique_ptr<DataBatchProtectionAgentInterface>(instance);

  return instance_ptr;
} // CreateInstance()

std::unique_ptr<DataBatchProtectionAgentInterface> LoadableEncryptorUtils::LoadFromLibrary(const std::string& library_path) {

  if (library_path.empty()) {
    throw std::invalid_argument("LoadableEncryptorUtils::LoadFromLibrary: No library path provided");
  }

  auto library_handle_result = arrow::internal::LoadDynamicLibrary(library_path.c_str());;
  if (!library_handle_result.ok()) {
    throw std::runtime_error("Failed to load library: " + library_handle_result.status().message());
  }
  
  void* library_handle = library_handle_result.ValueOrDie();
  auto agent_instance = CreateInstance(library_handle);

  //wrap the agent in a DBPALibraryWrapper
  auto wrapped_agent = std::make_unique<DBPALibraryWrapper>(
    std::move(agent_instance), 
    library_handle);

  return wrapped_agent;
}

} // namespace parquet::encryption::external 


