//TODO: figure out the licensing.

#include "parquet/encryption/external/dbpa_library_wrapper.h"
#include "parquet/encryption/external/third_party/dbpa_interface.h"

#include <stdexcept>
#include <functional>

#include <iostream>

#include "arrow/util/io_util.h"

namespace parquet::encryption::external {

// Default implementation for handle closing function
void DefaultSharedLibraryClosingFn(void* library_handle) {
  auto status = arrow::internal::CloseDynamicLibrary(library_handle);
  if (!status.ok()) {
    std::cerr << "Error closing library: " << status.message() << std::endl;
  }
}

DBPALibraryWrapper::DBPALibraryWrapper(
    std::unique_ptr<DataBatchProtectionAgentInterface> agent,
    void* library_handle,
    std::function<void(void*)> handle_closing_fn)
    : wrapped_agent_(std::move(agent)), 
      library_handle_(library_handle),
      handle_closing_fn_(std::move(handle_closing_fn)) {
  // Ensure the wrapped agent is not null
  if (!wrapped_agent_) {
    throw std::invalid_argument("DBPAWrapper: Cannot create wrapper with null agent");
  }
  if (!library_handle_) {
    throw std::invalid_argument("DBPAWrapper: Cannot create wrapper with null library handle");
  }
  if (!handle_closing_fn_) {
    throw std::invalid_argument("DBPAWrapper: Cannot create wrapper with null handle closing function");
  }
}

// DBPALibraryWrapper destructor
// This is the main reason for the decorator/wrapper.
// This will (a) destroy the wrapped agent, and (b) close the shared library.
// While the wrapped_agent_ would automatically be destroyed when this object is destroyed
// we need to explicitly destroy **before** we are able to close the shared library.
// Doing it in a different order, may cause issues, as by unloading the library may cause the class
// definition to be unloaded before the destructor completes, and that is likely to cause issues 
// (such as a segfault).
DBPALibraryWrapper::~DBPALibraryWrapper() {
  // Explicitly destroy the wrapped agent first
  if (wrapped_agent_) {
    DataBatchProtectionAgentInterface* wrapped_agent = wrapped_agent_.release();
    delete wrapped_agent;
  }
  
  // Now we can close the shared library using the provided function
  handle_closing_fn_(library_handle_);
  library_handle_ = nullptr;
} //DBPALibraryWrapper::~DBPALibraryWrapper()
}  // namespace parquet::encryption::external
