// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "parquet/encryption/external/loadable_encryptor_utils.h"
#include "parquet/encryption/external/dbpa_interface.h"
#include "parquet/encryption/external/dbpa_library_wrapper.h"

#include "arrow/util/span.h"
#include <dlfcn.h>

#ifdef _WIN32
//TODO: this needs to be reviewed and tested.
#include <windows.h>
#endif

#include <iostream>
#include <stdexcept>
#include <string>

using ::arrow::util::span;

namespace parquet::encryption::external {

// Function pointer type for creating encryptor instances
// This needs to match the return type of the create_new_instance function in the shared library.
typedef DataBatchProtectionAgentInterface* (*create_encryptor_t)();

// forward declarations
void* LoadSharedLibrary(const std::string& library_path);
std::unique_ptr<DataBatchProtectionAgentInterface> CreateInstance(void* library_handle);

std::unique_ptr<DataBatchProtectionAgentInterface> LoadableEncryptorUtils::LoadFromLibrary(const std::string& library_path) {
  std::cout << "Inside LoadableEncryptorUtils::LoadFromLibrary" << std::endl;

  if (library_path.empty()) {
    throw std::invalid_argument("LoadableEncryptorUtils::LoadFromLibrary: No library path provided");
  }

  //TODO: do we need to wrap this in a try/catch block?
  //if we do that, how to we raise exceptions to the caller?

  void* library_handle = LoadSharedLibrary(library_path);
  auto agent_instance = CreateInstance(library_handle);
  auto wrapped_agent = std::make_unique<DBPALibraryWrapper>(
    std::move(agent_instance), 
    library_handle);
  return wrapped_agent;
}

void* LoadSharedLibrary(const std::string& library_path) {
  //TODO: WIN vs UNIX handling
  //    //https://github.com/apache/arrow/blob/main/cpp/src/arrow/util/io_util.cc#L2241

  // Load the shared library
  void* library_handle = dlopen(library_path.c_str(), RTLD_LAZY);
  if (library_handle != nullptr) {
    return library_handle;
  }

  std::string error_msg = "Failed to load shared library: " + library_path;

  auto dl_error = dlerror();
  if (dl_error) {
    error_msg += " - " + std::string(dl_error);
  }

  //TODO: this is likely temporary.
  std::cout << error_msg << std::endl;

  throw std::runtime_error(error_msg);
}

std::unique_ptr<DataBatchProtectionAgentInterface> CreateInstance(void* library_handle) {

  //TODO: WIN vs UNIX handling
  void* symbol_handle = dlsym(library_handle, "create_new_instance");
  if (symbol_handle == nullptr) {
    std::cerr << "Error: Cannot load symbol 'create_new_instance()': " << dlerror() << std::endl;
    dlclose(library_handle);
    return nullptr;
  }
  
  create_encryptor_t create_instance = (create_encryptor_t) symbol_handle;

  //at this point, we have the create_instance function pointer (from the shared library)
  // so we can create a new instance of the DLLEncryptor
  DataBatchProtectionAgentInterface* instance = create_instance();
  auto instance_ptr = std::unique_ptr<DataBatchProtectionAgentInterface>(instance);

  return instance_ptr;
} // CreateInstance()

} // namespace parquet::encryption::external 


