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
#include <dbpa_interface.h>
#include "parquet/encryption/external/dbpa_library_wrapper.h"

#include "arrow/result.h"
#include "arrow/util/io_util.h"  // Utils for loading shared libraries
#include "arrow/util/logging.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using ::arrow::Result;

namespace parquet::encryption::external {

// Function pointer type for creating encryptor instances
// This needs to match the return type of the create_new_instance function in the
// shared library.
typedef DataBatchProtectionAgentInterface* (*create_encryptor_t)();
// Optional function pointer type for destroying instances inside the shared library.
// If present, Arrow will prefer calling this to avoid cross-DLL delete issues on Windows.
typedef void (*destroy_encryptor_t)(DataBatchProtectionAgentInterface*);

std::unique_ptr<DataBatchProtectionAgentInterface> LoadableEncryptorUtils::CreateInstance(
    void* library_handle) {
  auto symbol_result =
      ::arrow::internal::GetSymbol(library_handle, "create_new_instance");
  if (!symbol_result.ok()) {
    ARROW_LOG(ERROR) << "Cannot load symbol 'create_new_instance()': "
                     << symbol_result.status().message();
    auto status = ::arrow::internal::CloseDynamicLibrary(library_handle);

    throw std::runtime_error("Failed to load symbol 'create_new_instance()': " +
                             symbol_result.status().message());
  }

  // Create_instance_fn is a function pointer to the create_new_instance function in
  // the shared library.
  create_encryptor_t create_instance_fn =
      reinterpret_cast<create_encryptor_t>(symbol_result.ValueOrDie());

  // at this point, we have the create_instance function pointer (from the shared library)
  // so we can create a new instance of the DataBatchProtectionAgentInterface
  DataBatchProtectionAgentInterface* instance = create_instance_fn();

  if (instance == nullptr) {
    ARROW_LOG(ERROR) << "Cannot create instance of DataBatchProtectionAgentInterface";
    auto status = ::arrow::internal::CloseDynamicLibrary(library_handle);
    throw std::runtime_error(
        "Failed to create instance of DataBatchProtectionAgentInterface");
  }

  auto instance_ptr = std::unique_ptr<DataBatchProtectionAgentInterface>(instance);

  return instance_ptr;
}  // CreateInstance()

std::unique_ptr<DataBatchProtectionAgentInterface>
LoadableEncryptorUtils::LoadFromLibrary(const std::string& library_path) {
  if (library_path.empty()) {
    throw std::invalid_argument(
        "LoadableEncryptorUtils::LoadFromLibrary: No library path provided");
  }

  auto library_handle_result =
      ::arrow::internal::LoadDynamicLibrary(library_path.c_str());
  if (!library_handle_result.ok()) {
    throw std::runtime_error("Failed to load library: " +
                             library_handle_result.status().message());
  }

  void* library_handle = library_handle_result.ValueOrDie();
  auto agent_instance = CreateInstance(library_handle);

  // Best-effort: look for an optional destroy function.
  // We don't require it for backwards compatibility.
  destroy_encryptor_t destroy_instance_fn = nullptr;
  auto destroy_symbol_result =
      ::arrow::internal::GetSymbol(library_handle, "destroy_instance");
  if (destroy_symbol_result.ok()) {
    destroy_instance_fn =
        reinterpret_cast<destroy_encryptor_t>(destroy_symbol_result.ValueOrDie());
  } else {
    ARROW_LOG(DEBUG)
        << "Optional symbol 'destroy_instance(DataBatchProtectionAgentInterface*)' not "
           "found in DBPA library; falling back to delete.";
  }

  // Wrap the agent in a DBPALibraryWrapper
  auto wrapped_agent =
      std::make_unique<DBPALibraryWrapper>(std::move(agent_instance), library_handle,
                                           &DefaultSharedLibraryClosingFn,
                                           destroy_instance_fn);

  return wrapped_agent;
}

}  // namespace parquet::encryption::external
