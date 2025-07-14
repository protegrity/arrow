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

#include "parquet/encryption/loadable_encryptor_utils.h"
#include "parquet/encryption/dll_encryptor.h"
#include <dlfcn.h>

#include <iostream>
#include <stdexcept>

namespace parquet::encryption {

// Function pointer type for creating encryptor instances
// This needs to match the return type of the create_new_instance function in the shared library.
typedef LoadableEncryptorInterface* (*create_encryptor_t)();

std::unique_ptr<LoadableEncryptorInterface> LoadableEncryptorUtils::LoadFromLibrary(const std::string& library_path) {
  std::cout << "Inside LoadableEncryptorUtils::LoadFromLibrary" << std::endl;

  // If library_path is provided, try to load the shared library
  if (!library_path.empty()) {
    try {

      // Load the shared library
      auto library_handle = dlopen(library_path.c_str(), RTLD_LAZY);

      if (!library_handle) {
        std::cout << "Warning: Failed to load shared library: " << library_path << std::endl;
        return nullptr;
      }

      //load the create_new_instance() function from the library
      create_encryptor_t create_instance = (create_encryptor_t) dlsym(library_handle, "create_new_instance");
      const char* dlsym_error = dlerror();

      if (dlsym_error) {
        std::cerr << "Error: Cannot load symbol 'create_new_instance()': " << dlsym_error << std::endl;
        dlclose(library_handle);

        //TODO: what to return here?
        return nullptr;
      }

      //at this point, we have the create_instance function pointer (from the shared library)
      // so we can create a new instance of the DLLEncryptor
      auto instance = std::unique_ptr<LoadableEncryptorInterface>(create_instance());

      std::cout << "LoadableEncryptorUtils -- Successfully loaded DLLEncryptor from shared library: " << library_path << std::endl;

      
      return instance;
    } catch (const std::exception& e) {
      std::cout << "Warning: Exception while loading shared library: " << e.what() << std::endl;      
    }

  } //if (!library_path.empty())

  std::cout << "Returning nullptr" << std::endl;
  return nullptr;
}

}  // namespace parquet::encryption 