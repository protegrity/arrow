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

#include "parquet/encryption/external/test_utils.h"

#include <filesystem>
#include <string>
#include <vector>
#include <iostream>

#ifdef __APPLE__
#  include <mach-o/dyld.h>
#elif defined(__linux__)
#  include <linux/limits.h>
#  include <unistd.h>
#elif defined(_WIN32)
#  include <windows.h>
#endif

namespace parquet::encryption::external::test {

std::string TestUtils::GetExecutableDirectory() {
#ifdef __APPLE__
  char path[PATH_MAX];
  uint32_t size = sizeof(path);
  if (_NSGetExecutablePath(path, &size) == 0) {
    return std::filesystem::path(path).parent_path().string();
  }
#elif defined(__linux__)
  char path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (len != -1) {
    path[len] = '\0';
    return std::filesystem::path(path).parent_path().string();
  }
#elif defined(_WIN32)
  char path[MAX_PATH];
  if (GetModuleFileNameA(NULL, path, MAX_PATH) != 0) {
    return std::filesystem::path(path).parent_path().string();
  }
#endif
  // Fallback to current working directory if we can't determine executable path
  return std::filesystem::current_path().string();
}

std::string TestUtils::GetTestLibraryPath() {
  // Strong override: reuse the same env var as the Python tooling
  // (`python/scripts/base_app.py`): DBPA_LIBRARY_PATH.
  //
  // This allows CI/build systems to provide the exact path to the DBPA agent shared
  // library, avoiding reliance on executable-path heuristics or current working directory.
  const char* explicit_path = std::getenv("DBPA_LIBRARY_PATH");
  if (explicit_path && explicit_path[0]) {
    std::string p(explicit_path);
    if (std::filesystem::exists(p)) {
      return p;
    }
    throw std::runtime_error("DBPA_LIBRARY_PATH is set but the file does not exist: " +
                             p);
  }

  // Check for environment variable to override the executable directory
  const char* cwd_override = std::getenv("PARQUET_TEST_LIBRARY_CWD");
  std::string base_path;

  if (cwd_override && cwd_override[0]) {
    base_path = std::string(cwd_override);
  } else {
    // Get the directory where the executable is located
    base_path = GetExecutableDirectory();
  }

  std::vector<std::string> possible_filenames = {
      "libDBPATestAgent.so", "libDBPATestAgent.dylib", "DBPATestAgent.dll"};

  std::vector<std::string> possible_directories = {GetExecutableDirectory() + "/",
                                                   base_path + "/", "./", ""};

  for (const auto& filename : possible_filenames) {
    for (const auto& directory : possible_directories) {
      std::string path = directory + filename;
      if (std::filesystem::exists(path)) {
        return path;
      }
    }
  }

  // Provide a detailed error to make CI failures diagnosable.
  std::string msg = "Could not find DBPA test agent library. Tried:\n";
  for (const auto& filename : possible_filenames) {
    for (const auto& directory : possible_directories) {
      msg += "  - " + (directory + filename) + "\n";
    }
  }
  msg += "PARQUET_TEST_LIBRARY_CWD=";
  msg += (cwd_override && cwd_override[0]) ? cwd_override : "<unset>";
  msg += "\n";
  throw std::runtime_error(msg);
}

}  // namespace parquet::encryption::external::test
