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
  // Check for environment variable to override the executable directory
  const char* cwd_override = std::getenv("PARQUET_TEST_LIBRARY_CWD");
  std::string base_path;

  const std::string exec_dir = GetExecutableDirectory();
  if (cwd_override && cwd_override[0]) {
    base_path = std::string(cwd_override);
  } else {
    // Get the directory where the executable is located
    base_path = exec_dir;
  }

  std::vector<std::string> possible_filenames = {
      #if defined(__linux__)
        "libDBPATestAgent.so"
      #elif defined(__APPLE__)
        "libDBPATestAgent.dylib"
      #elif defined(_WIN32)
        // Windows (MSVC): no "lib" prefix for DLLs
        "DBPATestAgent.dll",
        // Windows (MinGW): typically uses "lib" prefix even for DLLs
        "libDBPATestAgent.dll",

        // Some toolchains use a debug postfix (commonly "d")
        "DBPATestAgentd.dll",
        "libDBPATestAgentd.dll"
      #endif
    };

  std::vector<std::string> possible_directories = {exec_dir + "/", base_path + "/",
                                                   "./", ""};

  // Arrow's CMake places most runtime artifacts under:
  //   <build>/cpp/<lowercase-build-type>/
  // and CI often runs `ctest` from <build>/cpp. On Windows in particular, this
  // means the shared library can sit under "./debug/" (or "./release/") even
  // when the test executable isn't.
  const std::string cwd = std::filesystem::current_path().string();
  const std::filesystem::path cwd_path = std::filesystem::current_path();
  const std::filesystem::path exec_dir_path = std::filesystem::path(exec_dir);
  const std::string exec_parent = exec_dir_path.parent_path().string();

  // Common CMake build-type directory spellings (Arrow CI frequently uses "debug").
  const std::vector<std::string> build_type_dirs = {
      "debug", "Debug", "release", "Release", "relwithdebinfo", "RelWithDebInfo",
      "minsizerel", "MinSizeRel"};

  auto add_build_type_dirs = [&](const std::filesystem::path& root) {
    if (root.empty()) {
      return;
    }
    const std::string root_s = root.string();
    for (const auto& cfg : build_type_dirs) {
      possible_directories.push_back(root_s + "/" + cfg + "/");
    }
  };

  // Search build-type dirs under CWD and a few parents (handles ctest running
  // from build/cpp/src/* while outputs are in build/cpp/<cfg>/).
  {
    std::filesystem::path p = cwd_path;
    for (int i = 0; i < 5 && !p.empty(); ++i) {
      add_build_type_dirs(p);
      p = p.parent_path();
    }
  }

  // Also handle the common "build root" case where CWD is <build> (not <build>/cpp).
  for (const auto& cfg : build_type_dirs) {
    possible_directories.push_back(cwd + "/cpp/" + cfg + "/");
  }

  // Finally, search under the executable's parent and its parents.
  {
    std::filesystem::path p = exec_dir_path.parent_path();
    for (int i = 0; i < 5 && !p.empty(); ++i) {
      add_build_type_dirs(p);
      p = p.parent_path();
    }
  }

  if (!exec_parent.empty()) {
    possible_directories.push_back(exec_parent + "/");
  }

  for (const auto& filename : possible_filenames) {
    for (const auto& directory : possible_directories) {
      std::string path = directory + filename;
      if (std::filesystem::exists(path)) {
        return path;
      }
    }
  }

  throw std::runtime_error("test_utils.cc: Could not find DBPATestAgent library ");
}

}  // namespace parquet::encryption::external::test
