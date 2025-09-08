// TODO: figure out the licensing.

#include "parquet/encryption/external/test_utils.h"

#include <filesystem>
#include <string>
#include <vector>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <unistd.h>
#include <linux/limits.h>
#elif defined(_WIN32)
#include <windows.h>
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
  
  if (cwd_override && cwd_override[0]) {
    base_path = std::string(cwd_override);
  } else {
    // Get the directory where the executable is located
    base_path = GetExecutableDirectory();
  }

  std::vector<std::string> possible_filenames = {
    "libDBPATestAgent.so",
    "libDBPATestAgent.dylib",
    "DBPATestAgent.dll"
  };

  std::vector<std::string> possible_directories = {
    GetExecutableDirectory() + "/",
    base_path + "/",
    "./",
    ""
  };

  for (const auto& filename : possible_filenames) {
    for (const auto& directory : possible_directories) {
      std::string path = directory + filename;
      if (std::filesystem::exists(path)) {
        return path;
      }
    }
  }

  throw std::runtime_error("Could not find library");
}

}  // namespace parquet::encryption::external::test
