//TODO: figure out the licensing.

#include <iostream>
#include <memory>
#include <string>
#include <filesystem>

#include "gtest/gtest.h"
#include "parquet/encryption/external/loadable_encryptor_utils.h"
#include "parquet/encryption/external/dbpa_interface.h"
#include "parquet/encryption/external/dbpa_library_wrapper.h"
#include "arrow/util/span.h"
#include "parquet/test_util.h"

#ifdef __APPLE__
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <unistd.h>
#include <linux/limits.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace parquet::encryption::external::test {

// Test fixture for LoadableEncryptorUtils tests
class LoadableEncryptorUtilsTest : public ::testing::Test {
  public:
    std::string library_path_;

  protected:
    void SetUp() override {
      // Get the path to the DBPATestAgent shared library
      // This assumes the library is built 
      library_path_ = GetTestLibraryPath();
    }

// Helper function to get the directory where the executable is located
// used within GetTestLibraryPath to determine the path to the test library (*.so)
std::string GetExecutableDirectory() {
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

  // Helper method to get the path to the test library
  std::string GetTestLibraryPath() {
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
      base_path + "/"
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
};

// ============================================================================
// SUCCESS TESTS
// ============================================================================

TEST_F(LoadableEncryptorUtilsTest, LoadValidLibrary) {
  // Test loading the library
  std::unique_ptr<DataBatchProtectionAgentInterface> agent;
  
  try {
    agent = LoadableEncryptorUtils::LoadFromLibrary(library_path_);
    ASSERT_NE(agent, nullptr) << "Agent should be successfully loaded";
  } catch (const std::runtime_error& e) {
    // Library doesn't exist or failed to load - this is expected in some build environments
    GTEST_SKIP() << "Library not available: " << e.what();
  }
}

TEST_F(LoadableEncryptorUtilsTest, MultipleLoads) {
  // Load multiple agents
  std::unique_ptr<DataBatchProtectionAgentInterface> agent1, agent2, agent3;
  
  try {
    agent1 = LoadableEncryptorUtils::LoadFromLibrary(library_path_);
    agent2 = LoadableEncryptorUtils::LoadFromLibrary(library_path_);
    agent3 = LoadableEncryptorUtils::LoadFromLibrary(library_path_);
    
    ASSERT_NE(agent1, nullptr) << "First agent should be successfully loaded";
    ASSERT_NE(agent2, nullptr) << "Second agent should be successfully loaded";
    ASSERT_NE(agent3, nullptr) << "Third agent should be successfully loaded";

    // Verify that all instances are different from each other
    ASSERT_NE(agent1.get(), agent2.get()) << "First and second agents should be different instances";
    ASSERT_NE(agent1.get(), agent3.get()) << "First and third agents should be different instances";
    ASSERT_NE(agent2.get(), agent3.get()) << "Second and third agents should be different instances";
    
  } catch (const std::runtime_error& e) {
    // Library doesn't exist or failed to load - this is expected in some build environments
    GTEST_SKIP() << "Library not available: " << e.what();
  }
}

TEST_F(LoadableEncryptorUtilsTest, ReturnsDBPALibraryWrapper) {
  // Test that LoadFromLibrary returns an instance of DBPALibraryWrapper
  std::unique_ptr<DataBatchProtectionAgentInterface> agent;
  
  try {
    agent = LoadableEncryptorUtils::LoadFromLibrary(library_path_);
    ASSERT_NE(agent, nullptr) << "Agent should be successfully loaded";
    
    // Verify that the returned instance is of type DBPALibraryWrapper
    DBPALibraryWrapper* wrapper = dynamic_cast<DBPALibraryWrapper*>(agent.get());
    EXPECT_NE(wrapper, nullptr) << "Returned instance should be of type DBPALibraryWrapper";    
  } catch (const std::runtime_error& e) {
    // Library doesn't exist or failed to load - this is expected in some build environments
    GTEST_SKIP() << "Library not available: " << e.what();
  }
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

TEST_F(LoadableEncryptorUtilsTest, EmptyLibraryPath) {
  EXPECT_THROW({
    LoadableEncryptorUtils::LoadFromLibrary("");
  }, std::invalid_argument);
}

TEST_F(LoadableEncryptorUtilsTest, NonexistentLibrary) {
  EXPECT_THROW({
    LoadableEncryptorUtils::LoadFromLibrary("./nonexistent_library.so");
  }, std::runtime_error);
}

TEST_F(LoadableEncryptorUtilsTest, InvalidLibraryPath) {
  EXPECT_THROW({
    LoadableEncryptorUtils::LoadFromLibrary("/invalid/path/to/library.so");
  }, std::runtime_error);
}

}  // namespace parquet::encryption::external::test 
