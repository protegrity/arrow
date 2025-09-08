// TODO: figure out the licensing.

#pragma once

#include <string>

namespace parquet::encryption::external::test {

/**
 * Utility class for test-related helper functions.
 */
class TestUtils {
 public:
  /**
   * Get the directory where the executable is located.
   * Used to determine the path to test libraries (*.so, *.dylib, *.dll).
   * 
   * @return The directory path where the executable is located
   */
  static std::string GetExecutableDirectory();

  /**
   * Get the path to the test library (DBPATestAgent).
   * Searches for the library in various possible locations and filenames.
   * 
   * @return The full path to the test library
   * @throws std::runtime_error if the library cannot be found
   */
  static std::string GetTestLibraryPath();
};

}  // namespace parquet::encryption::external::test
