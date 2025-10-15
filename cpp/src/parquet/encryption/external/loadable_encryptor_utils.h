//TODO: figure out the licensing.

#pragma once

#include <memory>
#include <string>

#include "parquet/platform.h"
#include <dbpa_interface.h>

using dbps::external::DataBatchProtectionAgentInterface;

namespace parquet::encryption::external {

class PARQUET_EXPORT LoadableEncryptorUtils {
 public:
  //Will load the shared library and instantiate the DataBatchProtectionAgentInterface 
  // provided by the shared library. The instance will be wrapped in a DBPALibraryWrapper.
  static std::unique_ptr<DataBatchProtectionAgentInterface> LoadFromLibrary(const std::string& library_path);
};

}  // namespace parquet::encryption::external 
