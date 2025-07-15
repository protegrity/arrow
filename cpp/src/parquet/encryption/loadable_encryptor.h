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

#pragma once

#include <string>

#include "parquet/platform.h"
#include "parquet/properties.h"
#include "parquet/types.h"
#include "parquet/encryption/encryption_internal.h"

namespace parquet::encryption {

// Forward declaration
class EncryptorInterface;

// Interface for loadable encryptors that can be dynamically loaded from shared libraries
// This extends the base EncryptorInterface with initialization capabilities
class PARQUET_EXPORT LoadableEncryptorInterface : public EncryptorInterface {
 public:
  virtual void init(ParquetCipher::type alg_id, 
    int32_t key_len,
    std::string column_name, 
    Type::type data_type,
    Compression::type compression_type, 
    Encoding::type encoding,
    std::string ext_column_key, 
    std::string user_id,
    std::string app_context,
    bool metadata, 
    bool write_length = true) = 0;
    
  virtual ~LoadableEncryptorInterface() = default;
};

}  // namespace parquet::encryption 