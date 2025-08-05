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

#include <memory>
#include <string>

#include "parquet/platform.h"
#include "parquet/encryption/external/dbpa_interface.h"

namespace parquet::encryption::external {

class PARQUET_EXPORT DBPATestAgent : public DataBatchProtectionAgentInterface {
 public:
  explicit DBPATestAgent();

  void init(std::string agent_name, 
            std::string configuration,
            bool enable_logging = true);

  std::unique_ptr<EncryptionResult> Encrypt(
      span<const uint8_t> plaintext, 
      span<uint8_t> ciphertext) override;

  std::unique_ptr<DecryptionResult> Decrypt(
      span<const uint8_t> ciphertext) override;

  ~DBPATestAgent();

 private:
  std::string agent_name_;
  std::string configuration_;
  bool enable_logging_;
  bool is_initialized_;
};

}  // namespace parquet::encryption::external 