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

#include <atomic>
#include <span>

#include "parquet/encryption/external_encryptor_provider.h"

namespace parquet::encryption::test {

/// XOR-based in-process encryptor stub for unit tests only.
/// Applies a fixed XOR mask to each byte — symmetric with MockDecryptorProvider.
class MockEncryptorProvider : public ExternalEncryptorProvider {
 public:
  int32_t Encrypt(const ColumnEncryptionParams& params,
                  std::span<const uint8_t> plaintext,
                  std::span<uint8_t> ciphertext) override;

  /// Ciphertext is the same length as plaintext (XOR adds no overhead).
  int32_t CiphertextLength(int64_t plaintext_length) const override;

  /// Number of times Encrypt() has been called across all columns and pages.
  int call_count() const { return call_count_.load(); }

 private:
  std::atomic<int> call_count_{0};
};

}  // namespace parquet::encryption::test
