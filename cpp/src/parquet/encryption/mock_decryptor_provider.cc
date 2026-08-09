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

#include "parquet/encryption/mock_decryptor_provider.h"

#include <algorithm>

namespace parquet::encryption::test {

int32_t MockDecryptorProvider::Decrypt(const ColumnEncryptionParams& /*params*/,
                                       std::span<const uint8_t> ciphertext,
                                       std::span<uint8_t> plaintext) {
  std::transform(ciphertext.begin(), ciphertext.end(), plaintext.begin(),
                 [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
  call_count_++;
  return static_cast<int32_t>(ciphertext.size());
}

int32_t MockDecryptorProvider::PlaintextLength(int32_t ciphertext_length) const {
  return ciphertext_length;
}

}  // namespace parquet::encryption::test
