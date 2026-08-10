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
#include <span>

#include "arrow/buffer.h"
#include "parquet/encryption/encoding_properties.h"

namespace parquet::encryption::test {

namespace {

class XorDecryptor : public DecryptorInterface {
 public:
  explicit XorDecryptor(std::atomic<int>& counter) : counter_(counter) {}

  bool CanCalculateLengths() const override { return true; }
  int32_t PlaintextLength(int32_t n) const override { return n; }
  // XOR is its own inverse; ciphertext and plaintext are equal length.
  int32_t CiphertextLength(int32_t n) const override { return n; }

  int32_t Decrypt(std::span<const uint8_t> cipher, std::span<const uint8_t> /*key*/,
                  std::span<const uint8_t> /*aad*/, std::span<uint8_t> plain,
                  std::unique_ptr<EncodingProperties> /*props*/) override {
    std::transform(cipher.begin(), cipher.end(), plain.begin(),
                   [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
    ++counter_;
    return static_cast<int32_t>(cipher.size());
  }

  int32_t DecryptWithManagedBuffer(
      std::span<const uint8_t> cipher, ::arrow::ResizableBuffer* plain,
      std::unique_ptr<EncodingProperties> /*props*/) override {
    PARQUET_THROW_NOT_OK(plain->Resize(static_cast<int64_t>(cipher.size())));
    std::transform(cipher.begin(), cipher.end(), plain->mutable_data(),
                   [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
    ++counter_;
    return static_cast<int32_t>(cipher.size());
  }

 private:
  std::atomic<int>& counter_;
};

}  // namespace

std::unique_ptr<DecryptorInterface> MockDecryptorProvider::GetColumnDecryptor(
    const ColumnEncryptionParams& /*params*/) {
  return std::make_unique<XorDecryptor>(call_count_);
}

}  // namespace parquet::encryption::test
