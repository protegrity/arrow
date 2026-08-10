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

#include "parquet/encryption/mock_encryptor_provider.h"

#include <algorithm>
#include <span>

#include "arrow/buffer.h"
#include "parquet/encryption/encoding_properties.h"
#include "parquet/exception.h"

namespace parquet::encryption::test {

namespace {

class XorEncryptor : public EncryptorInterface {
 public:
  explicit XorEncryptor(std::atomic<int>& counter) : counter_(counter) {}

  bool CanCalculateCiphertextLength() const override { return true; }

  int32_t CiphertextLength(int64_t n) const override { return static_cast<int32_t>(n); }

  int32_t Encrypt(std::span<const uint8_t> plain, std::span<const uint8_t> /*key*/,
                  std::span<const uint8_t> /*aad*/, std::span<uint8_t> cipher,
                  std::unique_ptr<EncodingProperties> /*props*/) override {
    std::transform(plain.begin(), plain.end(), cipher.begin(),
                   [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
    ++counter_;
    return static_cast<int32_t>(plain.size());
  }

  int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t> plain, ::arrow::ResizableBuffer* cipher,
      std::unique_ptr<EncodingProperties> /*props*/) override {
    PARQUET_THROW_NOT_OK(cipher->Resize(static_cast<int64_t>(plain.size())));
    std::transform(plain.begin(), plain.end(), cipher->mutable_data(),
                   [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
    ++counter_;
    return static_cast<int32_t>(plain.size());
  }

  int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                              std::span<const uint8_t>, std::span<const uint8_t>,
                              std::span<uint8_t>) override {
    throw ParquetException("XorEncryptor: SignedFooterEncrypt not supported");
  }

 private:
  std::atomic<int>& counter_;
};

}  // namespace

std::unique_ptr<EncryptorInterface> MockEncryptorProvider::GetColumnEncryptor(
    const ColumnEncryptionParams& /*params*/) {
  return std::make_unique<XorEncryptor>(call_count_);
}

}  // namespace parquet::encryption::test
