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

#include "parquet/encryption/test_mock_crypto_providers.h"

#include "parquet/exception.h"

namespace parquet::encryption::test {

namespace {
constexpr uint8_t kXorKey = 0xAB;
}  // namespace

::arrow::Result<std::vector<uint8_t>> XorBlockCryptoProvider::EncryptBlock(
    std::span<const uint8_t> plaintext, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  encrypt_block_calls_.fetch_add(1);
  if (!dek.empty()) calls_with_dek_.fetch_add(1);
  RecordCall(ctx, module_aad);
  std::vector<uint8_t> ciphertext(plaintext.size());
  for (size_t i = 0; i < plaintext.size(); ++i) {
    ciphertext[i] = plaintext[i] ^ kXorKey;
  }
  return ciphertext;
}

::arrow::Result<std::vector<uint8_t>> XorBlockCryptoProvider::DecryptBlock(
    std::span<const uint8_t> ciphertext, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  decrypt_block_calls_.fetch_add(1);
  if (!dek.empty()) calls_with_dek_.fetch_add(1);
  RecordCall(ctx, module_aad);
  // XOR is self-inverse: decrypting is the same transform as encrypting.
  std::vector<uint8_t> plaintext(ciphertext.size());
  for (size_t i = 0; i < ciphertext.size(); ++i) {
    plaintext[i] = ciphertext[i] ^ kXorKey;
  }
  return plaintext;
}

::arrow::Status XorBlockCryptoProvider::EncryptCells(CryptoValueBuffer& values,
                                                     const ParquetCryptoContext& ctx,
                                                     std::span<const uint8_t> dek) {
  encrypt_cells_calls_.fetch_add(1);
  return ::arrow::Status::NotImplemented(
      "XorBlockCryptoProvider::EncryptCells is unreachable: SupportsTypedValues() "
      "always returns false");
}

::arrow::Status XorBlockCryptoProvider::DecryptCells(CryptoValueBuffer& values,
                                                     const ParquetCryptoContext& ctx,
                                                     std::span<const uint8_t> dek) {
  decrypt_cells_calls_.fetch_add(1);
  return ::arrow::Status::NotImplemented(
      "XorBlockCryptoProvider::DecryptCells is unreachable: SupportsTypedValues() "
      "always returns false");
}

std::vector<ParquetCryptoContext> XorBlockCryptoProvider::seen_contexts() const {
  std::lock_guard<std::mutex> lock(contexts_mutex_);
  return seen_contexts_;
}

std::vector<std::vector<uint8_t>> XorBlockCryptoProvider::seen_module_aads() const {
  std::lock_guard<std::mutex> lock(contexts_mutex_);
  return seen_module_aads_;
}

void XorBlockCryptoProvider::RecordCall(const ParquetCryptoContext& ctx,
                                        std::span<const uint8_t> module_aad) {
  std::lock_guard<std::mutex> lock(contexts_mutex_);
  seen_contexts_.push_back(ctx);
  seen_module_aads_.emplace_back(module_aad.begin(), module_aad.end());
}

::arrow::Result<std::vector<uint8_t>> XorCellCryptoProvider::EncryptBlock(
    std::span<const uint8_t> plaintext, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  return ::arrow::Status::NotImplemented(
      "XorCellCryptoProvider::EncryptBlock is unreachable: SupportsTypedValues() "
      "always returns true");
}

::arrow::Result<std::vector<uint8_t>> XorCellCryptoProvider::DecryptBlock(
    std::span<const uint8_t> ciphertext, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  return ::arrow::Status::NotImplemented(
      "XorCellCryptoProvider::DecryptBlock is unreachable: SupportsTypedValues() "
      "always returns true");
}

::arrow::Status XorCellCryptoProvider::EncryptCells(CryptoValueBuffer& values,
                                                    const ParquetCryptoContext& ctx,
                                                    std::span<const uint8_t> dek) {
  encrypt_cells_calls_.fetch_add(1);
  auto* strings = std::get_if<std::vector<std::string>>(&values);
  if (strings == nullptr) {
    return ::arrow::Status::NotImplemented(
        "XorCellCryptoProvider::EncryptCells only supports BYTE_ARRAY values");
  }
  for (std::string& value : *strings) {
    for (char& c : value) {
      c = static_cast<char>(static_cast<uint8_t>(c) ^ kXorKey);
    }
  }
  return ::arrow::Status::OK();
}

::arrow::Status XorCellCryptoProvider::DecryptCells(CryptoValueBuffer& values,
                                                    const ParquetCryptoContext& ctx,
                                                    std::span<const uint8_t> dek) {
  decrypt_cells_calls_.fetch_add(1);
  auto* strings = std::get_if<std::vector<std::string>>(&values);
  if (strings == nullptr) {
    return ::arrow::Status::NotImplemented(
        "XorCellCryptoProvider::DecryptCells only supports BYTE_ARRAY values");
  }
  // XOR is self-inverse: decrypting is the same transform as encrypting.
  for (std::string& value : *strings) {
    for (char& c : value) {
      c = static_cast<char>(static_cast<uint8_t>(c) ^ kXorKey);
    }
  }
  return ::arrow::Status::OK();
}

}  // namespace parquet::encryption::test
