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

#include <algorithm>
#include <type_traits>

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

::arrow::Result<std::vector<uint8_t>> XorBlockCryptoProvider::SignFooter(
    std::span<const uint8_t> footer_bytes, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> footer_aad, std::span<const uint8_t> dek) {
  std::vector<uint8_t> signature;
  signature.reserve(footer_aad.size() + footer_bytes.size());
  for (uint8_t b : footer_aad) signature.push_back(b ^ kXorKey);
  for (uint8_t b : footer_bytes) signature.push_back(b ^ kXorKey);
  return signature;
}

::arrow::Result<bool> XorBlockCryptoProvider::VerifyFooterSignature(
    std::span<const uint8_t> footer_bytes, std::span<const uint8_t> stored_signature,
    const ParquetCryptoContext& ctx, std::span<const uint8_t> footer_aad,
    std::span<const uint8_t> dek) {
  ARROW_ASSIGN_OR_RAISE(std::vector<uint8_t> recomputed,
                        SignFooter(footer_bytes, ctx, footer_aad, dek));
  return recomputed.size() == stored_signature.size() &&
         std::equal(recomputed.begin(), recomputed.end(), stored_signature.begin());
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

::arrow::Result<std::vector<uint8_t>> XorCellCryptoProvider::SignFooter(
    std::span<const uint8_t> footer_bytes, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> footer_aad, std::span<const uint8_t> dek) {
  std::vector<uint8_t> signature;
  signature.reserve(footer_aad.size() + footer_bytes.size());
  for (uint8_t b : footer_aad) signature.push_back(b ^ kXorKey);
  for (uint8_t b : footer_bytes) signature.push_back(b ^ kXorKey);
  return signature;
}

::arrow::Result<bool> XorCellCryptoProvider::VerifyFooterSignature(
    std::span<const uint8_t> footer_bytes, std::span<const uint8_t> stored_signature,
    const ParquetCryptoContext& ctx, std::span<const uint8_t> footer_aad,
    std::span<const uint8_t> dek) {
  ARROW_ASSIGN_OR_RAISE(std::vector<uint8_t> recomputed,
                        SignFooter(footer_bytes, ctx, footer_aad, dek));
  return recomputed.size() == stored_signature.size() &&
         std::equal(recomputed.begin(), recomputed.end(), stored_signature.begin());
}

namespace {
// XORs the raw bytes of a fixed-width span in place; works for every
// CryptoValueBuffer span alternative regardless of element type, including
// bit-packed BOOLEAN, since XOR is applied at the byte level.
template <typename T>
void XorSpanBytesInPlace(std::span<T> data) {
  auto* bytes = reinterpret_cast<uint8_t*>(data.data());
  size_t num_bytes = data.size() * sizeof(T);
  for (size_t i = 0; i < num_bytes; ++i) {
    bytes[i] ^= kXorKey;
  }
}

// XOR is self-inverse, so the same transform serves both EncryptCells() and
// DecryptCells() regardless of which CryptoValueBuffer alternative is active.
void XorCryptoValueBufferInPlace(CryptoValueBuffer& values) {
  std::visit(
      [](auto&& alt) {
        using T = std::decay_t<decltype(alt)>;
        if constexpr (std::is_same_v<T, std::vector<std::string>>) {
          for (std::string& value : alt) {
            for (char& c : value) {
              c = static_cast<char>(static_cast<uint8_t>(c) ^ kXorKey);
            }
          }
        } else {
          XorSpanBytesInPlace(alt);
        }
      },
      values);
}
}  // namespace

::arrow::Result<std::vector<uint8_t>> XorTypedValuesCryptoProvider::EncryptBlock(
    std::span<const uint8_t> plaintext, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  encrypt_block_calls_.fetch_add(1);
  std::vector<uint8_t> ciphertext(plaintext.size());
  for (size_t i = 0; i < plaintext.size(); ++i) {
    ciphertext[i] = plaintext[i] ^ kXorKey;
  }
  return ciphertext;
}

::arrow::Result<std::vector<uint8_t>> XorTypedValuesCryptoProvider::DecryptBlock(
    std::span<const uint8_t> ciphertext, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  decrypt_block_calls_.fetch_add(1);
  // XOR is self-inverse: decrypting is the same transform as encrypting.
  std::vector<uint8_t> plaintext(ciphertext.size());
  for (size_t i = 0; i < ciphertext.size(); ++i) {
    plaintext[i] = ciphertext[i] ^ kXorKey;
  }
  return plaintext;
}

::arrow::Status XorTypedValuesCryptoProvider::EncryptCells(
    CryptoValueBuffer& values, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> dek) {
  encrypt_cells_calls_.fetch_add(1);
  XorCryptoValueBufferInPlace(values);
  return ::arrow::Status::OK();
}

::arrow::Status XorTypedValuesCryptoProvider::DecryptCells(
    CryptoValueBuffer& values, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> dek) {
  decrypt_cells_calls_.fetch_add(1);
  XorCryptoValueBufferInPlace(values);
  return ::arrow::Status::OK();
}

::arrow::Result<std::vector<uint8_t>> XorTypedValuesCryptoProvider::SignFooter(
    std::span<const uint8_t> footer_bytes, const ParquetCryptoContext& ctx,
    std::span<const uint8_t> footer_aad, std::span<const uint8_t> dek) {
  std::vector<uint8_t> signature;
  signature.reserve(footer_aad.size() + footer_bytes.size());
  for (uint8_t b : footer_aad) signature.push_back(b ^ kXorKey);
  for (uint8_t b : footer_bytes) signature.push_back(b ^ kXorKey);
  return signature;
}

::arrow::Result<bool> XorTypedValuesCryptoProvider::VerifyFooterSignature(
    std::span<const uint8_t> footer_bytes, std::span<const uint8_t> stored_signature,
    const ParquetCryptoContext& ctx, std::span<const uint8_t> footer_aad,
    std::span<const uint8_t> dek) {
  ARROW_ASSIGN_OR_RAISE(std::vector<uint8_t> recomputed,
                        SignFooter(footer_bytes, ctx, footer_aad, dek));
  return recomputed.size() == stored_signature.size() &&
         std::equal(recomputed.begin(), recomputed.end(), stored_signature.begin());
}

}  // namespace parquet::encryption::test
