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
#include <mutex>
#include <vector>

#include "parquet/encryption/parquet_crypto_provider.h"

namespace parquet::encryption::test {

// Minimal ParquetCryptoProvider exercising the block path (EncryptBlock/DecryptBlock).
// XORs every byte with a fixed key so Encrypt and Decrypt are the same operation;
// call counters let tests assert which path Arrow actually took.
class XorBlockCryptoProvider : public ParquetCryptoProvider {
 public:
  ::arrow::Result<std::vector<uint8_t>> EncryptBlock(
      std::span<const uint8_t> plaintext, const ParquetCryptoContext& ctx,
      std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) override;

  ::arrow::Result<std::vector<uint8_t>> DecryptBlock(
      std::span<const uint8_t> ciphertext, const ParquetCryptoContext& ctx,
      std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) override;

  [[nodiscard]] bool SupportsTypedValues() const override { return false; }

  // Unreachable: SupportsTypedValues() is always false for this provider.
  ::arrow::Status EncryptCells(CryptoValueBuffer& values, const ParquetCryptoContext& ctx,
                               std::span<const uint8_t> dek) override;

  // Unreachable for the same reason as EncryptCells().
  ::arrow::Status DecryptCells(CryptoValueBuffer& values, const ParquetCryptoContext& ctx,
                               std::span<const uint8_t> dek) override;

  [[nodiscard]] int encrypt_block_calls() const { return encrypt_block_calls_.load(); }
  [[nodiscard]] int decrypt_block_calls() const { return decrypt_block_calls_.load(); }
  [[nodiscard]] int encrypt_cells_calls() const { return encrypt_cells_calls_.load(); }
  [[nodiscard]] int decrypt_cells_calls() const { return decrypt_cells_calls_.load(); }
  // Number of EncryptBlock/DecryptBlock calls seen with a non-empty dek.
  [[nodiscard]] int calls_with_dek() const { return calls_with_dek_.load(); }

  // Every ctx seen by EncryptBlock()/DecryptBlock(), in call order. Lets tests verify
  // that ExternalEncryptionConfiguration values (app_context, per-column key_metadata,
  // module routing) actually reach the provider, not just that a call happened.
  [[nodiscard]] std::vector<ParquetCryptoContext> seen_contexts() const;

  // Every module_aad seen by EncryptBlock()/DecryptBlock(), in the same call order
  // as seen_contexts() (index i of each vector is the same call). Lets tests verify
  // Arrow's per-page positional binding (CreateModuleAad()) reaches the provider.
  [[nodiscard]] std::vector<std::vector<uint8_t>> seen_module_aads() const;

 private:
  void RecordCall(const ParquetCryptoContext& ctx, std::span<const uint8_t> module_aad);

  std::atomic<int> encrypt_block_calls_{0};
  std::atomic<int> decrypt_block_calls_{0};
  std::atomic<int> encrypt_cells_calls_{0};
  std::atomic<int> decrypt_cells_calls_{0};
  std::atomic<int> calls_with_dek_{0};
  mutable std::mutex contexts_mutex_;
  std::vector<ParquetCryptoContext> seen_contexts_;
  std::vector<std::vector<uint8_t>> seen_module_aads_;
};

// Minimal ParquetCryptoProvider exercising the cell path (EncryptCells/DecryptCells).
// XORs each character of every BYTE_ARRAY string value with a fixed key. The cell
// path is not yet reachable through a real file round-trip (ParquetPageDecoder's
// Decompress()/Recompress() are not yet implemented); this class exists now so
// that implementation only needs to add tests, not a new mock provider.
class XorCellCryptoProvider : public ParquetCryptoProvider {
 public:
  // Unreachable: SupportsTypedValues() is always true for this provider.
  ::arrow::Result<std::vector<uint8_t>> EncryptBlock(
      std::span<const uint8_t> plaintext, const ParquetCryptoContext& ctx,
      std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) override;

  // Unreachable for the same reason as EncryptBlock().
  ::arrow::Result<std::vector<uint8_t>> DecryptBlock(
      std::span<const uint8_t> ciphertext, const ParquetCryptoContext& ctx,
      std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) override;

  [[nodiscard]] bool SupportsTypedValues() const override { return true; }

  ::arrow::Status EncryptCells(CryptoValueBuffer& values, const ParquetCryptoContext& ctx,
                               std::span<const uint8_t> dek) override;

  ::arrow::Status DecryptCells(CryptoValueBuffer& values, const ParquetCryptoContext& ctx,
                               std::span<const uint8_t> dek) override;

  [[nodiscard]] int encrypt_cells_calls() const { return encrypt_cells_calls_.load(); }
  [[nodiscard]] int decrypt_cells_calls() const { return decrypt_cells_calls_.load(); }

 private:
  std::atomic<int> encrypt_cells_calls_{0};
  std::atomic<int> decrypt_cells_calls_{0};
};

}  // namespace parquet::encryption::test
