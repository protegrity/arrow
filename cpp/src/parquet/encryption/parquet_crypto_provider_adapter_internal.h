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
#include <span>

#include "parquet/encryption/decryptor_interface.h"
#include "parquet/encryption/encryptor_interface.h"
#include "parquet/encryption/parquet_crypto_provider.h"
#include "parquet/exception.h"
#include "parquet/platform.h"

namespace parquet {

// Arrow-internal bridge from the external-provider-facing ParquetCryptoProvider
// interface to Arrow's page-writer-facing EncryptorInterface. Never exposed to
// provider implementations; created inline by
// InternalFileEncryptor::GetColumnEncryptor() — one instance per column per file
// write, reused across all row groups (see column_data_map_ cache).
class ParquetCryptoProviderEncryptorAdapter : public encryption::EncryptorInterface {
 public:
  // dispatch_module_type is one of parquet::encryption's module-type constants
  // (encryption_utils.h) — the same values CreateModuleAad()/GetKeyValueMetadata()
  // already use. Fixed once for this adapter's lifetime (one instance per column or
  // footer); used only to gate UseCellPath().
  ParquetCryptoProviderEncryptorAdapter(std::shared_ptr<ParquetCryptoProvider> provider,
                                        ParquetCryptoContext ctx,
                                        int8_t dispatch_module_type);

  // Always false: every call is routed through EncryptWithManagedBuffer(), which
  // lets the provider return an arbitrarily-sized owned buffer (block path) or the
  // recompressed page (cell path) without Arrow pre-sizing anything.
  [[nodiscard]] bool CanCalculateCiphertextLength() const override { return false; }

  // Unreachable: Arrow only calls this pre-allocated-buffer path when
  // CanCalculateCiphertextLength()==true, which this adapter never returns.
  [[nodiscard]] int32_t CiphertextLength(int64_t plaintext_len) const override {
    throw ParquetException(
        "ParquetCryptoProviderEncryptorAdapter::CiphertextLength is unreachable: "
        "CanCalculateCiphertextLength() always returns false");
  }

  // Unreachable for the same reason as CiphertextLength().
  int32_t Encrypt(std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
                  std::span<const uint8_t> aad, std::span<uint8_t> ciphertext,
                  std::unique_ptr<encryption::EncodingProperties> encoding_properties =
                      nullptr) override {
    throw ParquetException(
        "ParquetCryptoProviderEncryptorAdapter::Encrypt is unreachable: Arrow only calls "
        "the "
        "pre-allocated-buffer path when CanCalculateCiphertextLength() is true");
  }

  // The real entry point. Routes to the block or cell path based on
  // dispatch_module_type_ and provider_->SupportsTypedValues() — never on
  // SupportsTypedValues() alone, since footer/column-metadata/index/bloom-filter
  // modules must always go through the block path regardless of that flag. `aad` is
  // the module AAD Encryptor::UpdateAad() already computed via CreateModuleAad();
  // `dek` is the column's or footer's resolved key. Both are forwarded straight
  // through to the block path; the cell path forwards only `dek`.
  int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t> plaintext, ::arrow::ResizableBuffer* ciphertext,
      std::span<const uint8_t> aad = {}, std::span<const uint8_t> dek = {},
      std::unique_ptr<encryption::EncodingProperties> encoding_properties = nullptr)
      override;

  // Footer signing is not yet routed to the provider (future extension); unreachable
  // until that lands.
  int32_t SignedFooterEncrypt(std::span<const uint8_t> footer,
                              std::span<const uint8_t> key, std::span<const uint8_t> aad,
                              std::span<const uint8_t> nonce,
                              std::span<uint8_t> encrypted_footer) override;

 private:
  // True only when dispatch_module_type_ is kDataPage/kDictionaryPage and the
  // provider supports typed values. Footer/column-metadata adapters always use the
  // block path, regardless of SupportsTypedValues().
  [[nodiscard]] bool UseCellPath() const;

  std::shared_ptr<ParquetCryptoProvider> provider_;
  ParquetCryptoContext ctx_;
  int8_t dispatch_module_type_;
};

// Arrow-internal bridge from the external-provider-facing ParquetCryptoProvider
// interface to Arrow's page-reader-facing DecryptorInterface. Never exposed to
// provider implementations; created inline by InternalFileDecryptor's
// footer/column-metadata/data-page dispatch — one instance per call (no shared
// cache, unlike the AES path's key-size-keyed cache, since ParquetCryptoContext is
// per-column/footer and not content-addressable).
class ParquetCryptoProviderDecryptorAdapter : public encryption::DecryptorInterface {
 public:
  // See ParquetCryptoProviderEncryptorAdapter's constructor comment for what
  // dispatch_module_type is used for.
  ParquetCryptoProviderDecryptorAdapter(std::shared_ptr<ParquetCryptoProvider> provider,
                                        ParquetCryptoContext ctx,
                                        int8_t dispatch_module_type);

  // Always false: every call is routed through DecryptWithManagedBuffer(), which
  // lets the provider return an arbitrarily-sized owned buffer (block path) or the
  // recompressed page (cell path) without Arrow pre-sizing anything.
  [[nodiscard]] bool CanCalculateLengths() const override { return false; }

  // Unreachable: Arrow only calls this pre-allocated-buffer path when
  // CanCalculateLengths()==true, which this adapter never returns.
  [[nodiscard]] int32_t PlaintextLength(int32_t ciphertext_len) const override {
    throw ParquetException(
        "ParquetCryptoProviderDecryptorAdapter::PlaintextLength is unreachable: "
        "CanCalculateLengths() always returns false");
  }

  // Unreachable for the same reason as PlaintextLength().
  [[nodiscard]] int32_t CiphertextLength(int32_t plaintext_len) const override {
    throw ParquetException(
        "ParquetCryptoProviderDecryptorAdapter::CiphertextLength is unreachable: "
        "CanCalculateLengths() always returns false");
  }

  // Unreachable for the same reason as PlaintextLength().
  int32_t Decrypt(std::span<const uint8_t> ciphertext, std::span<const uint8_t> key,
                  std::span<const uint8_t> aad, std::span<uint8_t> plaintext,
                  std::unique_ptr<encryption::EncodingProperties> encoding_properties =
                      nullptr) override {
    throw ParquetException(
        "ParquetCryptoProviderDecryptorAdapter::Decrypt is unreachable: Arrow only "
        "calls the pre-allocated-buffer path when CanCalculateLengths() is true");
  }

  // The real entry point. Routes to the block or cell path based on
  // dispatch_module_type_ and provider_->SupportsTypedValues() (mirrors
  // ParquetCryptoProviderEncryptorAdapter::EncryptWithManagedBuffer()'s gating rule).
  // `aad` is the module AAD Decryptor::UpdateAad() already computed; `dek` is the
  // column's or footer's resolved key. Both are forwarded straight through to the block
  // path; the cell path forwards only `dek`.
  int32_t DecryptWithManagedBuffer(
      std::span<const uint8_t> ciphertext, ::arrow::ResizableBuffer* plaintext,
      std::span<const uint8_t> aad = {}, std::span<const uint8_t> dek = {},
      std::unique_ptr<encryption::EncodingProperties> encoding_properties = nullptr)
      override;

 private:
  // Reads the 4-byte little-endian length prefix EncryptWithManagedBuffer() wrote
  // (mirrors AesDecryptor::GetCiphertextLength()'s existing convention and access
  // level) so a caller peeking an over-sized, not-yet-delimited buffer (e.g.
  // SerializedPageReader::NextPage()'s growing page-header peek) can learn
  // exactly how many bytes are the real payload before advancing its stream
  // cursor. Callers that already pass an exactly-sized buffer (column metadata,
  // footer, column/offset index, bloom filter header) get back `ciphertext.size()`.
  // Private like AesDecryptor's own override: every real caller reaches this only
  // through the base DecryptorInterface*/Decryptor wrapper, never this concrete type.
  [[nodiscard]] int32_t GetCiphertextLength(
      std::span<const uint8_t> ciphertext) const override;

  // True only when dispatch_module_type_ is kDataPage/kDictionaryPage and the
  // provider supports typed values. Footer/column-metadata adapters always use the
  // block path, regardless of SupportsTypedValues().
  [[nodiscard]] bool UseCellPath() const;
  std::shared_ptr<ParquetCryptoProvider> provider_;

  ParquetCryptoContext ctx_;
  int8_t dispatch_module_type_;
};

}  // namespace parquet
