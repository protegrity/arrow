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

#include <span>
#include <vector>

#include "parquet/encryption/encoding_properties.h"
#include "parquet/exception.h"
#include "parquet/platform.h"

namespace parquet::encryption {

class PARQUET_EXPORT EncryptorInterface {
 public:
  virtual ~EncryptorInterface() = default;

  /// Signal whether the encryptor can calculate a valid ciphertext length
  /// before performing encryption or not. If false, a proper sized buffer cannot
  /// be allocated before calling the Encrypt method, and Arrow must use this
  /// encryptor's EncryptWithManagedBuffer method instead of Encrypt.
  [[nodiscard]] virtual bool CanCalculateCiphertextLength() const = 0;

  /// Calculate the size of the ciphertext for a given plaintext length.
  [[nodiscard]] virtual int32_t CiphertextLength(int64_t plaintext_len) const = 0;

  /// Encrypt the plaintext and leave the results in the ciphertext buffer.
  /// Most implementations will require the key and aad to be provided, but it is
  /// up to each encryptor whether to use them or not.
  virtual int32_t Encrypt(
      std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
      std::span<const uint8_t> aad, std::span<uint8_t> ciphertext,
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr) = 0;

  /// Encrypt the plaintext and leave the results in the ciphertext buffer.
  /// The buffer will be resized to the appropriate size by the encryptor during
  /// encryption. This method is used when the encryptor cannot calculate the
  /// ciphertext length before encryption.
  ///
  /// \param plaintext The bytes to encrypt.
  /// \param ciphertext Resized to the actual ciphertext length and filled by
  ///     the encryptor.
  /// \param aad The positional binding for this call (e.g. Encryptor::UpdateAad()'s
  ///     CreateModuleAad() result, already updated per-page). Implementations
  ///     without AEAD-style binding may ignore it.
  /// \param dek The key resolved for this call, if any. Implementations that
  ///     already hold their key (e.g. AES, bound at construction) ignore it.
  /// \param encoding_properties Page value/level encoding context, forwarded to
  ///     implementations that need it to encode a self-describing buffer.
  /// \param new_uncompressed_size Out-param: if non-null and the implementation's
  ///     output represents different content than what the caller's `plaintext`
  ///     decompresses to (e.g. the cell path changing a value's length), set to
  ///     the new, correct pre-recompression size. Left untouched otherwise;
  ///     callers must not assume it was set.
  virtual int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t> plaintext, ::arrow::ResizableBuffer* ciphertext,
      std::span<const uint8_t> aad = {}, std::span<const uint8_t> dek = {},
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr,
      int64_t* new_uncompressed_size = nullptr) = 0;

  /// Return column-level metadata accumulated during encryption of a single page.
  ///
  /// Called by the column writer after each dictionary or data page write.
  virtual std::shared_ptr<::arrow::KeyValueMetadata> GetKeyValueMetadata(
      int8_t module_type) {
    return nullptr;
  }

  /// Encrypt footer bytes to produce the authentication tag for plaintext-footer files.
  virtual int32_t SignedFooterEncrypt(std::span<const uint8_t> footer,
                                      std::span<const uint8_t> key,
                                      std::span<const uint8_t> aad,
                                      std::span<const uint8_t> nonce,
                                      std::span<uint8_t> encrypted_footer) = 0;

  /// Compute a standalone, opaque footer-signature blob (as opposed to
  /// SignedFooterEncrypt()'s AES-GCM tag-via-encryption mechanism). Default throws;
  /// only implementations that don't use SignedFooterEncrypt() override this.
  virtual std::vector<uint8_t> ComputeFooterSignature(std::span<const uint8_t> footer,
                                                      std::span<const uint8_t> footer_aad,
                                                      std::span<const uint8_t> dek = {}) {
    throw ParquetException("ComputeFooterSignature is not supported by this encryptor");
  }
};

}  // namespace parquet::encryption
