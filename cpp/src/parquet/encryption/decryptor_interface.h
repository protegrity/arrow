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

#include "parquet/encryption/encoding_properties.h"
#include "parquet/exception.h"
#include "parquet/platform.h"

namespace parquet::encryption {

class PARQUET_EXPORT DecryptorInterface {
 public:
  virtual ~DecryptorInterface() = default;

  /// Signal whether the decryptor can calculate a valid plaintext or ciphertext
  /// length before performing decryption or not. If false, a proper sized buffer
  /// cannot be allocated before calling the Decrypt method, and Arrow must use
  /// this decryptor's DecryptWithManagedBuffer method instead of Decrypt.
  [[nodiscard]] virtual bool CanCalculateLengths() const = 0;

  /// Calculate the size of the plaintext for a given ciphertext length.
  [[nodiscard]] virtual int32_t PlaintextLength(int32_t ciphertext_len) const = 0;

  /// Calculate the size of the ciphertext for a given plaintext length.
  [[nodiscard]] virtual int32_t CiphertextLength(int32_t plaintext_len) const = 0;

  /// Determine how many bytes of `ciphertext` are the real encrypted payload.
  /// Most callers already pass an exactly-sized buffer, for which the entire
  /// buffer is the payload (the default below). Some callers (e.g. a page-header
  /// reader peeking a progressively larger, over-sized buffer before it knows the
  /// header's real extent) need to know the true boundary before treating the
  /// rest of the buffer as unrelated trailing data; implementations that write a
  /// self-describing length prefix (like ParquetCryptoProviderDecryptorAdapter)
  /// override this to read it back.
  [[nodiscard]] virtual int32_t GetCiphertextLength(
      std::span<const uint8_t> ciphertext) const {
    return static_cast<int32_t>(ciphertext.size());
  }

  /// Decrypt the ciphertext and leave the results in the plaintext buffer.
  /// Most implementations will require the key and aad to be provided, but it is up to
  /// each decryptor whether to use them or not.
  virtual int32_t Decrypt(
      std::span<const uint8_t> ciphertext, std::span<const uint8_t> key,
      std::span<const uint8_t> aad, std::span<uint8_t> plaintext,
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr) = 0;

  /// Decrypt the ciphertext and leave the results in the plaintext buffer.
  /// The buffer will be resized to the correct size during decryption. This method
  /// is used when the decryptor cannot calculate the plaintext length before decryption.
  ///
  /// \param ciphertext The bytes to decrypt.
  /// \param plaintext Resized to the actual plaintext length and filled by the
  ///     decryptor.
  /// \param aad The positional binding for this call (e.g. Decryptor::UpdateAad()'s
  ///     CreateModuleAad() result, already updated per-page). Implementations
  ///     without AEAD-style binding may ignore it.
  /// \param dek The key resolved for this call, if any. Implementations that
  ///     already hold their key (e.g. AES, bound at construction) ignore it.
  /// \param encoding_properties Page value/level encoding context, forwarded to
  ///     implementations that need it to decode a self-describing buffer.
  virtual int32_t DecryptWithManagedBuffer(
      std::span<const uint8_t> ciphertext, ::arrow::ResizableBuffer* plaintext,
      std::span<const uint8_t> aad = {}, std::span<const uint8_t> dek = {},
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr) = 0;

  /// Verify a standalone, opaque footer-signature blob produced by
  /// EncryptorInterface::ComputeFooterSignature() (as opposed to recomputing and
  /// comparing SignedFooterEncrypt()'s AES-GCM tag). Default throws; only
  /// implementations that don't use SignedFooterEncrypt() override this.
  virtual bool VerifyFooterSignature(std::span<const uint8_t> footer,
                                     std::span<const uint8_t> stored_signature,
                                     std::span<const uint8_t> footer_aad,
                                     std::span<const uint8_t> dek = {}) {
    throw ParquetException("VerifyFooterSignature is not supported by this decryptor");
  }
};

}  // namespace parquet::encryption
