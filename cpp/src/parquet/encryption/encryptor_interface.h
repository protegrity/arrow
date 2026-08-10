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
  virtual int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t> plaintext, ::arrow::ResizableBuffer* ciphertext,
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr) = 0;

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
};

}  // namespace parquet::encryption
