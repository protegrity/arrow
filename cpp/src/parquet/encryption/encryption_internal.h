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
#include <string>
#include <unordered_map>

#include "parquet/encryption/decryptor_interface.h"
#include "parquet/encryption/encryptor_interface.h"
#include "parquet/exception.h"
#include "parquet/types.h"

using parquet::ParquetCipher;

namespace parquet::encryption {

constexpr int32_t kGcmTagLength = 16;
constexpr int32_t kNonceLength = 12;

// Module types
constexpr int8_t kFooter = 0;
constexpr int8_t kColumnMetaData = 1;
constexpr int8_t kDataPage = 2;
constexpr int8_t kDictionaryPage = 3;
constexpr int8_t kDataPageHeader = 4;
constexpr int8_t kDictionaryPageHeader = 5;
constexpr int8_t kColumnIndex = 6;
constexpr int8_t kOffsetIndex = 7;
constexpr int8_t kBloomFilterHeader = 8;
constexpr int8_t kBloomFilterBitset = 9;

/// Performs AES encryption operations with GCM or CTR ciphers.
class PARQUET_EXPORT AesEncryptor : public EncryptorInterface {
 public:
  /// Can serve one key length only. Possible values: 16, 24, 32 bytes.
  /// If write_length is true, prepend ciphertext length to the ciphertext
  explicit AesEncryptor(ParquetCipher::type alg_id, int32_t key_len, bool metadata,
                        bool write_length = true);

  static std::unique_ptr<AesEncryptor> Make(ParquetCipher::type alg_id, int32_t key_len,
                                            bool metadata, bool write_length = true);

  ~AesEncryptor();

  /// Signal whether the encryptor can calculate a valid ciphertext length
  /// before performing encryption.
  [[nodiscard]] bool CanCalculateCiphertextLength() const override { return true; }

  /// The size of the ciphertext, for this cipher and the specified plaintext length.
  [[nodiscard]] int32_t CiphertextLength(int64_t plaintext_len) const override;

  /// Encrypts plaintext with the key and aad. Key length is passed only for validation.
  /// If different from value in constructor, exception will be thrown.
  int32_t Encrypt(std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
                  std::span<const uint8_t> aad, std::span<uint8_t> ciphertext) override;

  /// Encrypt the plaintext and leave the results in the ciphertext buffer. This method is
  /// not supported as we can calculate the ciphertext length before encryption.
  int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t> plaintext, ::arrow::ResizableBuffer* ciphertext,
      std::span<const uint8_t> aad = {}, std::span<const uint8_t> dek = {},
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr,
      int64_t* new_uncompressed_size = nullptr,
      ::arrow::util::Codec* codec = nullptr) override {
    throw ParquetException(
        "EncryptWithManagedBuffer is not supported in AesEncryptor, use Encrypt instead");
  }

  /// Encrypts plaintext footer, in order to compute footer signature (tag).
  int32_t SignedFooterEncrypt(std::span<const uint8_t> footer,
                              std::span<const uint8_t> key, std::span<const uint8_t> aad,
                              std::span<const uint8_t> nonce,
                              std::span<uint8_t> encrypted_footer) override;

 private:
  // PIMPL Idiom
  class AesEncryptorImpl;
  std::unique_ptr<AesEncryptorImpl> impl_;
};

/// Caches AesEncryptor instances so that columns with the same algorithm, key length
/// and metadata flag share one. The key length is one of 16, 24 or 32 bytes.
class AesEncryptorFactory {
 public:
  AesEncryptor* GetMetaAesEncryptor(ParquetCipher::type alg_id, size_t key_size);
  AesEncryptor* GetDataAesEncryptor(ParquetCipher::type alg_id, size_t key_size);

 private:
  /// Build a cache key including algorithm id, key length, and metadata flag.
  static uint64_t MakeCacheKey(ParquetCipher::type alg_id, int32_t key_len,
                               bool metadata);

  std::unordered_map<uint64_t, std::unique_ptr<AesEncryptor>> encryptor_cache_;
};

/// Performs AES decryption operations with GCM or CTR ciphers.
class PARQUET_EXPORT AesDecryptor : public DecryptorInterface {
 public:
  /// \brief Construct an AesDecryptor
  ///
  /// \param alg_id the encryption algorithm to use
  /// \param key_len key length. Possible values: 16, 24, 32 bytes.
  /// \param metadata if true then this is a metadata decryptor
  /// \param contains_length if true, expect ciphertext length prepended to the ciphertext
  explicit AesDecryptor(ParquetCipher::type alg_id, int32_t key_len, bool metadata,
                        bool contains_length = true);

  static std::unique_ptr<AesDecryptor> Make(ParquetCipher::type alg_id, int32_t key_len,
                                            bool metadata);

  ~AesDecryptor();

  /// Signal whether the decryptor can calculate a valid plaintext or ciphertext
  /// length before performing decryption or not. If false, a proper sized buffer
  /// cannot be allocated before calling the Decrypt method, and Arrow must use
  /// this decryptor's DecryptWithManagedBuffer method instead of Decrypt.
  [[nodiscard]] bool CanCalculateLengths() const override { return true; }

  /// The size of the plaintext, for this cipher and the specified ciphertext length.
  [[nodiscard]] int32_t PlaintextLength(int32_t ciphertext_len) const override;

  /// The size of the ciphertext, for this cipher and the specified plaintext length.
  [[nodiscard]] int32_t CiphertextLength(int32_t plaintext_len) const override;

  /// Decrypts ciphertext with the key and aad. Key length is passed only for
  /// validation. If different from value in constructor, exception will be thrown.
  /// The caller is responsible for ensuring that the plaintext buffer is at least as
  /// large as PlaintextLength(ciphertext_len).
  int32_t Decrypt(std::span<const uint8_t> ciphertext, std::span<const uint8_t> key,
                  std::span<const uint8_t> aad, std::span<uint8_t> plaintext) override;

  /// Decrypt the ciphertext and leave the results in the plaintext buffer. This
  /// method is not supported as we can calculate the plaintext length before
  /// decryption.
  int32_t DecryptWithManagedBuffer(
      std::span<const uint8_t> ciphertext, ::arrow::ResizableBuffer* plaintext,
      std::span<const uint8_t> aad = {}, std::span<const uint8_t> dek = {},
      std::unique_ptr<EncodingProperties> encoding_properties = nullptr,
      int64_t* new_uncompressed_size = nullptr,
      ::arrow::util::Codec* codec = nullptr) override {
    throw ParquetException(
        "DecryptWithManagedBuffer is not supported in AesDecryptor, use Decrypt instead");
  }

 private:
  // Get the actual ciphertext length, inclusive of the length buffer length,
  // and validate that the provided buffer size is large enough.
  [[nodiscard]] int32_t GetCiphertextLength(
      std::span<const uint8_t> ciphertext) const override;

  // PIMPL Idiom
  class AesDecryptorImpl;
  std::unique_ptr<AesDecryptorImpl> impl_;
};

std::string CreateModuleAad(const std::string& file_aad, int8_t module_type,
                            int16_t row_group_ordinal, int16_t column_ordinal,
                            int32_t page_ordinal);

std::string CreateFooterAad(const std::string& aad_prefix_bytes);

// Update last two bytes of page (or page header) module AAD
void QuickUpdatePageAad(int32_t new_page_ordinal, std::string* AAD);

// Wraps OpenSSL RAND_bytes function
void RandBytes(unsigned char* buf, size_t num);

// Ensure OpenSSL is initialized.
//
// This is only necessary in specific situations since OpenSSL otherwise
// initializes itself automatically. For example, under Valgrind, a memory
// leak will be reported if OpenSSL is initialized for the first time from
// a worker thread; calling this function from the main thread prevents this.
void EnsureBackendInitialized();

}  // namespace parquet::encryption
