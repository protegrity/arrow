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

#include "parquet/encryption/encryption_internal.h"

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "parquet/encryption/openssl_internal.h"
#include "parquet/exception.h"
#include "parquet/encryption/external/loadable_encryptor_utils.h"
#include "parquet/encryption/external/dbpa_utils.h"
#include "parquet/types.h"

using ::arrow::util::span;
using parquet::ParquetException;
using parquet::encryption::external::LoadableEncryptorUtils;
using parquet::encryption::external::dbpa_utils;

using dbps::external::EncryptionResult;
using dbps::external::DecryptionResult;
using dbps::external::DataBatchProtectionAgentInterface;

namespace parquet::encryption {

// Forward declarations for utility functions
std::string HackTypeToString(Type::type t);
std::string CompressName(Compression::type codec);

#define ENCRYPT_INIT(CTX, ALG)                                        \
  if (1 != EVP_EncryptInit_ex(CTX, ALG, nullptr, nullptr, nullptr)) { \
    throw ParquetException("Couldn't init ALG encryption");           \
  }

#define DECRYPT_INIT(CTX, ALG)                                        \
  if (1 != EVP_DecryptInit_ex(CTX, ALG, nullptr, nullptr, nullptr)) { \
    throw ParquetException("Couldn't init ALG decryption");           \
  }

AesEncryptorImpl::AesEncryptorImpl(ParquetCipher::type alg_id, int32_t key_len,
                                   bool metadata, bool write_length)
    : AesCryptoContext(alg_id, key_len, metadata, write_length) {}

AesCryptoContext::CipherContext AesEncryptorImpl::MakeCipherContext() const {
  auto ctx = NewCipherContext();
  if (kGcmMode == aes_mode_) {
    // Init AES-GCM with specified key length
    if (16 == key_length_) {
      ENCRYPT_INIT(ctx.get(), EVP_aes_128_gcm());
    } else if (24 == key_length_) {
      ENCRYPT_INIT(ctx.get(), EVP_aes_192_gcm());
    } else if (32 == key_length_) {
      ENCRYPT_INIT(ctx.get(), EVP_aes_256_gcm());
    }
  } else {
    // Init AES-CTR with specified key length
    if (16 == key_length_) {
      ENCRYPT_INIT(ctx.get(), EVP_aes_128_ctr());
    } else if (24 == key_length_) {
      ENCRYPT_INIT(ctx.get(), EVP_aes_192_ctr());
    } else if (32 == key_length_) {
      ENCRYPT_INIT(ctx.get(), EVP_aes_256_ctr());
    }
  }
  return ctx;
}

std::unique_ptr<AesEncryptorImpl> AesEncryptorImpl::Make(ParquetCipher::type alg_id, 
                                                         int32_t key_len, bool metadata,
                                                         bool write_length) {
    return std::make_unique<AesEncryptorImpl>(alg_id, key_len, metadata, write_length);
}

int32_t AesEncryptorImpl::SignedFooterEncrypt(span<const uint8_t> footer, span<const uint8_t> key,
                                              span<const uint8_t> aad, span<const uint8_t> nonce,
                                              span<uint8_t> encrypted_footer) {
  if (static_cast<size_t>(key_length_) != key.size()) {
    std::stringstream ss;
    ss << "Wrong key length " << key.size() << ". Should be " << key_length_;
    throw ParquetException(ss.str());
  }

  if (encrypted_footer.size() != footer.size() + ciphertext_size_delta_) {
    std::stringstream ss;
    ss << "Encrypted footer buffer length " << encrypted_footer.size()
       << " does not match expected length " << (footer.size() + ciphertext_size_delta_);
    throw ParquetException(ss.str());
  }

  if (kGcmMode != aes_mode_) {
    throw ParquetException("Must use AES GCM (metadata) encryptor");
  }

  return GcmEncrypt(footer, key, nonce, aad, encrypted_footer);
}

int32_t AesEncryptorImpl::Encrypt(span<const uint8_t> plaintext, span<const uint8_t> key,
                                  span<const uint8_t> aad, span<uint8_t> ciphertext) {
  if (static_cast<size_t>(key_length_) != key.size()) {
    std::stringstream ss;
    ss << "Wrong key length " << key.size() << ". Should be " << key_length_;
    throw ParquetException(ss.str());
  }

  if (ciphertext.size() != plaintext.size() + ciphertext_size_delta_) {
    std::stringstream ss;
    ss << "Ciphertext buffer length " << ciphertext.size()
       << " does not match expected length "
       << (plaintext.size() + ciphertext_size_delta_);
    throw ParquetException(ss.str());
  }

  std::array<uint8_t, kNonceLength> nonce{};
  // Random nonce
  RAND_bytes(nonce.data(), kNonceLength);

  if (kGcmMode == aes_mode_) {
    return GcmEncrypt(plaintext, key, nonce, aad, ciphertext);
  }

  return CtrEncrypt(plaintext, key, nonce, ciphertext);
}

int32_t AesEncryptorImpl::GcmEncrypt(span<const uint8_t> plaintext, span<const uint8_t> key, 
                                     span<const uint8_t> nonce, span<const uint8_t> aad,
                                     span<uint8_t> ciphertext) {
  int len;
  int32_t ciphertext_len;

  std::array<uint8_t, kGcmTagLength> tag{};

  if (nonce.size() != static_cast<size_t>(kNonceLength)) {
    std::stringstream ss;
    ss << "Invalid nonce size " << nonce.size() << ", expected " << kNonceLength;
    throw ParquetException(ss.str());
  }

  auto ctx = MakeCipherContext();

  // Setting key and IV (nonce)
  if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data())) {
    throw ParquetException("Couldn't set key and nonce");
  }

  // Setting additional authenticated data
  if (aad.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    std::stringstream ss;
    ss << "AAD size " << aad.size() << " overflows int";
    throw ParquetException(ss.str());
  }
  if ((!aad.empty()) && (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                                static_cast<int>(aad.size())))) {
    throw ParquetException("Couldn't set AAD");
  }

  // Encryption
  if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    std::stringstream ss;
    ss << "Plaintext size " << plaintext.size() << " overflows int";
    throw ParquetException(ss.str());
  }
  if (1 != EVP_EncryptUpdate(
               ctx.get(), ciphertext.data() + length_buffer_length_ + kNonceLength, &len,
               plaintext.data(), static_cast<int>(plaintext.size()))) {
    throw ParquetException("Failed encryption update");
  }

  ciphertext_len = len;

  // Finalization
  if (1 != EVP_EncryptFinal_ex(
               ctx.get(), ciphertext.data() + length_buffer_length_ + kNonceLength + len,
               &len)) {
    throw ParquetException("Failed encryption finalization");
  }

  ciphertext_len += len;

  // Getting the tag
  if (1 !=
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagLength, tag.data())) {
    throw ParquetException("Couldn't get AES-GCM tag");
  }

  // Copying the buffer size, nonce and tag to ciphertext
  int32_t buffer_size = kNonceLength + ciphertext_len + kGcmTagLength;
  if (length_buffer_length_ > 0) {
    ciphertext[3] = static_cast<uint8_t>(0xff & (buffer_size >> 24));
    ciphertext[2] = static_cast<uint8_t>(0xff & (buffer_size >> 16));
    ciphertext[1] = static_cast<uint8_t>(0xff & (buffer_size >> 8));
    ciphertext[0] = static_cast<uint8_t>(0xff & (buffer_size));
  }
  std::copy(nonce.begin(), nonce.begin() + kNonceLength,
            ciphertext.begin() + length_buffer_length_);
  std::copy(tag.begin(), tag.end(),
            ciphertext.begin() + length_buffer_length_ + kNonceLength + ciphertext_len);

  return length_buffer_length_ + buffer_size;
}

int32_t AesEncryptorImpl::CtrEncrypt(span<const uint8_t> plaintext, span<const uint8_t> key,
                                     span<const uint8_t> nonce, span<uint8_t> ciphertext) {
  int len;
  int32_t ciphertext_len;

  if (nonce.size() != static_cast<size_t>(kNonceLength)) {
    std::stringstream ss;
    ss << "Invalid nonce size " << nonce.size() << ", expected " << kNonceLength;
    throw ParquetException(ss.str());
  }

  // Parquet CTR IVs are comprised of a 12-byte nonce and a 4-byte initial
  // counter field.
  // The first 31 bits of the initial counter field are set to 0, the last bit
  // is set to 1.
  std::array<uint8_t, kCtrIvLength> iv{};
  std::copy(nonce.begin(), nonce.begin() + kNonceLength, iv.begin());
  iv[kCtrIvLength - 1] = 1;

  auto ctx = MakeCipherContext();

  // Setting key and IV
  if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data())) {
    throw ParquetException("Couldn't set key and IV");
  }

  // Encryption
  if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    std::stringstream ss;
    ss << "Plaintext size " << plaintext.size() << " overflows int";
    throw ParquetException(ss.str());
  }
  if (1 != EVP_EncryptUpdate(
               ctx.get(), ciphertext.data() + length_buffer_length_ + kNonceLength, &len,
               plaintext.data(), static_cast<int>(plaintext.size()))) {
    throw ParquetException("Failed encryption update");
  }

  ciphertext_len = len;

  // Finalization
  if (1 != EVP_EncryptFinal_ex(
               ctx.get(), ciphertext.data() + length_buffer_length_ + kNonceLength + len,
               &len)) {
    throw ParquetException("Failed encryption finalization");
  }

  ciphertext_len += len;

  // Copying the buffer size and nonce to ciphertext
  int32_t buffer_size = kNonceLength + ciphertext_len;
  if (length_buffer_length_ > 0) {
    ciphertext[3] = static_cast<uint8_t>(0xff & (buffer_size >> 24));
    ciphertext[2] = static_cast<uint8_t>(0xff & (buffer_size >> 16));
    ciphertext[1] = static_cast<uint8_t>(0xff & (buffer_size >> 8));
    ciphertext[0] = static_cast<uint8_t>(0xff & (buffer_size));
  }
  std::copy(nonce.begin(), nonce.begin() + kNonceLength,
            ciphertext.begin() + length_buffer_length_);

  return length_buffer_length_ + buffer_size;
}

AesDecryptorImpl::AesDecryptorImpl(ParquetCipher::type alg_id, int32_t key_len, bool metadata,
                                   bool contains_length)
    : AesCryptoContext(alg_id, key_len, metadata, contains_length) {
}

AesCryptoContext::CipherContext AesDecryptorImpl::MakeCipherContext()
    const {
  auto ctx = NewCipherContext();
  if (kGcmMode == aes_mode_) {
    // Init AES-GCM with specified key length
    if (16 == key_length_) {
      DECRYPT_INIT(ctx.get(), EVP_aes_128_gcm());
    } else if (24 == key_length_) {
      DECRYPT_INIT(ctx.get(), EVP_aes_192_gcm());
    } else if (32 == key_length_) {
      DECRYPT_INIT(ctx.get(), EVP_aes_256_gcm());
    }
  } else {
    // Init AES-CTR with specified key length
    if (16 == key_length_) {
      DECRYPT_INIT(ctx.get(), EVP_aes_128_ctr());
    } else if (24 == key_length_) {
      DECRYPT_INIT(ctx.get(), EVP_aes_192_ctr());
    } else if (32 == key_length_) {
      DECRYPT_INIT(ctx.get(), EVP_aes_256_ctr());
    }
  }
  return ctx;
}

std::unique_ptr<AesDecryptorImpl> AesDecryptorImpl::Make(ParquetCipher::type alg_id,
                                                         int32_t key_len, bool metadata) {
  return std::make_unique<AesDecryptorImpl>(alg_id, key_len, metadata);
}

int32_t AesDecryptorImpl::GetCiphertextLength(span<const uint8_t> ciphertext) const {
  if (length_buffer_length_ > 0) {
    // Note: length_buffer_length_ must be either 0 or kBufferSizeLength
    if (ciphertext.size() < static_cast<size_t>(kBufferSizeLength)) {
      std::stringstream ss;
      ss << "Ciphertext buffer length " << ciphertext.size()
         << " is insufficient to read the ciphertext length."
         << " At least " << kBufferSizeLength << " bytes are required.";
      throw ParquetException(ss.str());
    }

    // Extract ciphertext length
    uint32_t written_ciphertext_len = (static_cast<uint32_t>(ciphertext[3]) << 24) |
                                      (static_cast<uint32_t>(ciphertext[2]) << 16) |
                                      (static_cast<uint32_t>(ciphertext[1]) << 8) |
                                      (static_cast<uint32_t>(ciphertext[0]));

    if (written_ciphertext_len >
        static_cast<uint32_t>(std::numeric_limits<int32_t>::max() -
                              length_buffer_length_)) {
      std::stringstream ss;
      ss << "Written ciphertext length " << written_ciphertext_len
         << " plus length buffer length " << length_buffer_length_ << " overflows int32";
      throw ParquetException(ss.str());
    } else if (ciphertext.size() <
               static_cast<size_t>(written_ciphertext_len) + length_buffer_length_) {
      std::stringstream ss;
      ss << "Serialized ciphertext length "
         << (written_ciphertext_len + length_buffer_length_)
         << " is greater than the provided ciphertext buffer length "
         << ciphertext.size();
      throw ParquetException(ss.str());
    }

    return static_cast<int32_t>(written_ciphertext_len) + length_buffer_length_;
  } else {
    if (ciphertext.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
      std::stringstream ss;
      ss << "Ciphertext buffer length " << ciphertext.size() << " overflows int32";
      throw ParquetException(ss.str());
    }
    return static_cast<int32_t>(ciphertext.size());
  }
}

int32_t AesDecryptorImpl::GcmDecrypt(span<const uint8_t> ciphertext, span<const uint8_t> key,
                                     span<const uint8_t> aad, span<uint8_t> plaintext) {
                                      
std::cout << "GcmDecrypt: ciphertext_len=" << ciphertext.size() << std::endl;
std::cout << "GcmDecrypt: plaintext.size()=" << plaintext.size() << std::endl;
std::cout << "GcmDecrypt: ciphertext_size_delta_=" << ciphertext_size_delta_ << std::endl;
std::cout << "GcmDecrypt: length_buffer_length_=" << length_buffer_length_ << std::endl;
  int len;
  int32_t plaintext_len;

  std::array<uint8_t, kGcmTagLength> tag{};
  std::array<uint8_t, kNonceLength> nonce{};

  int32_t ciphertext_len = GetCiphertextLength(ciphertext);

  if (plaintext.size() < static_cast<size_t>(ciphertext_len) - ciphertext_size_delta_) {
    std::stringstream ss;
    ss << "Plaintext buffer length " << plaintext.size() << " is insufficient "
       << "for ciphertext length " << ciphertext_len;
    throw ParquetException(ss.str());
  }

  if (ciphertext_len < length_buffer_length_ + kNonceLength + kGcmTagLength) {
    std::stringstream ss;
    ss << "Invalid ciphertext length " << ciphertext_len << ". Expected at least "
       << length_buffer_length_ + kNonceLength + kGcmTagLength << "\n";
    throw ParquetException(ss.str());
  }

  // Extracting IV and tag
  std::copy(ciphertext.begin() + length_buffer_length_,
            ciphertext.begin() + length_buffer_length_ + kNonceLength, nonce.begin());
  std::copy(ciphertext.begin() + ciphertext_len - kGcmTagLength,
            ciphertext.begin() + ciphertext_len, tag.begin());

  auto ctx = MakeCipherContext();

  // Setting key and IV
  if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data())) {
    throw ParquetException("Couldn't set key and IV");
  }

  // Setting additional authenticated data
  if (aad.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    std::stringstream ss;
    ss << "AAD size " << aad.size() << " overflows int";
    throw ParquetException(ss.str());
  }
  if ((!aad.empty()) && (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                                static_cast<int>(aad.size())))) {
    throw ParquetException("Couldn't set AAD");
  }

  // Decryption
  int decryption_length =
      ciphertext_len - length_buffer_length_ - kNonceLength - kGcmTagLength;

  if (!EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         ciphertext.data() + length_buffer_length_ + kNonceLength,
                         decryption_length)) {
    throw ParquetException("Failed decryption update");
  }

  plaintext_len = len;

  // Checking the tag (authentication)
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagLength, tag.data())) {
    throw ParquetException("Failed authentication");
  }

  EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
  // Finalization
  /*if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) {
    throw ParquetException("why would you do empty here??");
  }*/

  plaintext_len += len;
  return plaintext_len;
}

int32_t AesDecryptorImpl::CtrDecrypt(span<const uint8_t> ciphertext, span<const uint8_t> key,
                                     span<uint8_t> plaintext) {
  int len;
  int32_t plaintext_len;

  std::array<uint8_t, kCtrIvLength> iv{};

  int32_t ciphertext_len = GetCiphertextLength(ciphertext);

  if (plaintext.size() < static_cast<size_t>(ciphertext_len) - ciphertext_size_delta_) {
    std::stringstream ss;
    ss << "Plaintext buffer length " << plaintext.size() << " is insufficient "
       << "for ciphertext length " << ciphertext_len;
    throw ParquetException(ss.str());
  }

  if (ciphertext_len < length_buffer_length_ + kNonceLength) {
    std::stringstream ss;
    ss << "Invalid ciphertext length " << ciphertext_len << ". Expected at least "
       << length_buffer_length_ + kNonceLength << "\n";
    throw ParquetException(ss.str());
  }

  // Extracting nonce
  std::copy(ciphertext.begin() + length_buffer_length_,
            ciphertext.begin() + length_buffer_length_ + kNonceLength, iv.begin());
  // Parquet CTR IVs are comprised of a 12-byte nonce and a 4-byte initial
  // counter field.
  // The first 31 bits of the initial counter field are set to 0, the last bit
  // is set to 1.
  iv[kCtrIvLength - 1] = 1;

  auto ctx = MakeCipherContext();

  // Setting key and IV
  if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data())) {
    throw ParquetException("Couldn't set key and IV");
  }

  // Decryption
  int decryption_length = ciphertext_len - length_buffer_length_ - kNonceLength;
  if (!EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         ciphertext.data() + length_buffer_length_ + kNonceLength,
                         decryption_length)) {
    throw ParquetException("Failed decryption update");
  }

  plaintext_len = len;

  // Finalization
  if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) {
    throw ParquetException("Failed decryption finalization");
  }

  plaintext_len += len;
  return plaintext_len;
}

int32_t AesDecryptorImpl::Decrypt(span<const uint8_t> ciphertext, span<const uint8_t> key,
                                  span<const uint8_t> aad, span<uint8_t> plaintext) {
  if (static_cast<size_t>(key_length_) != key.size()) {
    std::stringstream ss;
    ss << "Wrong key length " << key.size() << ". Should be " << key_length_;
    throw ParquetException(ss.str());
  }

  if (kGcmMode == aes_mode_) {
    std::cout << "GcmDecrypt called" << std::endl;
    return GcmDecrypt(ciphertext, key, aad, plaintext);
  }

  std::cout << "CtrDecrypt called" << std::endl;
  return CtrDecrypt(ciphertext, key, plaintext);
}

static std::string ShortToBytesLe(int16_t input) {
  int8_t output[2];
  memset(output, 0, 2);
  output[1] = static_cast<int8_t>(0xff & (input >> 8));
  output[0] = static_cast<int8_t>(0xff & (input));

  return std::string(reinterpret_cast<char const*>(output), 2);
}

static void CheckPageOrdinal(int32_t page_ordinal) {
  if (ARROW_PREDICT_FALSE(page_ordinal > std::numeric_limits<int16_t>::max())) {
    throw ParquetException("Encrypted Parquet files can't have more than " +
                           std::to_string(std::numeric_limits<int16_t>::max()) +
                           " pages per chunk: got " + std::to_string(page_ordinal));
  }
}

std::string CreateModuleAad(const std::string& file_aad, int8_t module_type,
                            int16_t row_group_ordinal, int16_t column_ordinal,
                            int32_t page_ordinal) {
  CheckPageOrdinal(page_ordinal);
  const int16_t page_ordinal_short = static_cast<int16_t>(page_ordinal);
  int8_t type_ordinal_bytes[1];
  type_ordinal_bytes[0] = module_type;
  std::string type_ordinal_bytes_str(reinterpret_cast<char const*>(type_ordinal_bytes),
                                     1);
  if (kFooter == module_type) {
    std::string result = file_aad + type_ordinal_bytes_str;
    return result;
  }
  std::string row_group_ordinal_bytes = ShortToBytesLe(row_group_ordinal);
  std::string column_ordinal_bytes = ShortToBytesLe(column_ordinal);
  if (kDataPage != module_type && kDataPageHeader != module_type) {
    std::ostringstream out;
    out << file_aad << type_ordinal_bytes_str << row_group_ordinal_bytes
        << column_ordinal_bytes;
    return out.str();
  }
  std::string page_ordinal_bytes = ShortToBytesLe(page_ordinal_short);
  std::ostringstream out;
  out << file_aad << type_ordinal_bytes_str << row_group_ordinal_bytes
      << column_ordinal_bytes << page_ordinal_bytes;
  return out.str();
}

std::string CreateFooterAad(const std::string& aad_prefix_bytes) {
  return CreateModuleAad(aad_prefix_bytes, kFooter, static_cast<int16_t>(-1),
                         static_cast<int16_t>(-1), static_cast<int16_t>(-1));
}

// Update last two bytes with new page ordinal (instead of creating new page AAD
// from scratch)
void QuickUpdatePageAad(int32_t new_page_ordinal, std::string* AAD) {
  CheckPageOrdinal(new_page_ordinal);
  const std::string page_ordinal_bytes =
      ShortToBytesLe(static_cast<int16_t>(new_page_ordinal));
  std::memcpy(AAD->data() + AAD->length() - 2, page_ordinal_bytes.data(), 2);
}

void RandBytes(unsigned char* buf, size_t num) {
  if (num > static_cast<size_t>(std::numeric_limits<int>::max())) {
    std::stringstream ss;
    ss << "Length " << num << " for RandBytes overflows int";
    throw ParquetException(ss.str());
  }
  openssl::EnsureInitialized();
  int status = RAND_bytes(buf, static_cast<int>(num));
  if (status != 1) {
    const auto error_code = ERR_get_error();
    char buffer[256];
    ERR_error_string_n(error_code, buffer, sizeof(buffer));
    std::stringstream ss;
    ss << "Failed to generate random bytes: " << buffer;
    throw ParquetException(ss.str());
  }
}

void EnsureBackendInitialized() { openssl::EnsureInitialized(); }

ExternalEncryptorImpl::ExternalEncryptorImpl(
  std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance)
    : agent_instance_(std::move(agent_instance)) {
  std::cout << "[DEBUG] ExternalEncryptorImpl constructor called" << std::endl;
}

std::unique_ptr<ExternalEncryptorImpl> ExternalEncryptorImpl::Make(
    ParquetCipher::type alg_id, int32_t key_len, std::string column_name, Type::type data_type, 
    Compression::type compression_type, Encoding::type encoding, std::string ext_column_key,
    std::string user_id, std::string app_context, bool metadata, bool write_length) {

  std::cout << "[DEBUG] ExternalEncryptorImpl::Make called with parameters:" << std::endl;
  std::cout << "  alg_id: " << alg_id << std::endl;
  std::cout << "  key_len: " << key_len << std::endl;
  std::cout << "  column_name: " << column_name << std::endl;
  std::cout << "  data_type: " << HackTypeToString(data_type) << std::endl;
  std::cout << "  compression_type: " << CompressName(compression_type) << std::endl;
  std::cout << "  encoding: " << encoding << std::endl;
  std::cout << "  ext_column_key: " << ext_column_key << std::endl;
  std::cout << "  user_id: " << user_id << std::endl;
  std::cout << "  app_context: " << app_context << std::endl;
  std::cout << "  metadata: " << (metadata ? "true" : "false") << std::endl;
  std::cout << "  write_length: " << (write_length ? "true" : "false") << std::endl;

  //TODO: this should be a config parameter
  std::string dbpa_library_path = "libDBPATestAgent.so";
  std::cout << "[DEBUG] Loading DBPA agent from: " << dbpa_library_path << std::endl;
  auto dbpa_agent = LoadableEncryptorUtils::LoadFromLibrary(dbpa_library_path);
  if (!dbpa_agent) {
    std::cout << "[ERROR] Failed to create instance of DataBatchProtectionAgentInterface" << std::endl;
    throw ParquetException("Failed to create instance of DataBatchProtectionAgentInterface");
  }
  std::cout << "[DEBUG] Successfully loaded DBPA agent" << std::endl;

  std::cout << "[DEBUG] Initializing DBPA agent..." << std::endl;
  dbpa_agent->init(
    /*column_name*/ column_name,
    /*connection_config*/ std::map<std::string, std::string>{},
    /*app_context*/ app_context,
    /*column_key_id*/ ext_column_key,
    /*data_type*/ dbpa_utils::ParquetTypeToExternal(data_type), 
    /*compression_type*/ dbpa_utils::ArrowCompressionToExternal(compression_type)
  );
  std::cout << "[DEBUG] DBPA agent initialized successfully" << std::endl;

  auto result = std::make_unique<ExternalEncryptorImpl>(std::move(dbpa_agent));
  std::cout << "[DEBUG] ExternalEncryptorImpl created successfully" << std::endl;
  return result;
}

int32_t ExternalEncryptorImpl::Encrypt(span<const uint8_t> plaintext, span<const uint8_t> key,
                                       span<const uint8_t> aad, span<uint8_t> ciphertext) {

  std::cout << "[DEBUG] ExternalEncryptorImpl::Encrypt called" << std::endl;
  std::cout << "  plaintext size: " << plaintext.size() << " bytes" << std::endl;
  std::cout << "  key size: " << key.size() << " bytes" << std::endl;
  std::cout << "  aad size: " << aad.size() << " bytes" << std::endl;
  std::cout << "  ciphertext buffer size: " << ciphertext.size() << " bytes" << std::endl;

  std::cout << "[DEBUG] Calling agent_instance_->Encrypt..." << std::endl;
  std::unique_ptr<EncryptionResult> result = agent_instance_->Encrypt(plaintext);
  
  if (!result->success()) {
    std::cout << "[ERROR] Encryption failed: " << result->error_message() << std::endl;
    throw ParquetException(result->error_message());
  }
  std::cout << "[DEBUG] Encryption successful" << std::endl;
  std::cout << "  result size: " << result->size() << " bytes" << std::endl;
  std::cout << "  result ciphertext size: " << result->ciphertext().size() << " bytes" << std::endl;

  if (ciphertext.size() < result->ciphertext().size()) {
    std::cout << "[ERROR] Ciphertext buffer too small. Need " << result->ciphertext().size() 
              << " bytes, have " << ciphertext.size() << " bytes" << std::endl;
    throw ParquetException("Ciphertext buffer too small for encrypted result");
  }
  
  std::cout << "[DEBUG] Copying result to ciphertext buffer..." << std::endl;
  std::copy(result->ciphertext().begin(), result->ciphertext().end(), ciphertext.begin());
  std::cout << "[DEBUG] Encryption completed successfully" << std::endl;

  return result->size();
}

int32_t ExternalEncryptorImpl::SignedFooterEncrypt(span<const uint8_t> footer, 
                                                   span<const uint8_t> key,
                                                   span<const uint8_t> aad,
                                                   span<const uint8_t> nonce,
                                                   span<uint8_t> encrypted_footer) {
  std::cout << "[DEBUG] ExternalEncryptorImpl::SignedFooterEncrypt called" << std::endl;
  std::cout << "  footer size: " << footer.size() << " bytes" << std::endl;
  std::cout << "  key size: " << key.size() << " bytes" << std::endl;
  std::cout << "  aad size: " << aad.size() << " bytes" << std::endl;
  std::cout << "  nonce size: " << nonce.size() << " bytes" << std::endl;
  std::cout << "  encrypted_footer buffer size: " << encrypted_footer.size() << " bytes" << std::endl;

  std::cout << "[DEBUG] Calling agent_instance_->Encrypt for footer..." << std::endl;
  std::unique_ptr<EncryptionResult> result = agent_instance_->Encrypt(footer);
  if (!result->success()) {
    std::cout << "[ERROR] Footer encryption failed: " << result->error_message() << std::endl;
    throw ParquetException(result->error_message());
  }
  std::cout << "[DEBUG] Footer encryption successful" << std::endl;
  std::cout << "  result size: " << result->size() << " bytes" << std::endl;

  if (encrypted_footer.size() < result->ciphertext().size()) {
    std::cout << "[ERROR] Encrypted footer buffer too small. Need " << result->ciphertext().size() 
              << " bytes, have " << encrypted_footer.size() << " bytes" << std::endl;
    throw ParquetException("Encrypted footer buffer too small for encrypted result");
  }
  
  std::cout << "[DEBUG] Copying footer result to encrypted_footer buffer..." << std::endl;
  std::copy(result->ciphertext().begin(), result->ciphertext().end(), encrypted_footer.begin());
  std::cout << "[DEBUG] Footer encryption completed successfully" << std::endl;

  return result->size();
}

int32_t ExternalEncryptorImpl::CiphertextLength(int64_t plaintext_len) const {
  std::cout << "[DEBUG] ExternalEncryptorImpl::CiphertextLength called with plaintext_len: " << plaintext_len << std::endl;

  //TODO
  // This is not production code. We know that the one DPBA Agent we have uses XOR encryption.
  // Therefore it's safe to assume that the ciphertext length is the same as the plaintext length.
  // This is not true for all DPBA Agents.
  if (plaintext_len < 0) {
    std::cout << "[ERROR] Negative plaintext length: " << plaintext_len << std::endl;
    std::stringstream ss;
    ss << "Negative plaintext length " << plaintext_len;
    throw ParquetException(ss.str());
  }
  int32_t result = static_cast<int32_t>(plaintext_len);
  std::cout << "[DEBUG] CiphertextLength returning: " << result << std::endl;
  return result;
}

std::string HackTypeToString(Type::type t) {
  switch (t) {
    case Type::BOOLEAN: return "BOOLEAN";
    case Type::INT32: return "INT32";
    case Type::INT64: return "INT64";
    case Type::INT96: return "INT96";
    case Type::FLOAT: return "FLOAT";
    case Type::DOUBLE: return "DOUBLE";
    case Type::BYTE_ARRAY: return "BYTE_ARRAY";
    case Type::FIXED_LEN_BYTE_ARRAY: return "FIXED_LEN_BYTE_ARRAY";
    default: return "UNKNOWN";
  }
}

std::string CompressName(Compression::type codec) {
  switch (codec) {
    case Compression::UNCOMPRESSED: return "UNCOMPRESSED";
    case Compression::SNAPPY:       return "SNAPPY";
    case Compression::GZIP:         return "GZIP";
    case Compression::BROTLI:       return "BROTLI";
    case Compression::ZSTD:         return "ZSTD";
    case Compression::LZ4:          return "LZ4";
    case Compression::LZ4_FRAME:    return "LZ4_FRAME";
    case Compression::LZO:          return "LZO";
    case Compression::BZ2:          return "BZ2";
    case Compression::LZ4_HADOOP:   return "LZ4_HADOOP";
    default:                        return "UNKNOWN";
  }
}

std::string MapArrowEncodingToExternalFormat(Encoding::type encoding) {
  // Temporary hack before we do the full mapping.
  return "raw-c-data";
}

std::string MapArrowEncodingToExternalEncoding(Encoding::type encoding) {
  // Temporary hack before we do the full mapping.
  return "base64";
}

void PrintSpan(span<const uint8_t> plaintext) {
  for (auto byte : plaintext) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
  }
  std::cout << std::dec << std::endl;
}

void ExternalEncryptorImpl::ConstructExternalCall(span<const uint8_t> plaintext) {
  std::cout << "\n\n!*!*!*!*!*!* START ExternalEncryptorImpl:ConstructExternalCall!*!*!*!*!*!*"
            << std::endl;

  std::cout << "Calling ExternalEncryptorService." << std::endl;

  std::cout << "Payload:" << std::endl;
  
  std::cout << "!*!*!*!*!*!* END ExternalEncryptorImpl:ConstructExternalCall!*!*!*!*!*!*\n\n"
            << std::endl;
}

ExternalDecryptorImpl::ExternalDecryptorImpl(
  std::unique_ptr<DataBatchProtectionAgentInterface> agent_instance)
    : agent_instance_(std::move(agent_instance)) {
  std::cout << "[DEBUG] ExternalDecryptorImpl constructor called" << std::endl;
}

std::unique_ptr<ExternalDecryptorImpl> ExternalDecryptorImpl::Make(
    ParquetCipher::type alg_id, int32_t key_len, std::string column_name, Type::type data_type, 
    Compression::type compression_type, Encoding::type encoding, std::string ext_column_key,
    std::string user_id, std::string app_context, bool metadata, bool contains_length) {

  std::cout << "[DEBUG] ExternalDecryptorImpl::Make (full) called with parameters:" << std::endl;
  std::cout << "  alg_id: " << alg_id << std::endl;
  std::cout << "  key_len: " << key_len << std::endl;
  std::cout << "  column_name: " << column_name << std::endl;
  std::cout << "  data_type: " << HackTypeToString(data_type) << std::endl;
  std::cout << "  compression_type: " << CompressName(compression_type) << std::endl;
  std::cout << "  encoding: " << encoding << std::endl;
  std::cout << "  ext_column_key: " << ext_column_key << std::endl;
  std::cout << "  user_id: " << user_id << std::endl;
  std::cout << "  app_context: " << app_context << std::endl;
  std::cout << "  metadata: " << (metadata ? "true" : "false") << std::endl;
  std::cout << "  contains_length: " << (contains_length ? "true" : "false") << std::endl;

  //TODO: this should be a config parameter
  std::string dbpa_library_path = "libDBPATestAgent.so";
  std::cout << "[DEBUG] Loading DBPA agent from: " << dbpa_library_path << std::endl;
  auto dbpa_agent = LoadableEncryptorUtils::LoadFromLibrary(dbpa_library_path);
  if (!dbpa_agent) {
    std::cout << "[ERROR] Failed to create instance of DataBatchProtectionAgentInterface" << std::endl;
    throw ParquetException("Failed to create instance of DataBatchProtectionAgentInterface");
  }
  std::cout << "[DEBUG] Successfully loaded DBPA agent" << std::endl;

  std::cout << "[DEBUG] Initializing DBPA agent..." << std::endl;
  dbpa_agent->init(
    /*column_name*/ column_name,
    /*connection_config*/ std::map<std::string, std::string>{},
    /*app_context*/ app_context,
    /*column_key_id*/ ext_column_key,
    /*data_type*/ dbpa_utils::ParquetTypeToExternal(data_type), 
    /*compression_type*/ dbpa_utils::ArrowCompressionToExternal(compression_type)
  );
  std::cout << "[DEBUG] DBPA agent initialized successfully" << std::endl;

  auto result = std::make_unique<ExternalDecryptorImpl>(std::move(dbpa_agent));
  std::cout << "[DEBUG] ExternalDecryptorImpl created successfully" << std::endl;
  return result;
}

std::unique_ptr<ExternalDecryptorImpl> ExternalDecryptorImpl::Make(ParquetCipher::type alg_id, int32_t key_len, bool metadata) {
  std::cout << "[DEBUG] ExternalDecryptorImpl::Make (simple) called with parameters:" << std::endl;

  std::cout << "  alg_id: " << alg_id << std::endl;
  std::cout << "  key_len: " << key_len << std::endl;
  std::cout << "  metadata: " << (metadata ? "true" : "false") << std::endl;

  //TODO: this should be a config parameter
  std::string dbpa_library_path = "libDBPATestAgent.so";

  std::cout << "[DEBUG] Loading DBPA agent from: " << dbpa_library_path << std::endl;
  auto dbpa_agent = LoadableEncryptorUtils::LoadFromLibrary(dbpa_library_path);
  if (!dbpa_agent) {
    std::cout << "[ERROR] Failed to create instance of DataBatchProtectionAgentInterface" << std::endl;
    throw ParquetException("Failed to create instance of DataBatchProtectionAgentInterface");
  }
  std::cout << "[DEBUG] Successfully loaded DBPA agent" << std::endl;

  // For simple cases (like footer decryption), we use default values
  std::cout << "[DEBUG] Initializing DBPA agent with default values..." << std::endl;
  dbpa_agent->init(
    /*column_name*/ "footer",  // Default column name for footer
    /*connection_config*/ std::map<std::string, std::string>{},
    /*app_context*/ "default",  // Default app context
    /*column_key_id*/ "default",  // Default column key
    /*data_type*/ dbps::external::Type::BYTE_ARRAY,  // Default to byte array for footer
    /*compression_type*/ dbps::external::CompressionCodec::UNCOMPRESSED  // Default to uncompressed
  );
  std::cout << "[DEBUG] DBPA agent initialized successfully with default values" << std::endl;

  auto result = std::make_unique<ExternalDecryptorImpl>(std::move(dbpa_agent));
  std::cout << "[DEBUG] ExternalDecryptorImpl created successfully" << std::endl;
  return result;
}

int32_t ExternalDecryptorImpl::Decrypt(span<const uint8_t> ciphertext, span<const uint8_t> key,
                                       span<const uint8_t> aad, span<uint8_t> plaintext) {

  std::cout << "🔥 [DEBUG] ExternalDecryptorImpl::Decrypt called" << std::endl;
  std::cout << "  ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
  std::cout << "  key size: " << key.size() << " bytes" << std::endl;
  std::cout << "  aad size: " << aad.size() << " bytes" << std::endl;
  std::cout << "  plaintext buffer size: " << plaintext.size() << " bytes" << std::endl;

  std::cout << "[DEBUG] Calling agent_instance_->Decrypt..." << std::endl;
  std::unique_ptr<DecryptionResult> result = agent_instance_->Decrypt(ciphertext);
  
  if (!result->success()) {
    std::cout << "[ERROR] Decryption failed: " << result->error_message() << std::endl;
    throw ParquetException(result->error_message());
  }
  std::cout << "[DEBUG] Decryption successful" << std::endl;
  std::cout << "  result size: " << result->size() << " bytes" << std::endl;
  std::cout << "  result plaintext size: " << result->plaintext().size() << " bytes" << std::endl;

  // Debug: Log the first few bytes of decrypted data
  std::cout << "[DEBUG] First 16 bytes of decrypted data: ";
  for (size_t i = 0; i < std::min(size_t(16), result->plaintext().size()); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') 
              << static_cast<int>(result->plaintext()[i]) << " ";
  }
  std::cout << std::dec << std::endl;

  if (plaintext.size() < result->plaintext().size()) {
    std::cout << "[ERROR] Plaintext buffer too small. Need " << result->plaintext().size() 
              << " bytes, have " << plaintext.size() << " bytes" << std::endl;
    throw ParquetException("Plaintext buffer too small for decrypted result");
  }
  
  std::cout << "[DEBUG] Copying result to plaintext buffer..." << std::endl;
  std::copy(result->plaintext().begin(), result->plaintext().end(), plaintext.begin());
  std::cout << "[DEBUG] Decryption completed successfully" << std::endl;

  return result->size();
}

int32_t ExternalDecryptorImpl::PlaintextLength(int32_t ciphertext_len) const {
  std::cout << "[DEBUG] ExternalDecryptorImpl::PlaintextLength called with ciphertext_len: " << ciphertext_len << std::endl;
  //TODO
  // This is not production code. We know that the one DPBA Agent we have uses XOR encryption.
  // Therefore it's safe to assume that the plaintext length is the same as the ciphertext length.
  // This is not true for all DPBA Agents.
  if (ciphertext_len < 0) {
    std::cout << "[ERROR] Negative ciphertext length: " << ciphertext_len << std::endl;
    std::stringstream ss;
    ss << "Negative ciphertext length " << ciphertext_len;
    throw ParquetException(ss.str());
  }
  int32_t result = ciphertext_len;
  std::cout << "[DEBUG] PlaintextLength returning: " << result << std::endl;
  return result;
}

int32_t ExternalDecryptorImpl::CiphertextLength(int32_t plaintext_len) const {
  std::cout << "[DEBUG] ExternalDecryptorImpl::CiphertextLength called with plaintext_len: " << plaintext_len << std::endl;
  //TODO
  // This is not production code. We know that the one DPBA Agent we have uses XOR encryption.
  // Therefore it's safe to assume that the ciphertext length is the same as the plaintext length.
  // This is not true for all DPBA Agents.
  if (plaintext_len < 0) {
    std::cout << "[ERROR] Negative plaintext length: " << plaintext_len << std::endl;
    std::stringstream ss;
    ss << "Negative plaintext length " << plaintext_len;
    throw ParquetException(ss.str());
  }
  int32_t result = plaintext_len;
  std::cout << "[DEBUG] CiphertextLength returning: " << result << std::endl;
  return result;
}

void ExternalDecryptorImpl::ConstructExternalCall(span<const uint8_t> ciphertext) {
  std::cout << "\n\n!*!*!*!*!*!* START ExternalDecryptorImpl:ConstructExternalCall!*!*!*!*!*!*"
            << std::endl;

  std::cout << "Calling ExternalDecryptorService." << std::endl;

  std::cout << "Payload:" << std::endl;
  
  std::cout << "!*!*!*!*!*!* END ExternalDecryptorImpl:ConstructExternalCall!*!*!*!*!*!*\n\n"
            << std::endl;
}

#undef ENCRYPT_INIT
#undef DECRYPT_INIT

}  // namespace parquet::encryption
