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

#include "parquet/encryption/parquet_crypto_provider_adapter_internal.h"

#include <cstring>
#include <limits>
#include <utility>

#include "arrow/buffer.h"
#include "parquet/encryption/encryption_utils.h"
#include "parquet/encryption/parquet_page_decoder_internal.h"
#include "parquet/exception.h"

namespace parquet {

namespace {

// 4-byte little-endian length prefix, mirroring AesDecryptor's existing
// kBufferSizeLength/GetCiphertextLength() convention for page headers. Only the
// block path (EncryptBlock/DecryptBlock) needs this: it is the only path whose
// output can be read back from a buffer whose exact boundary Arrow doesn't
// already know ahead of time (a page-header reader peeks a progressively larger,
// over-sized buffer before it knows the header's real extent). The cell path
// never has this ambiguity — the surrounding PageHeader already states the
// page's exact compressed size.
constexpr size_t kLengthPrefixSize = 4;

void AppendLengthPrefixedPayload(std::span<const uint8_t> payload,
                                 std::vector<uint8_t>* out) {
  if (payload.size() > std::numeric_limits<uint32_t>::max()) {
    throw ParquetException("ParquetCryptoProvider block payload too large: " +
                           std::to_string(payload.size()));
  }
  auto len = static_cast<uint32_t>(payload.size());
  out->reserve(out->size() + kLengthPrefixSize + payload.size());
  out->push_back(static_cast<uint8_t>(len));
  out->push_back(static_cast<uint8_t>(len >> 8));
  out->push_back(static_cast<uint8_t>(len >> 16));
  out->push_back(static_cast<uint8_t>(len >> 24));
  out->insert(out->end(), payload.begin(), payload.end());
}

// Returns the payload length encoded in `buf`'s leading 4-byte prefix (NOT
// including the prefix itself). Throws if `buf` is too short to even hold the
// prefix, or if the prefix claims more payload than `buf` actually has.
uint32_t ReadLengthPrefix(std::span<const uint8_t> buf) {
  if (buf.size() < kLengthPrefixSize) {
    throw ParquetException(
        "ParquetCryptoProvider block payload buffer is shorter than the 4-byte "
        "length prefix");
  }
  uint32_t len = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
                 (static_cast<uint32_t>(buf[2]) << 16) |
                 (static_cast<uint32_t>(buf[3]) << 24);
  // Mirror AesDecryptor::GetCiphertextLength's overflow guard: reject a prefix
  // that would make (len + kLengthPrefixSize) overflow the int32_t returned by
  // GetCiphertextLength(), before the (correct, but int64-widened) buffer-size
  // check below.
  if (len >
      static_cast<uint32_t>(std::numeric_limits<int32_t>::max()) - kLengthPrefixSize) {
    throw ParquetException("ParquetCryptoProvider block payload length prefix (" +
                           std::to_string(len) + ") plus the " +
                           std::to_string(kLengthPrefixSize) +
                           "-byte length prefix overflows int32");
  }
  if (static_cast<uint64_t>(len) + kLengthPrefixSize > buf.size()) {
    throw ParquetException("ParquetCryptoProvider block payload length prefix (" +
                           std::to_string(len) + ") exceeds the available buffer (" +
                           std::to_string(buf.size()) + " bytes)");
  }
  return len;
}

}  // namespace

ParquetCryptoProviderEncryptorAdapter::ParquetCryptoProviderEncryptorAdapter(
    std::shared_ptr<ParquetCryptoProvider> provider, ParquetCryptoContext ctx,
    int8_t dispatch_module_type)
    : provider_(std::move(provider)),
      ctx_(std::move(ctx)),
      dispatch_module_type_(dispatch_module_type) {}

bool ParquetCryptoProviderEncryptorAdapter::UseCellPath() const {
  return provider_->SupportsTypedValues() &&
         (dispatch_module_type_ == encryption::kDataPage ||
          dispatch_module_type_ == encryption::kDictionaryPage);
}

int32_t ParquetCryptoProviderEncryptorAdapter::EncryptWithManagedBuffer(
    std::span<const uint8_t> plaintext, ::arrow::ResizableBuffer* ciphertext,
    std::span<const uint8_t> aad, std::span<const uint8_t> dek,
    std::unique_ptr<encryption::EncodingProperties> encoding_properties,
    int64_t* new_uncompressed_size) {
  std::vector<uint8_t> result_bytes;

  if (UseCellPath()) {
    if (encoding_properties == nullptr) {
      throw ParquetException(
          "ParquetCryptoProviderEncryptorAdapter: EncodingProperties required for cell "
          "path");
    }
    TypedColumnValues typed =
        ParquetPageDecoder::Decompress(plaintext, *encoding_properties);
    PARQUET_THROW_NOT_OK(provider_->EncryptCells(typed.values(), ctx_, dek));
    result_bytes = ParquetPageDecoder::Recompress(typed, *encoding_properties,
                                                  new_uncompressed_size);
  } else {
    // aad is the module AAD Encryptor::UpdateAad() already computed via
    // CreateModuleAad()/QuickUpdatePageAad() — the same per-page positional binding
    // Internal PME uses for AES-GCM — forwarded straight through to the provider.
    std::vector<uint8_t> block_payload;
    PARQUET_ASSIGN_OR_THROW(block_payload,
                            provider_->EncryptBlock(plaintext, ctx_, aad, dek));
    AppendLengthPrefixedPayload(block_payload, &result_bytes);
  }

  PARQUET_THROW_NOT_OK(ciphertext->Resize(static_cast<int64_t>(result_bytes.size()),
                                          /*shrink_to_fit=*/false));
  std::memcpy(ciphertext->mutable_data(), result_bytes.data(), result_bytes.size());
  return static_cast<int32_t>(result_bytes.size());
}

int32_t ParquetCryptoProviderEncryptorAdapter::SignedFooterEncrypt(
    std::span<const uint8_t> footer, std::span<const uint8_t> key,
    std::span<const uint8_t> aad, std::span<const uint8_t> nonce,
    std::span<uint8_t> encrypted_footer) {
  throw ParquetException(
      "ParquetCryptoProviderEncryptorAdapter::SignedFooterEncrypt is unreachable: "
      "footer signing is routed to the provider via ComputeFooterSignature() instead");
}

std::vector<uint8_t> ParquetCryptoProviderEncryptorAdapter::ComputeFooterSignature(
    std::span<const uint8_t> footer, std::span<const uint8_t> footer_aad,
    std::span<const uint8_t> dek) {
  std::vector<uint8_t> signature;
  PARQUET_ASSIGN_OR_THROW(signature,
                          provider_->SignFooter(footer, ctx_, footer_aad, dek));
  return signature;
}

ParquetCryptoProviderDecryptorAdapter::ParquetCryptoProviderDecryptorAdapter(
    std::shared_ptr<ParquetCryptoProvider> provider, ParquetCryptoContext ctx,
    int8_t dispatch_module_type)
    : provider_(std::move(provider)),
      ctx_(std::move(ctx)),
      dispatch_module_type_(dispatch_module_type) {}

bool ParquetCryptoProviderDecryptorAdapter::UseCellPath() const {
  return provider_->SupportsTypedValues() &&
         (dispatch_module_type_ == encryption::kDataPage ||
          dispatch_module_type_ == encryption::kDictionaryPage);
}

int32_t ParquetCryptoProviderDecryptorAdapter::GetCiphertextLength(
    std::span<const uint8_t> ciphertext) const {
  if (UseCellPath()) {
    // The cell path is never read via a peeked/ambiguous buffer (its caller
    // always already knows the exact page size), so no length prefix exists.
    return static_cast<int32_t>(ciphertext.size());
  }
  return static_cast<int32_t>(kLengthPrefixSize + ReadLengthPrefix(ciphertext));
}

int32_t ParquetCryptoProviderDecryptorAdapter::DecryptWithManagedBuffer(
    std::span<const uint8_t> ciphertext, ::arrow::ResizableBuffer* plaintext,
    std::span<const uint8_t> aad, std::span<const uint8_t> dek,
    std::unique_ptr<encryption::EncodingProperties> encoding_properties,
    int64_t* new_uncompressed_size) {
  std::vector<uint8_t> result_bytes;

  if (UseCellPath()) {
    if (encoding_properties == nullptr) {
      throw ParquetException(
          "ParquetCryptoProviderDecryptorAdapter: EncodingProperties required for "
          "cell path");
    }
    TypedColumnValues typed =
        ParquetPageDecoder::Decompress(ciphertext, *encoding_properties);
    PARQUET_THROW_NOT_OK(provider_->DecryptCells(typed.values(), ctx_, dek));
    result_bytes = ParquetPageDecoder::Recompress(typed, *encoding_properties,
                                                  new_uncompressed_size);
  } else {
    // Strip the 4-byte length prefix EncryptWithManagedBuffer() wrote, so the
    // provider only ever sees its own real ciphertext — never trailing garbage
    // from an over-sized peeked buffer (e.g. a page header read speculatively
    // before its real extent is known).
    uint32_t payload_len = ReadLengthPrefix(ciphertext);
    std::span<const uint8_t> payload = ciphertext.subspan(kLengthPrefixSize, payload_len);
    // aad is the module AAD Decryptor::UpdateAad() already computed — the same
    // per-page positional binding Internal PME uses for AES-GCM — forwarded
    // straight through to the provider.
    PARQUET_ASSIGN_OR_THROW(result_bytes,
                            provider_->DecryptBlock(payload, ctx_, aad, dek));
  }

  PARQUET_THROW_NOT_OK(plaintext->Resize(static_cast<int64_t>(result_bytes.size()),
                                         /*shrink_to_fit=*/false));
  std::memcpy(plaintext->mutable_data(), result_bytes.data(), result_bytes.size());
  return static_cast<int32_t>(result_bytes.size());
}

bool ParquetCryptoProviderDecryptorAdapter::VerifyFooterSignature(
    std::span<const uint8_t> footer, std::span<const uint8_t> stored_signature,
    std::span<const uint8_t> footer_aad, std::span<const uint8_t> dek) {
  bool ok;
  PARQUET_ASSIGN_OR_THROW(ok, provider_->VerifyFooterSignature(footer, stored_signature,
                                                               ctx_, footer_aad, dek));
  return ok;
}

}  // namespace parquet
