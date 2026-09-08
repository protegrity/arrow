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
#include <utility>

#include "arrow/buffer.h"
#include "parquet/encryption/parquet_page_decoder_internal.h"
#include "parquet/exception.h"

namespace parquet {

ParquetCryptoProviderAdapter::ParquetCryptoProviderAdapter(
    std::shared_ptr<ParquetCryptoProvider> provider, ParquetCryptoContext ctx)
    : provider_(std::move(provider)), ctx_(std::move(ctx)) {}

bool ParquetCryptoProviderAdapter::UseCellPath() const {
  return provider_->SupportsTypedValues() &&
         (ctx_.module_type == ParquetModuleType::kDataPage ||
          ctx_.module_type == ParquetModuleType::kDictionaryPage);
}

int32_t ParquetCryptoProviderAdapter::EncryptWithManagedBuffer(
    std::span<const uint8_t> plaintext, ::arrow::ResizableBuffer* ciphertext,
    std::span<const uint8_t> aad,
    std::unique_ptr<encryption::EncodingProperties> encoding_properties) {
  std::vector<uint8_t> result_bytes;

  if (UseCellPath()) {
    if (encoding_properties == nullptr) {
      throw ParquetException(
          "ParquetCryptoProviderAdapter: EncodingProperties required for cell path");
    }
    TypedColumnValues typed =
        ParquetPageDecoder::Decompress(plaintext, *encoding_properties);
    PARQUET_THROW_NOT_OK(provider_->EncryptCells(typed.values(), ctx_));
    result_bytes = ParquetPageDecoder::Recompress(typed, *encoding_properties);
  } else {
    // aad is the module AAD Encryptor::UpdateAad() already computed via
    // CreateModuleAad()/QuickUpdatePageAad() — the same per-page positional binding
    // Internal PME uses for AES-GCM — forwarded straight through to the vendor.
    PARQUET_ASSIGN_OR_THROW(result_bytes, provider_->EncryptBlock(plaintext, ctx_, aad));
  }

  PARQUET_THROW_NOT_OK(ciphertext->Resize(static_cast<int64_t>(result_bytes.size()),
                                          /*shrink_to_fit=*/false));
  std::memcpy(ciphertext->mutable_data(), result_bytes.data(), result_bytes.size());
  return static_cast<int32_t>(result_bytes.size());
}

int32_t ParquetCryptoProviderAdapter::SignedFooterEncrypt(
    std::span<const uint8_t> footer, std::span<const uint8_t> key,
    std::span<const uint8_t> aad, std::span<const uint8_t> nonce,
    std::span<uint8_t> encrypted_footer) {
  throw ParquetException(
      "ParquetCryptoProviderAdapter::SignedFooterEncrypt is not implemented: vendor "
      "footer signing is a future extension, not yet dispatched to this adapter");
}

}  // namespace parquet
