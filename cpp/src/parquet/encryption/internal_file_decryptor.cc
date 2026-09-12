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

#include "parquet/encryption/internal_file_decryptor.h"

#include <span>

#include "arrow/buffer.h"
#include "arrow/util/logging.h"
#include "arrow/util/secure_string.h"
#include "parquet/encryption/encryption.h"
#include "parquet/encryption/encryption_internal.h"
#include "parquet/encryption/encryption_utils.h"
#include "parquet/encryption/parquet_crypto_provider_adapter_internal.h"
#include "parquet/exception.h"
#include "parquet/metadata.h"

using arrow::util::SecureString;

namespace parquet {

// Decryptor
Decryptor::Decryptor(std::unique_ptr<encryption::DecryptorInterface> decryptor_instance,
                     SecureString key, std::string file_aad, std::string aad,
                     ::arrow::MemoryPool* pool)
    : decryptor_instance_(std::move(decryptor_instance)),
      key_(std::move(key)),
      file_aad_(std::move(file_aad)),
      aad_(std::move(aad)),
      pool_(pool) {}

Decryptor::~Decryptor() = default;

bool Decryptor::CanCalculateLengths() const {
  return decryptor_instance_->CanCalculateLengths();
}

int32_t Decryptor::PlaintextLength(int32_t ciphertext_len) const {
  return decryptor_instance_->PlaintextLength(ciphertext_len);
}

int32_t Decryptor::CiphertextLength(int32_t plaintext_len) const {
  return decryptor_instance_->CiphertextLength(plaintext_len);
}

int32_t Decryptor::Decrypt(std::span<const uint8_t> ciphertext,
                           std::span<uint8_t> plaintext,
                           std::unique_ptr<EncodingProperties> encoding_properties) {
  return decryptor_instance_->Decrypt(ciphertext, key_.as_span(), str2span(aad_),
                                      plaintext, std::move(encoding_properties));
}

int32_t Decryptor::DecryptWithManagedBuffer(
    std::span<const uint8_t> ciphertext, ::arrow::ResizableBuffer* plaintext,
    std::unique_ptr<EncodingProperties> encoding_properties) {
  return decryptor_instance_->DecryptWithManagedBuffer(ciphertext, plaintext,
                                                       str2span(aad_), key_.as_span(),
                                                       std::move(encoding_properties));
}

// InternalFileDecryptor
InternalFileDecryptor::InternalFileDecryptor(
    std::shared_ptr<FileDecryptionProperties> properties, const std::string& file_aad,
    ParquetCipher::type algorithm, const std::string& footer_key_metadata,
    ::arrow::MemoryPool* pool)
    : properties_(std::move(properties)),
      file_aad_(file_aad),
      algorithm_(algorithm),
      footer_key_metadata_(footer_key_metadata),
      pool_(pool),
      parquet_crypto_provider_(properties_->parquet_crypto_provider()) {}

const SecureString& InternalFileDecryptor::GetFooterKey() {
  std::unique_lock lock(mutex_);
  if (!footer_key_.empty()) {
    return footer_key_;
  }

  // cache footer key to avoid repeated retrieval of key from the key_retriever
  footer_key_ = properties_->footer_key();
  // ignore footer key metadata if footer key is explicitly set via API
  if (footer_key_.empty()) {
    if (footer_key_metadata_.empty())
      throw ParquetException("No footer key or key metadata");
    if (properties_->key_retriever() == nullptr)
      throw ParquetException("No footer key or key retriever");
    // key_retriever() is a KMS-backed FileKeyUnwrapper, not a raw callback, so this
    // resolves the real key regardless of encryption algorithm.
    try {
      footer_key_ = properties_->key_retriever()->GetKey(footer_key_metadata_);
    } catch (KeyAccessDeniedException& e) {
      std::stringstream ss;
      ss << "Footer key: access denied " << e.what() << "\n";
      throw ParquetException(ss.str());
    }
  }
  if (footer_key_.empty()) {
    throw ParquetException(
        "Footer key unavailable. Could not verify "
        "plaintext footer metadata");
  }

  return footer_key_;
}

std::unique_ptr<Decryptor> InternalFileDecryptor::GetFooterDecryptor() {
  std::string aad = encryption::CreateFooterAad(file_aad_);
  return GetFooterDecryptor(aad, true);
}

std::unique_ptr<Decryptor> InternalFileDecryptor::GetFooterDecryptor(
    const std::string& aad, bool metadata) {
  // Route the footer through the external ParquetCryptoProvider. A column cannot be
  // encrypted with the footer key under EXTERNAL_PROTECT_V1 (ExternalProtectV1 requires
  // non-empty key_metadata, which implies !is_encrypted_with_footer_key() — see the
  // encrypt-side invalid combos), so metadata=false never applies here.
  if (algorithm_ == ParquetCipher::EXTERNAL_PROTECT_V1) {
    if (!metadata) {
      throw ParquetException(
          "EXTERNAL_PROTECT_V1 columns cannot be encrypted with the footer key");
    }
    if (!parquet_crypto_provider_) {
      throw ParquetException(
          "FileDecryptionProperties::parquet_crypto_provider must be set when using "
          "EXTERNAL_PROTECT_V1 algorithm");
    }
    ParquetCryptoContext ctx;
    ctx.key_metadata = footer_key_metadata_;
    ctx.module_type = ParquetModuleType::kFooterEncrypted;
    auto decryptor_instance = std::make_unique<ParquetCryptoProviderDecryptorAdapter>(
        parquet_crypto_provider_, std::move(ctx));
    return std::make_unique<Decryptor>(std::move(decryptor_instance), GetFooterKey(),
                                       file_aad_, aad, pool_);
  }

  const SecureString& footer_key = GetFooterKey();

  auto key_len = static_cast<int32_t>(footer_key.size());
  // Metadata is decrypted with AES.
  auto decryptor_instance = encryption::AesDecryptor::Make(algorithm_, key_len, metadata);
  return std::make_unique<Decryptor>(std::move(decryptor_instance), footer_key, file_aad_,
                                     aad, pool_);
}

SecureString InternalFileDecryptor::GetColumnKey(const std::string& column_path,
                                                 const std::string& column_key_metadata) {
  SecureString column_key = properties_->column_key(column_path);

  // No explicit column key given via API. Retrieve via key metadata.
  if (column_key.empty() && !column_key_metadata.empty() &&
      properties_->key_retriever() != nullptr) {
    try {
      column_key = properties_->key_retriever()->GetKey(column_key_metadata);
    } catch (KeyAccessDeniedException& e) {
      std::stringstream ss;
      ss << "HiddenColumnException, path=" + column_path + " " << e.what() << "\n";
      throw HiddenColumnException(ss.str());
    }
    if (column_key.empty()) {
      throw HiddenColumnException("HiddenColumnException, path=" + column_path);
    }
  }
  return column_key;
}

std::unique_ptr<Decryptor> InternalFileDecryptor::GetColumnMetaDecryptor(
    const std::string& column_path, const std::string& column_key_metadata,
    const std::string& aad) {
  // Route column metadata through the external ParquetCryptoProvider.
  if (algorithm_ == ParquetCipher::EXTERNAL_PROTECT_V1) {
    if (!parquet_crypto_provider_) {
      throw ParquetException(
          "FileDecryptionProperties::parquet_crypto_provider must be set when using "
          "EXTERNAL_PROTECT_V1 algorithm");
    }
    if (column_key_metadata.empty()) {
      throw ParquetException(
          "key_metadata must be set on ColumnCryptoMetaData when using "
          "EXTERNAL_PROTECT_V1");
    }
    ParquetCryptoContext ctx;
    ctx.key_metadata = column_key_metadata;
    ctx.column_path = column_path;
    ctx.module_type = ParquetModuleType::kColumnMetaData;
    auto decryptor_instance = std::make_unique<ParquetCryptoProviderDecryptorAdapter>(
        parquet_crypto_provider_, std::move(ctx));
    return std::make_unique<Decryptor>(std::move(decryptor_instance),
                                       GetColumnKey(column_path, column_key_metadata),
                                       file_aad_, aad, pool_);
  }

  const SecureString& column_key = GetColumnKey(column_path, column_key_metadata);
  auto key_len = static_cast<int32_t>(column_key.size());
  auto decryptor_instance =
      encryption::AesDecryptor::Make(algorithm_, key_len, /*metadata=*/true);
  return std::make_unique<Decryptor>(std::move(decryptor_instance), column_key, file_aad_,
                                     aad, pool_);
}

std::function<std::unique_ptr<Decryptor>()>
InternalFileDecryptor::GetColumnDecryptorFactory(
    const ColumnCryptoMetaData* crypto_metadata, const std::string& aad, bool metadata,
    const ColumnChunkMetaData* column_chunk_metadata) {
  if (crypto_metadata->encrypted_with_footer_key()) {
    return [this, aad, metadata]() { return GetFooterDecryptor(aad, metadata); };
  }

  // The column is encrypted with its own key
  const std::string& column_key_metadata = crypto_metadata->key_metadata();
  const std::string column_path = crypto_metadata->path_in_schema()->ToDotString();

  // If this is data decryption, check if the column is encrypted with its own algorithm.
  ParquetCipher::type algorithm = algorithm_;
  if (!metadata && crypto_metadata->is_encryption_algorithm_set()) {
    algorithm = crypto_metadata->encryption_algorithm().algorithm;
  }

  // Route EXTERNAL_PROTECT_V1 to the external ParquetCryptoProvider. Applies to both
  // column metadata (metadata=true) and data pages (metadata=false) — no !metadata
  // guard.
  if (algorithm == ParquetCipher::EXTERNAL_PROTECT_V1) {
    if (!parquet_crypto_provider_) {
      throw ParquetException(
          "FileDecryptionProperties::parquet_crypto_provider must be set when using "
          "EXTERNAL_PROTECT_V1 algorithm");
    }
    if (column_key_metadata.empty()) {
      throw ParquetException(
          "key_metadata must be set on ColumnCryptoMetaData when using "
          "EXTERNAL_PROTECT_V1");
    }
    ParquetCryptoContext ctx;
    ctx.key_metadata = column_key_metadata;
    ctx.column_path = column_path;
    ctx.module_type =
        metadata ? ParquetModuleType::kColumnMetaData : ParquetModuleType::kDataPage;
    if (column_chunk_metadata != nullptr) {
      auto* descr = column_chunk_metadata->descr();
      ctx.data_type = descr->physical_type();
      if (ctx.data_type == Type::FIXED_LEN_BYTE_ARRAY) {
        ctx.datatype_length = descr->type_length();
      }
    }
    return [this, aad, ctx, column_path, column_key_metadata]() {
      auto decryptor_instance = std::make_unique<ParquetCryptoProviderDecryptorAdapter>(
          parquet_crypto_provider_, ctx);
      return std::make_unique<Decryptor>(std::move(decryptor_instance),
                                         GetColumnKey(column_path, column_key_metadata),
                                         file_aad_, aad, pool_);
    };
  }

  const SecureString& column_key = GetColumnKey(column_path, column_key_metadata);

  return [this, aad, metadata, column_key = std::move(column_key), algorithm]() {
    auto key_len = static_cast<int32_t>(column_key.size());
    auto decryptor_instance =
        encryption::AesDecryptor::Make(algorithm, key_len, metadata);
    return std::make_unique<Decryptor>(std::move(decryptor_instance), column_key,
                                       file_aad_, aad, pool_);
  };
}

std::function<std::unique_ptr<Decryptor>()>
InternalFileDecryptor::GetColumnMetaDecryptorFactory(
    InternalFileDecryptor* file_decryptor, const ColumnCryptoMetaData* crypto_metadata,
    const std::string& aad) {
  if (crypto_metadata == nullptr) {
    // Column is not encrypted
    return [] { return nullptr; };
  }
  if (file_decryptor == nullptr) {
    throw ParquetException("Column is noted as encrypted but no file decryptor");
  }
  return file_decryptor->GetColumnDecryptorFactory(crypto_metadata, aad,
                                                   /*metadata=*/true);
}

std::function<std::unique_ptr<Decryptor>()>
InternalFileDecryptor::GetColumnDataDecryptorFactory(
    InternalFileDecryptor* file_decryptor, const ColumnCryptoMetaData* crypto_metadata,
    const ColumnChunkMetaData* column_chunk_metadata, const std::string& aad) {
  if (crypto_metadata == nullptr) {
    // Column is not encrypted
    return [] { return nullptr; };
  }
  if (file_decryptor == nullptr) {
    throw ParquetException("Column is noted as encrypted but no file decryptor");
  }
  return file_decryptor->GetColumnDecryptorFactory(
      crypto_metadata, aad, /*metadata=*/false, column_chunk_metadata);
}

void UpdateDecryptor(Decryptor* decryptor, int16_t row_group_ordinal,
                     int16_t column_ordinal, int8_t module_type) {
  ARROW_DCHECK(!decryptor->file_aad().empty());
  const std::string aad =
      encryption::CreateModuleAad(decryptor->file_aad(), module_type, row_group_ordinal,
                                  column_ordinal, kNonPageOrdinal);
  decryptor->UpdateAad(aad);
}

}  // namespace parquet
