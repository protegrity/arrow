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

#include "arrow/python/parquet_encryption.h"
#include "parquet/exception.h"

namespace arrow {
namespace py {
namespace parquet {
namespace encryption {

PyKmsClient::PyKmsClient(PyObject* handler, PyKmsClientVtable vtable)
    : handler_(handler), vtable_(std::move(vtable)) {
  Py_INCREF(handler);
}

PyKmsClient::~PyKmsClient() {}

std::string PyKmsClient::WrapKey(const ::arrow::util::SecureString& key,
                                 const std::string& master_key_identifier) {
  std::string wrapped;
  auto st = SafeCallIntoPython([&]() -> Status {
    vtable_.wrap_key(handler_.obj(), key, master_key_identifier, &wrapped);
    return CheckPyError();
  });
  if (!st.ok()) {
    throw ::parquet::ParquetStatusException(st);
  }
  return wrapped;
}

::arrow::util::SecureString PyKmsClient::UnwrapKey(
    const std::string& wrapped_key, const std::string& master_key_identifier) {
  arrow::util::SecureString unwrapped;
  auto st = SafeCallIntoPython([&]() -> Status {
    vtable_.unwrap_key(handler_.obj(), wrapped_key, master_key_identifier, &unwrapped);
    return CheckPyError();
  });
  if (!st.ok()) {
    throw ::parquet::ParquetStatusException(st);
  }
  return unwrapped;
}

PyKmsClientFactory::PyKmsClientFactory(PyObject* handler, PyKmsClientFactoryVtable vtable)
    : handler_(handler), vtable_(std::move(vtable)) {
  Py_INCREF(handler);
}

PyKmsClientFactory::~PyKmsClientFactory() {}

std::shared_ptr<::parquet::encryption::KmsClient> PyKmsClientFactory::CreateKmsClient(
    const ::parquet::encryption::KmsConnectionConfig& kms_connection_config) {
  std::shared_ptr<::parquet::encryption::KmsClient> kms_client;
  auto st = SafeCallIntoPython([&]() -> Status {
    vtable_.create_kms_client(handler_.obj(), kms_connection_config, &kms_client);
    return CheckPyError();
  });
  if (!st.ok()) {
    throw ::parquet::ParquetStatusException(st);
  }
  return kms_client;
}

PyParquetCryptoProvider::PyParquetCryptoProvider(PyObject* handler,
                                                 PyParquetCryptoProviderVtable vtable)
    : handler_(handler), vtable_(std::move(vtable)) {
  Py_INCREF(handler);
}

PyParquetCryptoProvider::~PyParquetCryptoProvider() {}

arrow::Result<std::vector<uint8_t>> PyParquetCryptoProvider::EncryptBlock(
    std::span<const uint8_t> plaintext, const ::parquet::ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  std::string out;
  RETURN_NOT_OK(SafeCallIntoPython([&]() -> Status {
    vtable_.encrypt_block(handler_.obj(), std::string(plaintext.begin(), plaintext.end()),
                          ctx.key_metadata, ctx.column_path, ctx.app_context,
                          std::string(module_aad.begin(), module_aad.end()),
                          std::string(dek.begin(), dek.end()), &out);
    return CheckPyError();
  }));
  return std::vector<uint8_t>(out.begin(), out.end());
}

arrow::Result<std::vector<uint8_t>> PyParquetCryptoProvider::DecryptBlock(
    std::span<const uint8_t> ciphertext, const ::parquet::ParquetCryptoContext& ctx,
    std::span<const uint8_t> module_aad, std::span<const uint8_t> dek) {
  std::string out;
  RETURN_NOT_OK(SafeCallIntoPython([&]() -> Status {
    vtable_.decrypt_block(handler_.obj(),
                          std::string(ciphertext.begin(), ciphertext.end()),
                          ctx.key_metadata, ctx.column_path, ctx.app_context,
                          std::string(module_aad.begin(), module_aad.end()),
                          std::string(dek.begin(), dek.end()), &out);
    return CheckPyError();
  }));
  return std::vector<uint8_t>(out.begin(), out.end());
}

// Dead code: SupportsTypedValues() always returns false, so Arrow never calls this.
arrow::Status PyParquetCryptoProvider::EncryptCells(
    ::parquet::CryptoValueBuffer& values, const ::parquet::ParquetCryptoContext& ctx,
    std::span<const uint8_t> dek) {
  return arrow::Status::NotImplemented(
      "PyParquetCryptoProvider only supports the block path (SupportsTypedValues() "
      "returns false); EncryptCells is unreachable.");
}

// Dead code for the same reason as EncryptCells().
arrow::Status PyParquetCryptoProvider::DecryptCells(
    ::parquet::CryptoValueBuffer& values, const ::parquet::ParquetCryptoContext& ctx,
    std::span<const uint8_t> dek) {
  return arrow::Status::NotImplemented(
      "PyParquetCryptoProvider only supports the block path (SupportsTypedValues() "
      "returns false); DecryptCells is unreachable.");
}

// Unlike EncryptCells/DecryptCells, this is reachable whenever plaintext_footer=true
// is used with this provider -- there is no SupportsTypedValues()-style gate.
arrow::Result<std::vector<uint8_t>> PyParquetCryptoProvider::SignFooter(
    std::span<const uint8_t> footer_bytes, const ::parquet::ParquetCryptoContext& ctx,
    std::span<const uint8_t> footer_aad, std::span<const uint8_t> dek) {
  std::string out;
  RETURN_NOT_OK(SafeCallIntoPython([&]() -> Status {
    vtable_.sign_footer(handler_.obj(),
                        std::string(footer_bytes.begin(), footer_bytes.end()),
                        ctx.key_metadata, ctx.column_path, ctx.app_context,
                        std::string(footer_aad.begin(), footer_aad.end()),
                        std::string(dek.begin(), dek.end()), &out);
    return CheckPyError();
  }));
  return std::vector<uint8_t>(out.begin(), out.end());
}

// Unreachable for the same reason SignFooter() can't be dismissed as dead code.
arrow::Result<bool> PyParquetCryptoProvider::VerifyFooterSignature(
    std::span<const uint8_t> footer_bytes, std::span<const uint8_t> stored_signature,
    const ::parquet::ParquetCryptoContext& ctx, std::span<const uint8_t> footer_aad,
    std::span<const uint8_t> dek) {
  bool out = false;
  RETURN_NOT_OK(SafeCallIntoPython([&]() -> Status {
    vtable_.verify_footer_signature(
        handler_.obj(), std::string(footer_bytes.begin(), footer_bytes.end()),
        std::string(stored_signature.begin(), stored_signature.end()), ctx.key_metadata,
        ctx.column_path, ctx.app_context,
        std::string(footer_aad.begin(), footer_aad.end()),
        std::string(dek.begin(), dek.end()), &out);
    return CheckPyError();
  }));
  return out;
}

arrow::Result<std::shared_ptr<::parquet::FileEncryptionProperties>>
PyCryptoFactory::SafeGetFileEncryptionProperties(
    const ::parquet::encryption::KmsConnectionConfig& kms_connection_config,
    const ::parquet::encryption::EncryptionConfiguration& encryption_config,
    const std::string& parquet_file_path,
    const std::shared_ptr<::arrow::fs::FileSystem>& filesystem) {
  PARQUET_CATCH_AND_RETURN(this->GetFileEncryptionProperties(
      kms_connection_config, encryption_config, parquet_file_path, filesystem));
}

arrow::Result<std::shared_ptr<::parquet::ExternalFileEncryptionProperties>>
PyCryptoFactory::SafeGetExternalFileEncryptionProperties(
    const ::parquet::encryption::KmsConnectionConfig& kms_connection_config,
    const ::parquet::encryption::ExternalEncryptionConfiguration&
        external_encryption_config,
    const std::shared_ptr<::parquet::ParquetCryptoProvider>& parquet_crypto_provider,
    const std::string& parquet_file_path,
    const std::shared_ptr<::arrow::fs::FileSystem>& filesystem) {
  PARQUET_CATCH_AND_RETURN(this->GetExternalFileEncryptionProperties(
      kms_connection_config, external_encryption_config, parquet_crypto_provider,
      parquet_file_path, filesystem));
}

arrow::Result<std::shared_ptr<::parquet::FileDecryptionProperties>>
PyCryptoFactory::SafeGetFileDecryptionProperties(
    const ::parquet::encryption::KmsConnectionConfig& kms_connection_config,
    const ::parquet::encryption::DecryptionConfiguration& decryption_config,
    const std::string& parquet_file_path,
    const std::shared_ptr<::arrow::fs::FileSystem>& filesystem) {
  PARQUET_CATCH_AND_RETURN(this->GetFileDecryptionProperties(
      kms_connection_config, decryption_config, parquet_file_path, filesystem));
}

arrow::Status PyCryptoFactory::SafeRotateMasterKeys(
    const ::parquet::encryption::KmsConnectionConfig& kms_connection_config,
    const std::string& parquet_file_path,
    const std::shared_ptr<::arrow::fs::FileSystem>& filesystem, bool double_wrapping,
    double cache_lifetime_seconds) {
  PARQUET_CATCH_NOT_OK(this->RotateMasterKeys(kms_connection_config, parquet_file_path,
                                              filesystem, double_wrapping,
                                              cache_lifetime_seconds));
  return arrow::Status::OK();
}

arrow::Result<std::shared_ptr<::parquet::ExternalFileDecryptionProperties>>
PyCryptoFactory::SafeGetExternalFileDecryptionProperties(
    const ::parquet::encryption::KmsConnectionConfig& kms_connection_config,
    const ::parquet::encryption::ExternalDecryptionConfiguration&
        external_decryption_config,
    const std::shared_ptr<::parquet::ParquetCryptoProvider>& parquet_crypto_provider,
    const std::string& parquet_file_path,
    const std::shared_ptr<::arrow::fs::FileSystem>& filesystem) {
  PARQUET_CATCH_AND_RETURN(this->GetExternalFileDecryptionProperties(
      kms_connection_config, external_decryption_config, parquet_crypto_provider,
      parquet_file_path, filesystem));
}

}  // namespace encryption
}  // namespace parquet
}  // namespace py
}  // namespace arrow
