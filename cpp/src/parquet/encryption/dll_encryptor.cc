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

#include "parquet/encryption/dll_encryptor.h"

#include <iostream>

#include "parquet/encryption/encryption_internal.h"

using ::arrow::util::span;

namespace parquet::encryption {

DLLEncryptor::DLLEncryptor(ParquetCipher::type alg_id, 
                           int32_t key_len, 
                           std::string column_name, 
                           Type::type data_type, 
                           Compression::type compression_type, 
                           Encoding::type encoding, 
                           std::string ext_column_key, 
                           std::string user_id, 
                           std::string app_context, 
                           bool metadata, 
                           bool write_length)
    : column_name_(column_name), 
      data_type_(data_type), 
      compression_type_(compression_type),
      encoding_(encoding), 
      ext_column_key_(ext_column_key), 
      user_id_(user_id),
      app_context_(app_context),
      aes_encryptor_(std::make_unique<AesEncryptorImpl>(alg_id, key_len, metadata, write_length)) {
  std::cout << "Created DLLEncryptor" << std::endl;
}

std::unique_ptr<DLLEncryptor> DLLEncryptor::Make(ParquetCipher::type alg_id, int32_t key_len, 
                                                  std::string column_name, Type::type data_type, 
                                                  Compression::type compression_type, 
                                                  Encoding::type encoding, 
                                                  std::string ext_column_key, 
                                                  std::string user_id, 
                                                  std::string app_context, 
                                                  bool metadata, 
                                                  bool write_length) {
  std::cout << "Inside DLLEncryptor::Make" << std::endl;
  return std::make_unique<DLLEncryptor>(alg_id, key_len, column_name, data_type, 
                                        compression_type, encoding, ext_column_key, 
                                        user_id, app_context, metadata, write_length);
}

int32_t DLLEncryptor::Encrypt(span<const uint8_t> plaintext, span<const uint8_t> key,
                              span<const uint8_t> aad, span<uint8_t> ciphertext) {
  std::cout << "Inside DLLEncryptor::Encrypt" << std::endl;
  ConstructExternalCall(plaintext);
  return aes_encryptor_->Encrypt(plaintext, key, aad, ciphertext);
}

int32_t DLLEncryptor::SignedFooterEncrypt(span<const uint8_t> footer, span<const uint8_t> key,
                                          span<const uint8_t> aad, span<const uint8_t> nonce,
                                          span<uint8_t> encrypted_footer) {
  std::cout << "Inside DLLEncryptor::SignedFooterEncrypt" << std::endl;
  return aes_encryptor_->SignedFooterEncrypt(footer, key, aad, nonce, encrypted_footer);
}

int32_t DLLEncryptor::CiphertextLength(int64_t plaintext_len) const {
  std::cout << "Inside DLLEncryptor::CiphertextLength" << std::endl;
  return aes_encryptor_->CiphertextLength(plaintext_len);
}

void DLLEncryptor::ConstructExternalCall(span<const uint8_t> plaintext) {
  std::cout << "Inside DLLEncryptor::ConstructExternalCall" << std::endl;
  // TODO: Implement actual DLL call logic here
}

}  // namespace parquet::encryption 