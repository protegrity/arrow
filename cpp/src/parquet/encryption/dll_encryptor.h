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
#include <string>

#include "parquet/platform.h"
#include "parquet/properties.h"
#include "parquet/types.h"
#include "parquet/encryption/encryption_internal.h"
#include "parquet/encryption/loadable_encryptor.h"

namespace parquet::encryption {

// Forward declaration
class AesEncryptorImpl;

class PARQUET_EXPORT DLLEncryptor : public LoadableEncryptorInterface {
 public:
  explicit DLLEncryptor();

  void init(ParquetCipher::type alg_id, 
            int32_t key_len,
            std::string column_name, 
            Type::type data_type,
            Compression::type compression_type, 
            Encoding::type encoding,
            std::string ext_column_key, 
            std::string user_id,
            std::string app_context,
            bool metadata, 
            bool write_length = true);
      
  int32_t Encrypt(span<const uint8_t> plaintext, span<const uint8_t> key,
                  span<const uint8_t> aad, span<uint8_t> ciphertext) override;

  int32_t SignedFooterEncrypt(span<const uint8_t> footer, span<const uint8_t> key,
                              span<const uint8_t> aad, span<const uint8_t> nonce,
                              span<uint8_t> encrypted_footer) override;

  [[nodiscard]] int32_t CiphertextLength(int64_t plaintext_len) const override;

  ~DLLEncryptor();

  std::string column_name_;
  Type::type data_type_;
  Compression::type compression_type_;
  Encoding::type encoding_;
  std::string ext_column_key_;
  std::string user_id_;
  std::string app_context_;
  std::unique_ptr<AesEncryptorImpl> aes_encryptor_;
};

}  // namespace parquet::encryption 