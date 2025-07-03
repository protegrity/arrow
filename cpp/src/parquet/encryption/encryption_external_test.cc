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

#include <gtest/gtest.h>
#include <string_view>
#include "arrow/util/span.h"
#include "parquet/encryption/encryption_internal.h"

namespace parquet::encryption::external {

class TestExternalEncryption : public ::testing::Test {
 protected:
  int32_t key_length_;
  std::string key_;
  std::string aad_;
  std::string plain_text_;

  std::string column_name_;
  Type::type data_type_;
  Compression::type compression_type_;
  Encoding::type encoding_;
  std::string ext_column_key_;
  std::string user_id_;
  std::string app_context_;
  bool metadata_;
  bool write_length_;

  void SetUp() override {
    key_length_ = 16;
    key_ = "1234567890123450";
    aad_ = "abcdefgh";
    plain_text_ =
        "Apache Parquet is an open source, column-oriented data file format designed for "
        "efficient data storage and retrieval";

    column_name_ = "test_column";
    data_type_ = Type::BYTE_ARRAY;
    compression_type_ = Compression::UNCOMPRESSED;
    encoding_ = Encoding::PLAIN;
    ext_column_key_ = "external_key";
    user_id_ = "user_123";
    app_context_ = "app_context";
    metadata_ = false;
    write_length_ = true;
  }

  static ::arrow::util::span<const uint8_t> str2span(const std::string& s) {
    return ::arrow::util::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(s.data()), s.size());
  }

  void EncryptionRoundTrip(ParquetCipher::type cipher_type, bool write_length) {
    ExternalEncryptorImpl encryptor(
      cipher_type,
      key_length_,
      column_name_,
      data_type_,
      compression_type_,
      encoding_,
      ext_column_key_,
      user_id_,
      app_context_,
      metadata_,
      write_length);

    int32_t expected_ciphertext_len =
        encryptor.CiphertextLength(static_cast<int64_t>(plain_text_.size()));

    std::vector<uint8_t> ciphertext(expected_ciphertext_len, 0);

    int32_t ciphertext_length = encryptor.Encrypt(
        str2span(plain_text_), str2span(key_), str2span(aad_), ciphertext);

    ASSERT_EQ(ciphertext_length, expected_ciphertext_len);

    // Fix here: use correct constructor for ExternalDecryptorImpl (adjust arguments)
    ExternalDecryptorImpl decryptor(
      cipher_type,
      key_length_,
      metadata_,
      write_length);

    int32_t expected_plaintext_length = decryptor.PlaintextLength(ciphertext_length);

    std::vector<uint8_t> decrypted_text(expected_plaintext_length, 0);

    int32_t plaintext_length =
        decryptor.Decrypt(ciphertext, str2span(key_), str2span(aad_), decrypted_text);

    std::string decrypted_text_str(decrypted_text.begin(), decrypted_text.end());

    ASSERT_EQ(plaintext_length, static_cast<int32_t>(plain_text_.size()));
    ASSERT_EQ(plaintext_length, expected_plaintext_length);
    ASSERT_EQ(decrypted_text_str, plain_text_);
  }
};

TEST_F(TestExternalEncryption, AesGcmRoundTrip) {
  EncryptionRoundTrip(ParquetCipher::EXTERNAL_V1, /*write_length=*/true);
  EncryptionRoundTrip(ParquetCipher::EXTERNAL_V1, /*write_length=*/false);
}

}  // namespace parquet::encryption::external