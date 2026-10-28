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
//
// Self-contained tests that generate and read encrypted files in a local
// temporary directory, without relying on parquet-testing data files.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "arrow/io/file.h"
#include "arrow/util/compression.h"

#include "parquet/encryption/encryption.h"
#include "parquet/encryption/test_encryption_util.h"
#include "parquet/encryption/test_mock_crypto_providers.h"
#include "parquet/file_reader.h"
#include "parquet/metadata.h"

namespace parquet::encryption::test {

class PerColumnEncryption : public ::testing::Test {
 protected:
  std::unique_ptr<TemporaryDir> temp_dir_;
  FileEncryptor encryptor_;
  FileDecryptor decryptor_;

  void SetUp() override { temp_dir_ = temp_data_dir().ValueOrDie(); }
};

namespace {

using ColumnPropertiesMap =
    std::map<std::string, std::shared_ptr<parquet::ColumnEncryptionProperties>>;

std::shared_ptr<parquet::ColumnEncryptionProperties> MakeAesColumn(
    const std::string& name, const ::arrow::util::SecureString& key,
    const std::string& key_id) {
  parquet::ColumnEncryptionProperties::Builder builder(name);
  return builder.key(key)->key_id(key_id)->build();
}

std::shared_ptr<parquet::ColumnEncryptionProperties> MakeExternalColumn(
    const std::string& name, const ::arrow::util::SecureString& key,
    const std::string& key_id) {
  parquet::ColumnEncryptionProperties::Builder builder(name);
  return builder.key(key)
      ->key_id(key_id)
      ->parquet_cipher(parquet::ParquetCipher::EXTERNAL_PROTECT_V1)
      ->build();
}

std::shared_ptr<parquet::ColumnEncryptionProperties> MakeAesColumnWithCipher(
    const std::string& name, const ::arrow::util::SecureString& key,
    const std::string& key_id, parquet::ParquetCipher::type cipher) {
  parquet::ColumnEncryptionProperties::Builder builder(name);
  return builder.key(key)->key_id(key_id)->parquet_cipher(cipher)->build();
}

// double and float use AES; `external_column` is routed to the provider.
ColumnPropertiesMap MakeMixedColumns(const std::string& external_column) {
  auto make = [&](const char* name, const ::arrow::util::SecureString& key,
                  const std::string& key_id) {
    return name == external_column ? MakeExternalColumn(name, key, key_id)
                                   : MakeAesColumn(name, key, key_id);
  };
  ColumnPropertiesMap columns;
  columns[kDoubleFieldName] = make(kDoubleFieldName, kColumnEncryptionKey1, "kc1");
  columns[kFloatFieldName] = make(kFloatFieldName, kColumnEncryptionKey2, "kc2");
  columns[kBooleanFieldName] = make(kBooleanFieldName, kColumnEncryptionKey1, "kc3");
  return columns;
}

std::shared_ptr<parquet::StringKeyIdRetriever> MakeKeyRetriever() {
  auto retriever = std::make_shared<parquet::StringKeyIdRetriever>();
  retriever->PutKey("kf", kFooterEncryptionKey);
  retriever->PutKey("kc1", kColumnEncryptionKey1);
  retriever->PutKey("kc2", kColumnEncryptionKey2);
  retriever->PutKey("kc3", kColumnEncryptionKey1);
  return retriever;
}

std::shared_ptr<parquet::ExternalFileEncryptionProperties> MakeExternalFileProperties(
    const ColumnPropertiesMap& columns, parquet::ParquetCipher::type file_algorithm,
    std::shared_ptr<parquet::ParquetCryptoProvider> provider,
    bool plaintext_footer = false) {
  parquet::ExternalFileEncryptionProperties::Builder builder(kFooterEncryptionKey);
  builder.footer_key_metadata("kf")
      ->encrypted_columns(columns)
      ->algorithm(file_algorithm)
      ->parquet_crypto_provider(std::move(provider));
  if (plaintext_footer) builder.set_plaintext_footer();
  return builder.build_external();
}

std::shared_ptr<parquet::ExternalFileDecryptionProperties> MakeExternalDecryption(
    std::shared_ptr<parquet::ParquetCryptoProvider> provider,
    const std::string& aad_prefix = "") {
  parquet::ExternalFileDecryptionProperties::Builder builder;
  builder.key_retriever(MakeKeyRetriever());
  if (provider != nullptr) {
    builder.parquet_crypto_provider(std::move(provider));
  }
  if (!aad_prefix.empty()) builder.aad_prefix(aad_prefix);
  return builder.build_external();
}

std::unique_ptr<parquet::ParquetFileReader> OpenEncryptedFile(
    const std::string& path,
    std::shared_ptr<parquet::ExternalFileDecryptionProperties> decryption_properties) {
  PARQUET_ASSIGN_OR_THROW(auto source, ::arrow::io::ReadableFile::Open(path));
  auto reader_properties = parquet::default_reader_properties();
  reader_properties.file_decryption_properties(std::move(decryption_properties));
  return parquet::ParquetFileReader::Open(std::move(source), reader_properties);
}

// Only the column that opted in to EXTERNAL_PROTECT_V1 records a per-column algorithm;
// the other encrypted columns carry column crypto metadata without one.
void ExpectPerColumnAlgorithm(parquet::FileMetaData* file_md,
                              const std::string& column_name, bool expect_external) {
  const int column_index = file_md->schema()->ColumnIndex(column_name);
  ASSERT_GE(column_index, 0) << column_name;
  auto crypto_md = file_md->RowGroup(0)->ColumnChunk(column_index)->crypto_metadata();
  ASSERT_NE(crypto_md, nullptr) << column_name;
  EXPECT_EQ(expect_external, crypto_md->is_encryption_algorithm_set()) << column_name;
  if (expect_external) {
    EXPECT_EQ(parquet::ParquetCipher::EXTERNAL_PROTECT_V1,
              crypto_md->encryption_algorithm().algorithm)
        << column_name;
  }
}

// Returns bytes of the right length that are not the plaintext, as a provider holding
// the wrong key would.
class WrongKeyProvider : public XorBlockCryptoProvider {
 public:
  ::arrow::Result<std::vector<uint8_t>> DecryptBlock(std::span<const uint8_t> ciphertext,
                                                     const ParquetCryptoContext&,
                                                     std::span<const uint8_t>,
                                                     std::span<const uint8_t>) override {
    return std::vector<uint8_t>(ciphertext.size(), 0xA5);
  }
};

}  // namespace

TEST_F(PerColumnEncryption, CtrWriteRead) {
  // Build encryption properties: two columns and the footer with different keys,
  // using AES_GCM_CTR_V1.
  std::map<std::string, std::shared_ptr<parquet::ColumnEncryptionProperties>>
      encryption_cols;
  parquet::ColumnEncryptionProperties::Builder col_builder_double(kDoubleFieldName);
  parquet::ColumnEncryptionProperties::Builder col_builder_float(kFloatFieldName);
  col_builder_double.key(kColumnEncryptionKey1)->key_id("kc1");
  col_builder_float.key(kColumnEncryptionKey2)->key_id("kc2");
  encryption_cols[kDoubleFieldName] = col_builder_double.build();
  encryption_cols[kFloatFieldName] = col_builder_float.build();

  parquet::FileEncryptionProperties::Builder file_encryption_builder(
      kFooterEncryptionKey);
  const std::string file_path = temp_dir_->path().ToString() +
                                "rw_encrypt_columns_and_footer_ctr.parquet.encrypted";
  // Write the encrypted file to the temporary location .
  // It uses the built-in synthetic dataset from FileEncryptor (not an external file).
  // The test calls FileEncryptor::EncryptFile(...), which writes fixed data with a
  // predefined schema and values.
  encryptor_.EncryptFile(file_path,
                         file_encryption_builder.footer_key_metadata("kf")
                             ->encrypted_columns(encryption_cols)
                             ->algorithm(parquet::ParquetCipher::AES_GCM_CTR_V1)
                             ->build());

  // Decrypt using key retriever
  auto retriever_1 = std::make_shared<parquet::StringKeyIdRetriever>();
  retriever_1->PutKey("kf", kFooterEncryptionKey);
  retriever_1->PutKey("kc1", kColumnEncryptionKey1);
  retriever_1->PutKey("kc2", kColumnEncryptionKey2);
  parquet::FileDecryptionProperties::Builder dec_builder_1;
  auto dec_props_1 = dec_builder_1.key_retriever(retriever_1)->build();
  EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props_1));
  EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props_1));

  // Decrypt using explicit keys
  std::map<std::string, std::shared_ptr<parquet::ColumnDecryptionProperties>>
      decryption_cols;
  parquet::ColumnDecryptionProperties::Builder decryption_double(kDoubleFieldName);
  parquet::ColumnDecryptionProperties::Builder decryption_float(kFloatFieldName);
  decryption_cols[kDoubleFieldName] =
      decryption_double.key(kColumnEncryptionKey1)->build();
  decryption_cols[kFloatFieldName] = decryption_float.key(kColumnEncryptionKey2)->build();
  parquet::FileDecryptionProperties::Builder dec_builder_3;
  auto dec_props_3 = dec_builder_3.footer_key(kFooterEncryptionKey)
                         ->column_keys(decryption_cols)
                         ->build();
  EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props_3));
  EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props_3));
}

TEST_F(PerColumnEncryption, ExternalProtectV1WriteRead) {
  // Same shape as CtrWriteRead above, but the boolean column is routed to a
  // external ParquetCryptoProvider (EXTERNAL_PROTECT_V1) instead of an AES key,
  // built directly through ExternalFileEncryptionProperties::Builder/
  // ExternalFileDecryptionProperties::Builder -- no CryptoFactory involved.
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  std::map<std::string, std::shared_ptr<parquet::ColumnEncryptionProperties>>
      encryption_cols;
  parquet::ColumnEncryptionProperties::Builder col_builder_double(kDoubleFieldName);
  parquet::ColumnEncryptionProperties::Builder col_builder_float(kFloatFieldName);
  parquet::ColumnEncryptionProperties::Builder col_builder_boolean(kBooleanFieldName);
  col_builder_double.key(kColumnEncryptionKey1)->key_id("kc1");
  col_builder_float.key(kColumnEncryptionKey2)->key_id("kc2");
  // key()/key_id() are still required: they back the column's metadata encryption,
  // which stays on the file-level AES algorithm. Only this column's data pages are
  // overridden to EXTERNAL_PROTECT_V1 below.
  col_builder_boolean.key(kColumnEncryptionKey1)
      ->key_id("kc3")
      ->parquet_cipher(parquet::ParquetCipher::EXTERNAL_PROTECT_V1);
  encryption_cols[kDoubleFieldName] = col_builder_double.build();
  encryption_cols[kFloatFieldName] = col_builder_float.build();
  encryption_cols[kBooleanFieldName] = col_builder_boolean.build();

  parquet::ExternalFileEncryptionProperties::Builder file_encryption_builder(
      kFooterEncryptionKey);
  const std::string file_path =
      temp_dir_->path().ToString() + "rw_encrypt_columns_external_v1.parquet.encrypted";
  encryptor_.EncryptFile(file_path,
                         file_encryption_builder.footer_key_metadata("kf")
                             ->encrypted_columns(encryption_cols)
                             ->algorithm(parquet::ParquetCipher::AES_GCM_CTR_V1)
                             ->parquet_crypto_provider(provider)
                             ->build_external());
  EXPECT_GT(provider->encrypt_block_calls(), 0);

  // Decrypt using key retriever for the AES columns and the same provider for
  // the EXTERNAL_PROTECT_V1 column's data pages.
  auto retriever = std::make_shared<parquet::StringKeyIdRetriever>();
  retriever->PutKey("kf", kFooterEncryptionKey);
  retriever->PutKey("kc1", kColumnEncryptionKey1);
  retriever->PutKey("kc2", kColumnEncryptionKey2);
  retriever->PutKey("kc3", kColumnEncryptionKey1);
  parquet::ExternalFileDecryptionProperties::Builder dec_builder;
  auto dec_props = dec_builder.key_retriever(retriever)
                       ->parquet_crypto_provider(provider)
                       ->build_external();

  // DecryptFile() compares the decrypted data but cannot tell which algorithm each
  // column used, so explicitly verify the on-disk ColumnCryptoMetaData records the
  // per-column EXTERNAL_PROTECT_V1 override. The footer here is
  // AES-encrypted (no set_plaintext_footer()), so reading it at all requires
  // real decryption properties, not a bare ParquetFileReader::Open(source).
  {
    PARQUET_ASSIGN_OR_THROW(auto source, ::arrow::io::ReadableFile::Open(file_path));
    auto reader_properties = parquet::default_reader_properties();
    reader_properties.file_decryption_properties(dec_props);
    auto file_reader = parquet::ParquetFileReader::Open(source, reader_properties);
    auto file_md = file_reader->metadata();
    // With an encrypted footer the file-level algorithm lives in FileCryptoMetaData,
    // not FileMetaData, so encryption_algorithm() would throw here.
    EXPECT_FALSE(file_md->is_encryption_algorithm_set());

    auto col_md = file_md->RowGroup(0)->ColumnChunk(0);  // kBooleanFieldName
    auto crypto_md = col_md->crypto_metadata();
    ASSERT_NE(crypto_md, nullptr);
    ASSERT_TRUE(crypto_md->is_encryption_algorithm_set());
    EXPECT_EQ(crypto_md->encryption_algorithm().algorithm,
              parquet::ParquetCipher::EXTERNAL_PROTECT_V1);
    file_reader->Close();
  }

  EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
  EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));
  EXPECT_GT(provider->decrypt_block_calls(), 0);
}

// With a plaintext footer, FileMetaData carries the file-level algorithm in the clear,
// so a reader can see which cipher the file uses without any key. It must be the
// configured algorithm, not a fixed one.
TEST_F(PerColumnEncryption, PlaintextFooterRecordsConfiguredFileAlgorithm) {
  for (auto algorithm :
       {parquet::ParquetCipher::AES_GCM_V1, parquet::ParquetCipher::AES_GCM_CTR_V1}) {
    SCOPED_TRACE(algorithm == parquet::ParquetCipher::AES_GCM_V1 ? "AES_GCM_V1"
                                                                 : "AES_GCM_CTR_V1");
    std::map<std::string, std::shared_ptr<parquet::ColumnEncryptionProperties>>
        encryption_cols;
    parquet::ColumnEncryptionProperties::Builder col_builder_double(kDoubleFieldName);
    parquet::ColumnEncryptionProperties::Builder col_builder_float(kFloatFieldName);
    col_builder_double.key(kColumnEncryptionKey1)->key_id("kc1");
    col_builder_float.key(kColumnEncryptionKey2)->key_id("kc2");
    encryption_cols[kDoubleFieldName] = col_builder_double.build();
    encryption_cols[kFloatFieldName] = col_builder_float.build();

    parquet::FileEncryptionProperties::Builder file_encryption_builder(
        kFooterEncryptionKey);
    const std::string file_path =
        temp_dir_->path().ToString() + "plaintext_footer_file_algorithm_" +
        std::to_string(static_cast<int>(algorithm)) + ".parquet.encrypted";
    encryptor_.EncryptFile(file_path, file_encryption_builder.footer_key_metadata("kf")
                                          ->encrypted_columns(encryption_cols)
                                          ->set_plaintext_footer()
                                          ->algorithm(algorithm)
                                          ->build());

    // The footer is plaintext, so the file opens without any decryption properties.
    PARQUET_ASSIGN_OR_THROW(auto source, ::arrow::io::ReadableFile::Open(file_path));
    auto file_reader = parquet::ParquetFileReader::Open(source);
    auto file_md = file_reader->metadata();
    ASSERT_TRUE(file_md->is_encryption_algorithm_set());
    EXPECT_EQ(algorithm, file_md->encryption_algorithm().algorithm);
    file_reader->Close();

    auto retriever = std::make_shared<parquet::StringKeyIdRetriever>();
    retriever->PutKey("kf", kFooterEncryptionKey);
    retriever->PutKey("kc1", kColumnEncryptionKey1);
    retriever->PutKey("kc2", kColumnEncryptionKey2);
    parquet::FileDecryptionProperties::Builder dec_builder;
    auto dec_props = dec_builder.key_retriever(retriever)->build();
    EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
  }
}

// Data columns that use different AES algorithms, with keys of the same length, must each
// be encrypted by an encryptor for their own algorithm: sharing one by key length alone
// would write a column in the wrong mode and it would fail to decrypt.
TEST_F(PerColumnEncryption, MixedAesAlgorithmsSameKeyLengthWriteRead) {
  for (auto file_algorithm :
       {parquet::ParquetCipher::AES_GCM_V1, parquet::ParquetCipher::AES_GCM_CTR_V1}) {
    const auto column_algorithm = file_algorithm == parquet::ParquetCipher::AES_GCM_V1
                                      ? parquet::ParquetCipher::AES_GCM_CTR_V1
                                      : parquet::ParquetCipher::AES_GCM_V1;
    SCOPED_TRACE("file algorithm " + std::to_string(static_cast<int>(file_algorithm)));
    ASSERT_EQ(kColumnEncryptionKey1.size(), kColumnEncryptionKey2.size());

    // double_field overrides the file algorithm; float_field follows it.
    parquet::ColumnEncryptionProperties::Builder col_builder_double(kDoubleFieldName);
    parquet::ColumnEncryptionProperties::Builder col_builder_float(kFloatFieldName);
    col_builder_double.key(kColumnEncryptionKey1)
        ->key_id("kc1")
        ->parquet_cipher(column_algorithm);
    col_builder_float.key(kColumnEncryptionKey2)->key_id("kc2");
    std::map<std::string, std::shared_ptr<parquet::ColumnEncryptionProperties>>
        encryption_cols;
    encryption_cols[kDoubleFieldName] = col_builder_double.build();
    encryption_cols[kFloatFieldName] = col_builder_float.build();

    parquet::FileEncryptionProperties::Builder file_encryption_builder(
        kFooterEncryptionKey);
    const std::string file_path = temp_dir_->path().ToString() + "mixed_aes_algorithms_" +
                                  std::to_string(static_cast<int>(file_algorithm)) +
                                  ".parquet.encrypted";
    encryptor_.EncryptFile(file_path, file_encryption_builder.footer_key_metadata("kf")
                                          ->encrypted_columns(encryption_cols)
                                          ->algorithm(file_algorithm)
                                          ->build());

    auto retriever = std::make_shared<parquet::StringKeyIdRetriever>();
    retriever->PutKey("kf", kFooterEncryptionKey);
    retriever->PutKey("kc1", kColumnEncryptionKey1);
    retriever->PutKey("kc2", kColumnEncryptionKey2);
    parquet::FileDecryptionProperties::Builder dec_builder;
    auto dec_props = dec_builder.key_retriever(retriever)->build();

    // Only the overriding column records its own algorithm.
    {
      PARQUET_ASSIGN_OR_THROW(auto source, ::arrow::io::ReadableFile::Open(file_path));
      auto reader_properties = parquet::default_reader_properties();
      reader_properties.file_decryption_properties(dec_props);
      auto file_reader = parquet::ParquetFileReader::Open(source, reader_properties);
      auto file_md = file_reader->metadata();
      auto double_md = file_md->RowGroup(0)->ColumnChunk(
          file_md->schema()->ColumnIndex(kDoubleFieldName));
      auto float_md = file_md->RowGroup(0)->ColumnChunk(
          file_md->schema()->ColumnIndex(kFloatFieldName));
      ASSERT_NE(double_md->crypto_metadata(), nullptr);
      ASSERT_NE(float_md->crypto_metadata(), nullptr);
      ASSERT_TRUE(double_md->crypto_metadata()->is_encryption_algorithm_set());
      EXPECT_EQ(column_algorithm,
                double_md->crypto_metadata()->encryption_algorithm().algorithm);
      EXPECT_FALSE(float_md->crypto_metadata()->is_encryption_algorithm_set());
      file_reader->Close();
    }

    EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
    EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));
  }
}

// A column with its own EXTERNAL_PROTECT_V1 cipher in a plaintext-footer file records
// that algorithm in its ColumnCryptoMetaData, together with the file-wide AAD fields,
// while the file-level algorithm stays the one configured for the file.
TEST_F(PerColumnEncryption, PlaintextFooterPerColumnExternalRecordsAlgorithmAndAad) {
  for (bool store_aad_prefix : {true, false}) {
    SCOPED_TRACE(store_aad_prefix ? "aad_prefix stored in file"
                                  : "aad_prefix supplied by reader");
    auto provider = std::make_shared<XorBlockCryptoProvider>();
    const std::string aad_prefix = "tester";
    auto columns = MakeMixedColumns(kBooleanFieldName);

    parquet::ExternalFileEncryptionProperties::Builder file_encryption_builder(
        kFooterEncryptionKey);
    file_encryption_builder.footer_key_metadata("kf")
        ->encrypted_columns(columns)
        ->set_plaintext_footer()
        ->algorithm(parquet::ParquetCipher::AES_GCM_CTR_V1)
        ->aad_prefix(aad_prefix)
        ->parquet_crypto_provider(provider);
    if (!store_aad_prefix) file_encryption_builder.disable_aad_prefix_storage();
    const std::string file_path =
        temp_dir_->path().ToString() + "plaintext_footer_per_column_external_" +
        (store_aad_prefix ? "stored" : "supplied") + ".parquet.encrypted";
    encryptor_.EncryptFile(file_path, file_encryption_builder.build_external());

    auto dec_props = MakeExternalDecryption(provider, store_aad_prefix ? "" : aad_prefix);

    {
      auto file_reader = OpenEncryptedFile(file_path, dec_props);
      auto file_md = file_reader->metadata();
      ASSERT_TRUE(file_md->is_encryption_algorithm_set());
      auto file_algo = file_md->encryption_algorithm();
      EXPECT_EQ(parquet::ParquetCipher::AES_GCM_CTR_V1, file_algo.algorithm);
      EXPECT_FALSE(file_algo.aad.aad_file_unique.empty());

      auto crypto_md = file_md->RowGroup(0)->ColumnChunk(0)->crypto_metadata();
      ASSERT_NE(crypto_md, nullptr);
      ASSERT_TRUE(crypto_md->is_encryption_algorithm_set());
      auto col_algo = crypto_md->encryption_algorithm();
      EXPECT_EQ(parquet::ParquetCipher::EXTERNAL_PROTECT_V1, col_algo.algorithm);
      EXPECT_EQ(file_algo.aad.aad_file_unique, col_algo.aad.aad_file_unique);
      EXPECT_EQ(file_algo.aad.supply_aad_prefix, col_algo.aad.supply_aad_prefix);
      EXPECT_EQ(!store_aad_prefix, col_algo.aad.supply_aad_prefix);
      EXPECT_EQ(store_aad_prefix ? aad_prefix : std::string(), col_algo.aad.aad_prefix);
      file_reader->Close();
    }

    EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
    EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));
    EXPECT_GT(provider->decrypt_block_calls(), 0);
  }
}

// With a file-level EXTERNAL_PROTECT_V1, a column that sets its own AES cipher encrypts
// its data pages itself and records that cipher; the footer and every column's metadata
// still go to the provider. This holds for an encrypted and a plaintext footer.
TEST_F(PerColumnEncryption, FileLevelExternalWithGcmCtrAndExternalColumns) {
  for (bool plaintext_footer : {false, true}) {
    SCOPED_TRACE(plaintext_footer ? "plaintext footer" : "encrypted footer");
    auto provider = std::make_shared<XorBlockCryptoProvider>();

    ColumnPropertiesMap columns;
    columns[kDoubleFieldName] =
        MakeAesColumnWithCipher(kDoubleFieldName, kColumnEncryptionKey1, "kc1",
                                parquet::ParquetCipher::AES_GCM_V1);
    columns[kFloatFieldName] =
        MakeAesColumnWithCipher(kFloatFieldName, kColumnEncryptionKey2, "kc2",
                                parquet::ParquetCipher::AES_GCM_CTR_V1);
    columns[kBooleanFieldName] =
        MakeExternalColumn(kBooleanFieldName, kColumnEncryptionKey1, "kc3");

    const std::string file_path =
        temp_dir_->path().ToString() + "file_level_external_gcm_ctr_external_" +
        (plaintext_footer ? "plaintext" : "encrypted") + ".parquet.encrypted";
    encryptor_.EncryptFile(
        file_path,
        MakeExternalFileProperties(columns, parquet::ParquetCipher::EXTERNAL_PROTECT_V1,
                                   provider, plaintext_footer));

    auto dec_props = MakeExternalDecryption(provider);
    {
      auto file_reader = OpenEncryptedFile(file_path, dec_props);
      auto file_md = file_reader->metadata();
      EXPECT_EQ(plaintext_footer, file_md->is_encryption_algorithm_set());
      if (plaintext_footer) {
        EXPECT_EQ(parquet::ParquetCipher::EXTERNAL_PROTECT_V1,
                  file_md->encryption_algorithm().algorithm);
      }

      const std::pair<const char*, parquet::ParquetCipher::type> expected[] = {
          {kDoubleFieldName, parquet::ParquetCipher::AES_GCM_V1},
          {kFloatFieldName, parquet::ParquetCipher::AES_GCM_CTR_V1},
          {kBooleanFieldName, parquet::ParquetCipher::EXTERNAL_PROTECT_V1}};
      for (const auto& [column_name, cipher] : expected) {
        const int column_index = file_md->schema()->ColumnIndex(column_name);
        ASSERT_GE(column_index, 0) << column_name;
        auto crypto_md =
            file_md->RowGroup(0)->ColumnChunk(column_index)->crypto_metadata();
        ASSERT_NE(crypto_md, nullptr) << column_name;
        ASSERT_TRUE(crypto_md->is_encryption_algorithm_set()) << column_name;
        EXPECT_EQ(cipher, crypto_md->encryption_algorithm().algorithm) << column_name;
      }
      file_reader->Close();
    }

    EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
    EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));

    // All three columns' metadata reach the provider, and so does an encrypted footer
    // (empty column path). A signed footer goes through SignFooter(), which has no
    // context to record.
    std::set<std::string> paths;
    for (const auto& ctx : provider->seen_contexts()) paths.insert(ctx.column_path);
    EXPECT_EQ(plaintext_footer ? 0u : 1u, paths.count(""));
    EXPECT_EQ(1u, paths.count(kDoubleFieldName));
    EXPECT_EQ(1u, paths.count(kFloatFieldName));
    EXPECT_EQ(1u, paths.count(kBooleanFieldName));
  }
}

// The provider must only ever see the column that opted in to EXTERNAL_PROTECT_V1,
// never the AES columns next to it, and the file-level algorithm may be AES_GCM_V1
// (the CryptoFactory default) as well as AES_GCM_CTR_V1.
TEST_F(PerColumnEncryption, ExternalColumnIsIsolatedFromAesColumnsBlockPath) {
  for (auto file_algorithm :
       {parquet::ParquetCipher::AES_GCM_V1, parquet::ParquetCipher::AES_GCM_CTR_V1}) {
    SCOPED_TRACE(file_algorithm == parquet::ParquetCipher::AES_GCM_V1 ? "AES_GCM_V1"
                                                                      : "AES_GCM_CTR_V1");
    auto provider = std::make_shared<XorBlockCryptoProvider>();
    auto columns = MakeMixedColumns(kBooleanFieldName);

    const std::string file_path = temp_dir_->path().ToString() + "isolated_block_" +
                                  std::to_string(static_cast<int>(file_algorithm)) +
                                  ".parquet.encrypted";
    encryptor_.EncryptFile(file_path,
                           MakeExternalFileProperties(columns, file_algorithm, provider));
    EXPECT_GT(provider->encrypt_block_calls(), 0);

    auto dec_props = MakeExternalDecryption(provider);
    {
      auto file_reader = OpenEncryptedFile(file_path, dec_props);
      auto file_md = file_reader->metadata();
      ExpectPerColumnAlgorithm(file_md.get(), kBooleanFieldName, true);
      ExpectPerColumnAlgorithm(file_md.get(), kDoubleFieldName, false);
      ExpectPerColumnAlgorithm(file_md.get(), kFloatFieldName, false);
      file_reader->Close();
    }
    EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
    EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));

    // Covers both the write and the read calls.
    const auto contexts = provider->seen_contexts();
    ASSERT_FALSE(contexts.empty());
    for (const auto& ctx : contexts) {
      EXPECT_EQ(kBooleanFieldName, ctx.column_path);
    }
  }
}

TEST_F(PerColumnEncryption, ExternalColumnIsIsolatedFromAesColumnsCellPath) {
  for (ParquetDataPageVersion page_version :
       {ParquetDataPageVersion::V1, ParquetDataPageVersion::V2}) {
    SCOPED_TRACE(page_version == ParquetDataPageVersion::V2 ? "DataPageV2"
                                                            : "DataPageV1");
    auto provider = std::make_shared<XorTypedValuesCryptoProvider>();
    auto columns = MakeMixedColumns(kBooleanFieldName);

    FileEncryptor cell_path_encryptor(/*disable_dictionary_encoding=*/true,
                                      /*compression=*/Compression::UNCOMPRESSED,
                                      /*data_page_version=*/page_version);
    const std::string file_path =
        temp_dir_->path().ToString() + (page_version == ParquetDataPageVersion::V2
                                            ? "isolated_cell_v2.parquet"
                                            : "isolated_cell_v1.parquet");
    cell_path_encryptor.EncryptFile(
        file_path, MakeExternalFileProperties(columns, parquet::ParquetCipher::AES_GCM_V1,
                                              provider));
    EXPECT_GT(provider->encrypt_cells_calls(), 0);

    auto dec_props = MakeExternalDecryption(provider);
    {
      auto file_reader = OpenEncryptedFile(file_path, dec_props);
      auto file_md = file_reader->metadata();
      ExpectPerColumnAlgorithm(file_md.get(), kBooleanFieldName, true);
      ExpectPerColumnAlgorithm(file_md.get(), kDoubleFieldName, false);
      ExpectPerColumnAlgorithm(file_md.get(), kFloatFieldName, false);
      file_reader->Close();
    }
    EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
    EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));
    EXPECT_GT(provider->decrypt_cells_calls(), 0);
  }
}

// A reader without a provider can still read the AES columns of a file that also has an
// EXTERNAL_PROTECT_V1 column; only the external column is unreadable.
TEST_F(PerColumnEncryption, ReadingAesColumnsDoesNotRequireProvider) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  auto columns = MakeMixedColumns(kBooleanFieldName);

  const std::string file_path =
      temp_dir_->path().ToString() + "read_without_provider.parquet.encrypted";
  encryptor_.EncryptFile(
      file_path,
      MakeExternalFileProperties(columns, parquet::ParquetCipher::AES_GCM_V1, provider));

  auto file_reader = OpenEncryptedFile(file_path, MakeExternalDecryption(nullptr));
  auto row_group = file_reader->RowGroup(0);
  const auto* schema = file_reader->metadata()->schema();

  constexpr int64_t kBatchSize = 10;
  int16_t def_levels[kBatchSize];
  int16_t rep_levels[kBatchSize];
  int64_t values_read = 0;

  auto double_reader = std::static_pointer_cast<parquet::DoubleReader>(
      row_group->Column(schema->ColumnIndex(kDoubleFieldName)));
  double doubles[kBatchSize];
  EXPECT_EQ(kBatchSize, double_reader->ReadBatch(kBatchSize, def_levels, rep_levels,
                                                 doubles, &values_read));
  EXPECT_EQ(kBatchSize, values_read);

  auto float_reader = std::static_pointer_cast<parquet::FloatReader>(
      row_group->Column(schema->ColumnIndex(kFloatFieldName)));
  float floats[kBatchSize];
  EXPECT_EQ(kBatchSize, float_reader->ReadBatch(kBatchSize, def_levels, rep_levels,
                                                floats, &values_read));
  EXPECT_EQ(kBatchSize, values_read);

  EXPECT_THAT(
      [&] {
        auto boolean_reader = std::static_pointer_cast<parquet::BoolReader>(
            row_group->Column(schema->ColumnIndex(kBooleanFieldName)));
        bool booleans[kBatchSize];
        boolean_reader->ReadBatch(kBatchSize, def_levels, rep_levels, booleans,
                                  &values_read);
      },
      ::testing::ThrowsMessage<ParquetException>(
          ::testing::HasSubstr("parquet_crypto_provider must be set")));
  file_reader->Close();
}

// Every encrypted column is EXTERNAL_PROTECT_V1 (no AES data column); columns that were
// not configured stay in plaintext.
TEST_F(PerColumnEncryption, AllEncryptedColumnsExternalWriteRead) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ColumnPropertiesMap columns;
  columns[kDoubleFieldName] =
      MakeExternalColumn(kDoubleFieldName, kColumnEncryptionKey1, "kc1");
  columns[kFloatFieldName] =
      MakeExternalColumn(kFloatFieldName, kColumnEncryptionKey2, "kc2");
  columns[kBooleanFieldName] =
      MakeExternalColumn(kBooleanFieldName, kColumnEncryptionKey1, "kc3");

  const std::string file_path =
      temp_dir_->path().ToString() + "all_external.parquet.encrypted";
  encryptor_.EncryptFile(file_path,
                         MakeExternalFileProperties(
                             columns, parquet::ParquetCipher::AES_GCM_CTR_V1, provider));

  auto dec_props = MakeExternalDecryption(provider);
  {
    auto file_reader = OpenEncryptedFile(file_path, dec_props);
    auto file_md = file_reader->metadata();
    ExpectPerColumnAlgorithm(file_md.get(), kBooleanFieldName, true);
    ExpectPerColumnAlgorithm(file_md.get(), kDoubleFieldName, true);
    ExpectPerColumnAlgorithm(file_md.get(), kFloatFieldName, true);
    const int int32_index = file_md->schema()->ColumnIndex(kInt32FieldName);
    EXPECT_EQ(nullptr, file_md->RowGroup(0)->ColumnChunk(int32_index)->crypto_metadata());
    file_reader->Close();
  }
  EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
  EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));

  std::set<std::string> seen_columns;
  for (const auto& ctx : provider->seen_contexts()) {
    seen_columns.insert(ctx.column_path);
  }
  EXPECT_EQ((std::set<std::string>{kBooleanFieldName, kDoubleFieldName, kFloatFieldName}),
            seen_columns);
}

// The block path hands the provider compressed pages; the cell path has to decompress
// and recompress around the provider call.
TEST_F(PerColumnEncryption, CompressedPagesBlockAndCellPath) {
  int codecs_tested = 0;
  for (auto codec : {Compression::GZIP, Compression::ZSTD, Compression::SNAPPY}) {
    if (!::arrow::util::Codec::IsAvailable(codec)) continue;
    ++codecs_tested;
    for (bool cell_path : {false, true}) {
      SCOPED_TRACE(std::string(cell_path ? "cell path, codec " : "block path, codec ") +
                   std::to_string(static_cast<int>(codec)));
      auto block_provider = std::make_shared<XorBlockCryptoProvider>();
      auto typed_provider = std::make_shared<XorTypedValuesCryptoProvider>();
      std::shared_ptr<parquet::ParquetCryptoProvider> provider =
          cell_path ? std::shared_ptr<parquet::ParquetCryptoProvider>(typed_provider)
                    : block_provider;

      FileEncryptor compressed_encryptor(/*disable_dictionary_encoding=*/true, codec);
      const std::string file_path = temp_dir_->path().ToString() + "compressed_" +
                                    std::to_string(static_cast<int>(codec)) +
                                    (cell_path ? "_cell" : "_block") +
                                    ".parquet.encrypted";
      compressed_encryptor.EncryptFile(
          file_path,
          MakeExternalFileProperties(MakeMixedColumns(kBooleanFieldName),
                                     parquet::ParquetCipher::AES_GCM_V1, provider));

      auto dec_props = MakeExternalDecryption(provider);
      EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
      EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));
      if (cell_path) {
        EXPECT_GT(typed_provider->encrypt_cells_calls(), 0);
        EXPECT_GT(typed_provider->decrypt_cells_calls(), 0);
      } else {
        EXPECT_GT(block_provider->encrypt_block_calls(), 0);
        EXPECT_GT(block_provider->decrypt_block_calls(), 0);
      }
    }
  }
  if (codecs_tested == 0) GTEST_SKIP() << "No compression codec is available";
}

// A plaintext footer with a provider column, for each file-level algorithm and both
// paths. The footer stays readable without keys and the provider is only used for the
// opted-in column.
TEST_F(PerColumnEncryption, PlaintextFooterExternalColumnAllFileAlgorithmsAndPaths) {
  for (auto algorithm :
       {parquet::ParquetCipher::AES_GCM_V1, parquet::ParquetCipher::AES_GCM_CTR_V1}) {
    for (bool cell_path : {false, true}) {
      SCOPED_TRACE(std::string(algorithm == parquet::ParquetCipher::AES_GCM_V1
                                   ? "AES_GCM_V1"
                                   : "AES_GCM_CTR_V1") +
                   (cell_path ? ", cell path" : ", block path"));
      auto block_provider = std::make_shared<XorBlockCryptoProvider>();
      auto typed_provider = std::make_shared<XorTypedValuesCryptoProvider>();
      std::shared_ptr<parquet::ParquetCryptoProvider> provider =
          cell_path ? std::shared_ptr<parquet::ParquetCryptoProvider>(typed_provider)
                    : block_provider;

      FileEncryptor plain_encryptor(/*disable_dictionary_encoding=*/true);
      const std::string file_path =
          temp_dir_->path().ToString() + "plaintext_footer_external_" +
          std::to_string(static_cast<int>(algorithm)) + (cell_path ? "_cell" : "_block") +
          ".parquet.encrypted";
      plain_encryptor.EncryptFile(
          file_path, MakeExternalFileProperties(MakeMixedColumns(kBooleanFieldName),
                                                algorithm, provider,
                                                /*plaintext_footer=*/true));

      {
        // No decryption properties: only the plaintext footer is needed.
        PARQUET_ASSIGN_OR_THROW(auto source, ::arrow::io::ReadableFile::Open(file_path));
        auto file_reader = parquet::ParquetFileReader::Open(source);
        ASSERT_TRUE(file_reader->metadata()->is_encryption_algorithm_set());
        EXPECT_EQ(algorithm, file_reader->metadata()->encryption_algorithm().algorithm);
        file_reader->Close();
      }

      auto dec_props = MakeExternalDecryption(provider);
      EXPECT_NO_THROW(decryptor_.DecryptFile(file_path, dec_props));
      EXPECT_NO_THROW(decryptor_.DecryptPageIndex(file_path, dec_props));
      if (cell_path) {
        EXPECT_GT(typed_provider->encrypt_cells_calls(), 0);
        EXPECT_GT(typed_provider->decrypt_cells_calls(), 0);
      } else {
        EXPECT_GT(block_provider->encrypt_block_calls(), 0);
        EXPECT_GT(block_provider->decrypt_block_calls(), 0);
        for (const auto& ctx : block_provider->seen_contexts()) {
          EXPECT_EQ(kBooleanFieldName, ctx.column_path);
        }
      }
    }
  }
}

// A provider holding the wrong key returns bytes of the right length that are not the
// plaintext. A compressed page cannot be decompressed from such bytes, so the read
// fails instead of returning wrong values.
TEST_F(PerColumnEncryption, ProviderWithWrongKeyFailsToReadCompressedPages) {
  if (!::arrow::util::Codec::IsAvailable(Compression::GZIP)) {
    GTEST_SKIP() << "GZIP is not available";
  }
  FileEncryptor compressed_encryptor(/*disable_dictionary_encoding=*/true,
                                     Compression::GZIP);
  const std::string file_path =
      temp_dir_->path().ToString() + "wrong_key.parquet.encrypted";
  compressed_encryptor.EncryptFile(
      file_path, MakeExternalFileProperties(MakeMixedColumns(kBooleanFieldName),
                                            parquet::ParquetCipher::AES_GCM_V1,
                                            std::make_shared<XorBlockCryptoProvider>()));

  auto dec_props = MakeExternalDecryption(std::make_shared<WrongKeyProvider>());
  EXPECT_THROW(decryptor_.DecryptFile(file_path, dec_props), ParquetException);
}

// When the AAD prefix is not stored in the file, the reader has to supply the same one.
TEST_F(PerColumnEncryption, UnstoredAadPrefixMissingOrWrongPrefixFailsTheRead) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  parquet::ExternalFileEncryptionProperties::Builder file_encryption_builder(
      kFooterEncryptionKey);
  const std::string file_path =
      temp_dir_->path().ToString() + "unstored_aad_prefix.parquet.encrypted";
  encryptor_.EncryptFile(file_path,
                         file_encryption_builder.footer_key_metadata("kf")
                             ->encrypted_columns(MakeMixedColumns(kBooleanFieldName))
                             ->algorithm(parquet::ParquetCipher::AES_GCM_V1)
                             ->aad_prefix("tester")
                             ->disable_aad_prefix_storage()
                             ->parquet_crypto_provider(provider)
                             ->build_external());

  EXPECT_NO_THROW(
      decryptor_.DecryptFile(file_path, MakeExternalDecryption(provider, "tester")));
  EXPECT_THROW(decryptor_.DecryptFile(file_path, MakeExternalDecryption(provider)),
               ParquetException);
  EXPECT_THROW(
      decryptor_.DecryptFile(file_path, MakeExternalDecryption(provider, "other")),
      ParquetException);
}

}  // namespace parquet::encryption::test
