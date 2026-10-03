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
// Full read/write round-trip tests for ParquetCryptoProvider (EXTERNAL_PROTECT_V1)
// using the XOR mock providers. Covers both the block path (XorBlockCryptoProvider)
// and the cell path (XorTypedValuesCryptoProvider) through real Parquet files.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "arrow/buffer.h"
#include "arrow/testing/gtest_util.h"
#include "arrow/util/secure_string.h"

#include "parquet/encryption/crypto_factory.h"
#include "parquet/encryption/encoding_properties.h"
#include "parquet/encryption/encryption_utils.h"
#include "parquet/encryption/parquet_crypto_provider_adapter_internal.h"
#include "parquet/encryption/test_encryption_util.h"
#include "parquet/encryption/test_in_memory_kms.h"
#include "parquet/encryption/test_mock_crypto_providers.h"

using ::testing::HasSubstr;

namespace parquet::encryption::test {

class ParquetColumnCryptoProviderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    temp_dir_ = temp_data_dir().ValueOrDie();
    key_list_ = BuildKeyMap(kColumnMasterKeyIds, kColumnMasterKeys, kFooterMasterKeyId,
                            kFooterMasterKey);
    crypto_factory_.RegisterKmsClientFactory(
        std::make_shared<TestOnlyInMemoryKmsClientFactory>(true, key_list_));
  }

  std::string TempFilePath(const std::string& name) {
    return temp_dir_->path().ToString() + name;
  }

  std::unique_ptr<TemporaryDir> temp_dir_;
  std::unordered_map<std::string, ::arrow::util::SecureString> key_list_;
  KmsConnectionConfig kms_config_;
  CryptoFactory crypto_factory_;
};

// The mock's XOR transform is proven self-inverse independent of the
// Parquet read/write pipeline, so a bug in the mock cannot masquerade as a
// passing integration test below.
TEST(XorBlockCryptoProviderMockTest, EncryptDecryptRoundTripIsSelfInverse) {
  XorBlockCryptoProvider provider;
  const std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
  ParquetCryptoContext ctx;

  ASSERT_OK_AND_ASSIGN(auto ciphertext, provider.EncryptBlock(plaintext, ctx, {}, {}));
  EXPECT_NE(ciphertext, plaintext);

  ASSERT_OK_AND_ASSIGN(auto round_trip, provider.DecryptBlock(ciphertext, ctx, {}, {}));
  EXPECT_EQ(round_trip, plaintext);
}

// Basic block-path mechanics: EncryptBlock()/DecryptBlock() are called and
// round-trip correctly.

// EncryptBlock is called on write when the file's algorithm is
// EXTERNAL_PROTECT_V1.
TEST_F(ParquetColumnCryptoProviderTest, EncryptBlockCalledOnWrite) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration config(kFooterMasterKeyId);
  // column_keys gives each column its own key_metadata. uniform_encryption
  // would encrypt every column with the footer key instead, which is an
  // invalid combination for EXTERNAL_PROTECT_V1.
  config.column_keys = BuildColumnKeyMapping();
  config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props =
      crypto_factory_.GetExternalFileEncryptionProperties(kms_config_, config, provider);
  ASSERT_NE(encryption_props, nullptr);

  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(
      TempFilePath("encrypt_block_called_on_write.parquet"), encryption_props));

  EXPECT_GT(provider->encrypt_block_calls(), 0);
}

// A file encrypted through the block path decrypts back to the original data.
TEST_F(ParquetColumnCryptoProviderTest, BlockPathRoundTrip) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("block_path_round_trip.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  // FileDecryptor::DecryptFile() asserts the read-back values match what
  // FileEncryptor wrote, so a successful call here is a real correctness check,
  // not just "no exception thrown".
  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_block_calls(), 0);
}

// A file with no ParquetCryptoProvider (plain AES_GCM_V1) is unaffected by the
// EXTERNAL_PROTECT_V1 dispatch code added alongside it.
TEST_F(ParquetColumnCryptoProviderTest, NullProviderKeepsAesPathWorking) {
  EncryptionConfiguration config(kFooterMasterKeyId);
  config.uniform_encryption = true;
  auto encryption_props =
      crypto_factory_.GetFileEncryptionProperties(kms_config_, config);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("null_provider_aes_path.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  DecryptionConfiguration dec_config;
  auto decryption_props =
      crypto_factory_.GetFileDecryptionProperties(kms_config_, dec_config);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));
}

// Object lifetime: the provider must stay alive for as long as the
// properties object that references it.

// The properties object (not the caller's local shared_ptr) must be what keeps
// the provider alive. Dropping the caller's reference before encrypting would
// surface as a use-after-free under ASAN if the adapter only held a raw pointer.
TEST_F(ParquetColumnCryptoProviderTest, ProviderLifetimeOutlivesLocalReference) {
  std::shared_ptr<parquet::FileEncryptionProperties> encryption_props;
  {
    auto provider = std::make_shared<XorBlockCryptoProvider>();
    ExternalEncryptionConfiguration config(kFooterMasterKeyId);
    config.column_keys = BuildColumnKeyMapping();
    config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
    encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
        kms_config_, config, provider);
    // `provider` goes out of scope here; encryption_props must hold its own
    // shared_ptr to keep the object alive for the encrypt below.
  }
  ASSERT_NE(encryption_props, nullptr);

  FileEncryptor encryptor;
  EXPECT_NO_THROW(
      encryptor.EncryptFile(TempFilePath("provider_lifetime.parquet"), encryption_props));
}

// Full-file coverage: footer, column metadata, and data pages all route
// through the provider together.

// A full-file round trip — footer, column metadata, and data pages all
// route through the provider (column_keys covers every module: the footer key
// plus one distinct key per column), the resolved DEK is forwarded on every
// call, and no cell-path methods are invoked for a block-path-only provider,
// on both write and read.
TEST_F(ParquetColumnCryptoProviderTest, FullFileRoundTrip) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("full_file_round_trip.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  EXPECT_GT(provider->encrypt_block_calls(), 0);
  EXPECT_GT(provider->calls_with_dek(), 0);
  EXPECT_EQ(provider->encrypt_cells_calls(), 0);

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_block_calls(), 0);
  EXPECT_EQ(provider->decrypt_cells_calls(), 0);
}

// Cell-path full-file coverage: data pages for every physical type route
// through EncryptCells()/DecryptCells() and round-trip correctly, while the
// footer and column metadata (never cell-path eligible) still route through
// EncryptBlock()/DecryptBlock() on the same provider instance.
//
// data_page_version=V2 and disable_dictionary_encoding=true are both required:
// ParquetPageDecoder only supports DataPageV2 + PLAIN value encoding today, so a
// DataPageV1 or dictionary-encoded page (the defaults for this low-cardinality
// test data) always falls back to the block path instead -- see
// DictionaryColumnRoutesIndicesToBlockAndDictionaryToCells below, which covers
// that case (and the real DictionaryPage's own cell-path routing).
TEST_F(ParquetColumnCryptoProviderTest, CellPathFullFileRoundTrip) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  // BuildColumnKeyMapping() covers 6 of the 8 columns; add the repeated int64
  // and the int96 column too, so every physical type -- and the repetition-
  // level round trip -- is exercised through the cell path.
  ColumnEncryptionAttributes int64_attrs;
  int64_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  int64_attrs.key_id = kColumnMasterKeyIds[0];
  enc_config.per_column_encryption[kInt64FieldName] = int64_attrs;
  ColumnEncryptionAttributes int96_attrs;
  int96_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  int96_attrs.key_id = kColumnMasterKeyIds[1];
  enc_config.per_column_encryption[kInt96FieldName] = int96_attrs;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("cell_path_full_file_round_trip.parquet");
  FileEncryptor encryptor(/*disable_dictionary_encoding=*/true,
                          /*compression=*/Compression::UNCOMPRESSED,
                          /*data_page_version=*/ParquetDataPageVersion::V2);
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  // Footer + column metadata always use the block path; every column's data
  // (and, for the repeated int64 column, its levels) uses the cell path.
  EXPECT_GT(provider->encrypt_block_calls(), 0);
  EXPECT_GT(provider->encrypt_cells_calls(), 0);

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  // FileDecryptor::DecryptFile() asserts every column's read-back values match
  // what FileEncryptor wrote -- a real per-physical-type correctness check for
  // the cell path's Decompress()/EncryptCells()/Recompress() round trip, not
  // just "no exception thrown".
  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_block_calls(), 0);
  EXPECT_GT(provider->decrypt_cells_calls(), 0);
}

// Same cell-path coverage as CellPathFullFileRoundTrip, but with
// ParquetDataPageVersion::V1 -- proves ParquetPageDecoder's DataPageV1 buffer
// framing (levels+values compressed as one blob, self-delimiting RLE level
// sections) round-trips correctly through a real file, not just the synthetic
// buffers parquet_page_decoder_test.cc constructs by hand.
TEST_F(ParquetColumnCryptoProviderTest, CellPathFullFileRoundTripDataPageV1) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  ColumnEncryptionAttributes int64_attrs;
  int64_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  int64_attrs.key_id = kColumnMasterKeyIds[0];
  enc_config.per_column_encryption[kInt64FieldName] = int64_attrs;
  ColumnEncryptionAttributes int96_attrs;
  int96_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  int96_attrs.key_id = kColumnMasterKeyIds[1];
  enc_config.per_column_encryption[kInt96FieldName] = int96_attrs;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("cell_path_full_file_round_trip_v1.parquet");
  FileEncryptor encryptor(/*disable_dictionary_encoding=*/true,
                          /*compression=*/Compression::UNCOMPRESSED,
                          /*data_page_version=*/ParquetDataPageVersion::V1);
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  EXPECT_GT(provider->encrypt_block_calls(), 0);
  EXPECT_GT(provider->encrypt_cells_calls(), 0);

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_block_calls(), 0);
  EXPECT_GT(provider->decrypt_cells_calls(), 0);
}

// Same cell-path coverage as CellPathFullFileRoundTrip, but with a real
// compression codec instead of UNCOMPRESSED -- proves Decompress()/
// Recompress() correctly reverse the values-portion codec independently of
// the (always-uncompressed) level bytes.
TEST_F(ParquetColumnCryptoProviderTest, CellPathFullFileRoundTripWithCompressionCodec) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  ColumnEncryptionAttributes int64_attrs;
  int64_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  int64_attrs.key_id = kColumnMasterKeyIds[0];
  enc_config.per_column_encryption[kInt64FieldName] = int64_attrs;
  ColumnEncryptionAttributes int96_attrs;
  int96_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  int96_attrs.key_id = kColumnMasterKeyIds[1];
  enc_config.per_column_encryption[kInt96FieldName] = int96_attrs;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path =
      TempFilePath("cell_path_full_file_round_trip_gzip.parquet");
  FileEncryptor encryptor(/*disable_dictionary_encoding=*/true,
                          /*compression=*/Compression::GZIP,
                          /*data_page_version=*/ParquetDataPageVersion::V2);
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  EXPECT_GT(provider->encrypt_cells_calls(), 0);

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_cells_calls(), 0);
}

// Pins the encoding-aware cell-path gate's behavior for a real dictionary-encoded
// file: UseCellPath() checks both the page type and the on-disk value encoding.
// A dictionary-encoded DataPage's indices (RLE_DICTIONARY, never real values)
// always fall back to EncryptBlock()/DecryptBlock() -- EncryptCells()/
// DecryptCells() must never see them. The DictionaryPage itself is a flat list of
// real (non-index) values, always PLAIN-encoded, and does route through the cell
// path: both paths are exercised by one file, on the same provider instance.
TEST_F(ParquetColumnCryptoProviderTest,
       DictionaryColumnRoutesIndicesToBlockAndDictionaryToCells) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  // disable_dictionary_encoding defaults to false: this column data is low
  // cardinality and small enough to stay dictionary-encoded throughout, so every
  // int32_field/bool_field/etc DataPage holds RLE_DICTIONARY indices, not values.
  const std::string file_path = TempFilePath("cell_path_dictionary_fallback.parquet");
  FileEncryptor encryptor(/*disable_dictionary_encoding=*/false,
                          /*compression=*/Compression::UNCOMPRESSED,
                          /*data_page_version=*/ParquetDataPageVersion::V2);
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  // Footer, column metadata, and every dictionary-encoded DataPage's indices
  // route through the block path; every DictionaryPage routes through the cell
  // path -- both are exercised by this one file.
  EXPECT_GT(provider->encrypt_block_calls(), 0);
  EXPECT_GT(provider->encrypt_cells_calls(), 0);

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_block_calls(), 0);
  EXPECT_GT(provider->decrypt_cells_calls(), 0);
}

// Same as above, for DataPageV1 -- confirms the encoding-aware gate's
// page-version-independence end-to-end, not just at the adapter-unit-test level.
TEST_F(ParquetColumnCryptoProviderTest,
       DictionaryColumnRoutesIndicesToBlockAndDictionaryToCellsV1) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("cell_path_dictionary_fallback_v1.parquet");
  FileEncryptor encryptor(/*disable_dictionary_encoding=*/false,
                          /*compression=*/Compression::UNCOMPRESSED,
                          /*data_page_version=*/ParquetDataPageVersion::V1);
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  EXPECT_GT(provider->encrypt_block_calls(), 0);
  EXPECT_GT(provider->encrypt_cells_calls(), 0);

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  EXPECT_GT(provider->decrypt_block_calls(), 0);
  EXPECT_GT(provider->decrypt_cells_calls(), 0);
}

namespace {
// Checks that the provider was invoked for column_path at all; ParquetCryptoContext
// does not identify which module (data page, column metadata, ...) triggered the call.
bool AnyContext(const std::vector<ParquetCryptoContext>& contexts,
                const std::string& column_path) {
  return std::any_of(contexts.begin(), contexts.end(),
                     [&](const auto& ctx) { return ctx.column_path == column_path; });
}
}  // namespace

// ParquetCryptoContext field propagation: app_context, data_type/datatype_length,
// and the per-page module AAD all reach the provider correctly.

// ExternalEncryptionConfiguration::app_context (write) and
// ExternalDecryptionConfiguration::app_context (read) each reach every
// ParquetCryptoContext the provider sees, independently of each other.
TEST_F(ParquetColumnCryptoProviderTest, AppContextReachesProvider) {
  const std::string kEncAppContext = R"({"user_id": "writer-1"})";
  const std::string kDecAppContext = R"({"user_id": "reader-1"})";

  auto enc_provider = std::make_shared<XorBlockCryptoProvider>();
  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  enc_config.app_context = kEncAppContext;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, enc_provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("app_context.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto enc_contexts = enc_provider->seen_contexts();
  ASSERT_FALSE(enc_contexts.empty());
  for (const auto& ctx : enc_contexts) {
    EXPECT_EQ(ctx.app_context, kEncAppContext);
  }

  auto dec_provider = std::make_shared<XorBlockCryptoProvider>();
  ExternalDecryptionConfiguration dec_config;
  dec_config.app_context = kDecAppContext;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, dec_provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  auto dec_contexts = dec_provider->seen_contexts();
  ASSERT_FALSE(dec_contexts.empty());
  for (const auto& ctx : dec_contexts) {
    EXPECT_EQ(ctx.app_context, kDecAppContext);
  }
}

// ParquetCryptoContext::data_type/datatype_length are populated correctly
// for a FIXED_LEN_BYTE_ARRAY column's data pages.
TEST_F(ParquetColumnCryptoProviderTest, FixedLenByteArrayContextPopulated) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("flba_context.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  // GetColumnMetaEncryptor() doesn't pass column_chunk_metadata, so the
  // column-metadata context's data_type/datatype_length are left at their
  // defaults; only the data-path context has them populated. Filter on that.
  bool found_data_page = false;
  for (const auto& ctx : provider->seen_contexts()) {
    if (ctx.column_path == kFixedLenByteArrayFieldName &&
        ctx.datatype_length.has_value()) {
      EXPECT_EQ(ctx.data_type, Type::FIXED_LEN_BYTE_ARRAY);
      EXPECT_EQ(ctx.datatype_length.value(), kFixedLength);
      found_data_page = true;
    }
  }
  EXPECT_TRUE(found_data_page);
}

// Symmetric to FixedLenByteArrayContextPopulated above, but for the decrypt side:
// a fresh provider instance receives its own ParquetCryptoContext with
// data_type/datatype_length populated when decrypting a FIXED_LEN_BYTE_ARRAY
// column's data pages.
TEST_F(ParquetColumnCryptoProviderTest, FixedLenByteArrayContextPopulatedOnDecrypt) {
  auto enc_provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, enc_provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("flba_context_decrypt.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto dec_provider = std::make_shared<XorBlockCryptoProvider>();
  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, dec_provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));

  bool found_data_page = false;
  for (const auto& ctx : dec_provider->seen_contexts()) {
    if (ctx.column_path == kFixedLenByteArrayFieldName &&
        ctx.datatype_length.has_value()) {
      EXPECT_EQ(ctx.data_type, Type::FIXED_LEN_BYTE_ARRAY);
      EXPECT_EQ(ctx.datatype_length.value(), kFixedLength);
      found_data_page = true;
    }
  }
  EXPECT_TRUE(found_data_page);
}

// Arrow's per-page positional binding (module_aad, from CreateModuleAad())
// reaches the provider on every block-path call and is never empty; distinct
// values appear across the file, proving it actually varies with row group /
// column / page ordinal instead of being a constant placeholder a provider
// could use as an AEAD tag input to detect page reordering or swapping.
TEST_F(ParquetColumnCryptoProviderTest, ModuleAadReachesProviderAndVariesPerCall) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("module_aad.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto module_aads = provider->seen_module_aads();
  ASSERT_FALSE(module_aads.empty());
  for (const auto& aad : module_aads) {
    EXPECT_FALSE(aad.empty());
  }
  std::set<std::vector<uint8_t>> distinct_aads(module_aads.begin(), module_aads.end());
  EXPECT_GT(distinct_aads.size(), 1u);
}

// Per-column configuration: overriding or adding a column's cipher only
// affects that column, and column metadata still follows the file-level
// algorithm independently of a column's data-page override.

// A per_column_encryption override to a non-EXTERNAL_PROTECT_V1 cipher only
// bypasses the provider for that column's data pages. Its column metadata still
// follows the file-level EXTERNAL_PROTECT_V1 algorithm (see
// InternalFileEncryptor::GetColumnEncryptor()), so it still reaches the provider.
// (ParquetCryptoContext does not identify which module reached the provider, so
// this only asserts column-level reachability.)
TEST_F(ParquetColumnCryptoProviderTest, PerColumnCipherOverrideRoutesDataToAes) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;

  ColumnEncryptionAttributes aes_override;
  aes_override.parquet_cipher = ParquetCipher::AES_GCM_CTR_V1;
  aes_override.key_id = kColumnMasterKeyIds[0];
  enc_config.per_column_encryption[kInt64FieldName] = aes_override;

  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("per_column_aes_override.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto contexts = provider->seen_contexts();
  // Metadata still routes through the provider even though data pages don't.
  EXPECT_TRUE(AnyContext(contexts, kInt64FieldName));
  EXPECT_TRUE(AnyContext(contexts, kDoubleFieldName));

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));
}

// per_column_encryption can add a column (not present in column_keys) that
// uses EXTERNAL_PROTECT_V1 explicitly; both its data pages and column metadata
// route through the provider, same as a column_keys-sourced column.
TEST_F(ParquetColumnCryptoProviderTest, PerColumnEncryptionAddsExternalColumn) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;

  ColumnEncryptionAttributes external_attrs;
  external_attrs.parquet_cipher = ParquetCipher::EXTERNAL_PROTECT_V1;
  external_attrs.key_id = kColumnMasterKeyIds[1];
  enc_config.per_column_encryption[kInt96FieldName] = external_attrs;

  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("per_column_external_add.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto contexts = provider->seen_contexts();
  EXPECT_TRUE(AnyContext(contexts, kInt96FieldName));

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));
}

// plaintext_footer=true with a ParquetCryptoProvider: the footer is signed via
// ParquetCryptoProvider::SignFooter() (an opaque blob, XOR'd with
// footer_aad||footer for this mock provider) and verified via
// VerifyFooterSignature() -- no AES-GCM byte-offset assumptions in metadata.cc.
TEST_F(ParquetColumnCryptoProviderTest, PlaintextFooterSigningRoundTrip) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  enc_config.plaintext_footer = true;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("plaintext_footer.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  // A real signature computed by the provider verifies successfully.
  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path, decryption_props));
}

// A corrupted footer signature is rejected rather than silently accepted --
// proves VerifyFooterSignature() (not just its absence) is actually enforced.
TEST_F(ParquetColumnCryptoProviderTest, PlaintextFooterTamperedSignatureThrows) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  enc_config.plaintext_footer = true;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("plaintext_footer_tampered.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  // Flip the last byte of the file (part of the signature blob, which sits after
  // the plaintext footer and before the trailing 8-byte length+magic trailer).
  {
    std::fstream f(file_path, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(f.is_open());
    f.seekg(-9, std::ios::end);
    char byte;
    f.read(&byte, 1);
    byte = static_cast<char>(static_cast<uint8_t>(byte) ^ 0xFF);
    f.seekp(-9, std::ios::end);
    f.write(&byte, 1);
  }

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_THROW(decryptor.DecryptFile(file_path, decryption_props), ParquetException);
}

// Validation and error handling: invalid configurations and provider errors
// surface as exceptions instead of being silently ignored or corrupting output.

// A per-column EXTERNAL_PROTECT_V1 cipher override with no key_metadata set
// throws at write time. Built directly through ColumnEncryptionProperties::Builder
// (bypassing CryptoFactory, which always generates a non-empty key_metadata) to
// reach InternalFileEncryptor::GetColumnEncryptor()'s guard.
TEST_F(ParquetColumnCryptoProviderTest, EmptyKeyMetadataThrows) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ColumnEncryptionProperties::Builder col_builder(kDoubleFieldName);
  col_builder.key(kColumnEncryptionKey1);
  col_builder.parquet_cipher(ParquetCipher::EXTERNAL_PROTECT_V1);
  // No key_metadata() call: key_metadata stays empty, which is invalid for
  // EXTERNAL_PROTECT_V1.
  ColumnPathToEncryptionPropertiesMap encrypted_columns;
  encrypted_columns[kDoubleFieldName] = col_builder.build();

  ExternalFileEncryptionProperties::Builder file_builder(kFooterEncryptionKey);
  auto encryption_props = file_builder.footer_key_metadata("kf")
                              ->encrypted_columns(encrypted_columns)
                              ->algorithm(ParquetCipher::AES_GCM_V1)
                              ->parquet_crypto_provider(provider)
                              ->build_external();

  FileEncryptor encryptor;
  EXPECT_THROW(
      encryptor.EncryptFile(TempFilePath("empty_key_metadata.parquet"), encryption_props),
      ParquetException);
}

// Symmetric to DecryptorProviderNotSetThrows below: InternalFileEncryptor's own
// null-provider guard (GetParquetCryptoProviderEncryptor) fires when
// EXTERNAL_PROTECT_V1 properties are built directly through
// ExternalFileEncryptionProperties::Builder, bypassing CryptoFactory's own,
// earlier null-provider check.
TEST_F(ParquetColumnCryptoProviderTest, EncryptorProviderNotSetThrows) {
  ColumnEncryptionProperties::Builder col_builder(kDoubleFieldName);
  col_builder.key(kColumnEncryptionKey1);
  col_builder.key_metadata("kc1");
  col_builder.parquet_cipher(ParquetCipher::EXTERNAL_PROTECT_V1);
  ColumnPathToEncryptionPropertiesMap encrypted_columns;
  encrypted_columns[kDoubleFieldName] = col_builder.build();

  ExternalFileEncryptionProperties::Builder file_builder(kFooterEncryptionKey);
  auto encryption_props = file_builder.footer_key_metadata("kf")
                              ->encrypted_columns(encrypted_columns)
                              ->algorithm(ParquetCipher::AES_GCM_V1)
                              // No parquet_crypto_provider() call: stays nullptr.
                              ->build_external();

  FileEncryptor encryptor;
  try {
    encryptor.EncryptFile(TempFilePath("encryptor_provider_not_set.parquet"),
                          encryption_props);
    FAIL() << "ParquetException should have been raised";
  } catch (const ParquetException& xcp) {
    EXPECT_THAT(xcp.what(), HasSubstr("parquet_crypto_provider must be set"));
  } catch (...) {
    FAIL() << "Caught unexpected exception type";
  }
}

// Reading a file written with EXTERNAL_PROTECT_V1 but no
// ParquetCryptoProvider set on the decryption side throws, instead of silently
// falling back to AES (there is no key for AES to use).
TEST_F(ParquetColumnCryptoProviderTest, DecryptorProviderNotSetThrows) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("decryptor_provider_not_set.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, /*parquet_crypto_provider=*/nullptr);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_THROW(decryptor.DecryptFile(file_path, decryption_props), ParquetException);
}

namespace {
// Fails every call so tests can verify the resulting Status/error propagates out
// as a ParquetException instead of being swallowed.
class FailingBlockCryptoProvider : public ParquetCryptoProvider {
 public:
  ::arrow::Result<std::vector<uint8_t>> EncryptBlock(std::span<const uint8_t>,
                                                     const ParquetCryptoContext&,
                                                     std::span<const uint8_t>,
                                                     std::span<const uint8_t>) override {
    return ::arrow::Status::IOError("injected EncryptBlock failure");
  }
  ::arrow::Result<std::vector<uint8_t>> DecryptBlock(std::span<const uint8_t>,
                                                     const ParquetCryptoContext&,
                                                     std::span<const uint8_t>,
                                                     std::span<const uint8_t>) override {
    return ::arrow::Status::IOError("injected DecryptBlock failure");
  }
  [[nodiscard]] bool SupportsTypedValues() const override { return false; }
  ::arrow::Status EncryptCells(CryptoValueBuffer&, const ParquetCryptoContext&,
                               std::span<const uint8_t>) override {
    return ::arrow::Status::NotImplemented("block-path-only provider");
  }
  ::arrow::Status DecryptCells(CryptoValueBuffer&, const ParquetCryptoContext&,
                               std::span<const uint8_t>) override {
    return ::arrow::Status::NotImplemented("block-path-only provider");
  }
  ::arrow::Result<std::vector<uint8_t>> SignFooter(std::span<const uint8_t>,
                                                   const ParquetCryptoContext&,
                                                   std::span<const uint8_t>,
                                                   std::span<const uint8_t>) override {
    return ::arrow::Status::IOError("injected SignFooter failure");
  }
  ::arrow::Result<bool> VerifyFooterSignature(std::span<const uint8_t>,
                                              std::span<const uint8_t>,
                                              const ParquetCryptoContext&,
                                              std::span<const uint8_t>,
                                              std::span<const uint8_t>) override {
    return ::arrow::Status::IOError("injected VerifyFooterSignature failure");
  }
};
}  // namespace

// An error Status returned from EncryptBlock() propagates out of
// EncryptFile() as a ParquetException, instead of being silently dropped or
// producing a corrupted file.
TEST_F(ParquetColumnCryptoProviderTest, ProviderEncryptErrorPropagates) {
  auto provider = std::make_shared<FailingBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  FileEncryptor encryptor;
  EXPECT_THROW(encryptor.EncryptFile(TempFilePath("provider_encrypt_error.parquet"),
                                     encryption_props),
               ParquetException);
}

// Symmetric to ProviderEncryptErrorPropagates above: an error Status returned
// from DecryptBlock() propagates out of DecryptFile() as a ParquetException.
TEST_F(ParquetColumnCryptoProviderTest, ProviderDecryptErrorPropagates) {
  auto enc_provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, enc_provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("provider_decrypt_error.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto dec_provider = std::make_shared<FailingBlockCryptoProvider>();
  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, dec_provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_THROW(decryptor.DecryptFile(file_path, decryption_props), ParquetException);
}

// Coverage: a column that isn't configured for encryption is never routed to
// the provider.

// A column absent from both column_keys and per_column_encryption is not
// encrypted at all, so the provider must never be called for it.
TEST_F(ParquetColumnCryptoProviderTest, UnencryptedColumnNeverReachesProvider) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  // column_keys covers 6 fields; kInt64FieldName/kInt96FieldName are deliberately
  // left out and unencrypted.
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path = TempFilePath("unencrypted_column.parquet");
  FileEncryptor encryptor;
  ASSERT_NO_THROW(encryptor.EncryptFile(file_path, encryption_props));

  auto contexts = provider->seen_contexts();
  EXPECT_FALSE(AnyContext(contexts, kInt64FieldName));
  EXPECT_FALSE(AnyContext(contexts, kInt96FieldName));
}

// Concurrency: multiple writers can safely share one provider instance.

// Two writers sharing one provider instance concurrently do not crash or
// corrupt each other's output; the provider's atomic call counters are the only
// shared mutable state (run under TSAN to fully validate absence of races).
TEST_F(ParquetColumnCryptoProviderTest, ConcurrentWritesShareProviderSafely) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();

  ExternalEncryptionConfiguration enc_config(kFooterMasterKeyId);
  enc_config.column_keys = BuildColumnKeyMapping();
  enc_config.encryption_algorithm = ParquetCipher::EXTERNAL_PROTECT_V1;
  auto encryption_props = crypto_factory_.GetExternalFileEncryptionProperties(
      kms_config_, enc_config, provider);
  ASSERT_NE(encryption_props, nullptr);

  const std::string file_path_1 = TempFilePath("concurrent_writes_1.parquet");
  const std::string file_path_2 = TempFilePath("concurrent_writes_2.parquet");

  std::thread writer_1([&] {
    FileEncryptor encryptor;
    encryptor.EncryptFile(file_path_1, encryption_props);
  });
  std::thread writer_2([&] {
    FileEncryptor encryptor;
    encryptor.EncryptFile(file_path_2, encryption_props);
  });
  writer_1.join();
  writer_2.join();

  ExternalDecryptionConfiguration dec_config;
  auto decryption_props = crypto_factory_.GetExternalFileDecryptionProperties(
      kms_config_, dec_config, provider);
  ASSERT_NE(decryption_props, nullptr);

  FileDecryptor decryptor;
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path_1, decryption_props));
  EXPECT_NO_THROW(decryptor.DecryptFile(file_path_2, decryption_props));
  EXPECT_GT(provider->encrypt_block_calls(), 0);
}

// Low-level adapter framing: the 4-byte length prefix EncryptWithManagedBuffer()/
// DecryptWithManagedBuffer() add around block-path ciphertext.

// EncryptWithManagedBuffer() writes a 4-byte little-endian length prefix
// before the provider's block-path ciphertext; DecryptWithManagedBuffer() strips
// it and recovers the original plaintext. GetCiphertextLength() reports the
// exact total size (prefix + payload) for an exactly-sized buffer.
TEST(ParquetCryptoProviderAdapterLengthPrefixTest, RoundTripAndExactLength) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> plaintext = {10, 20, 30, 40, 50, 60, 70};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  int32_t written = encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get());
  ASSERT_EQ(written, ciphertext_buf->size());
  // 4-byte prefix + payload (XOR is length-preserving, so payload == plaintext size).
  EXPECT_EQ(written, static_cast<int32_t>(4 + plaintext.size()));

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(ciphertext_buf->size()));
  auto* base_decryptor = static_cast<encryption::DecryptorInterface*>(&decryptor);
  EXPECT_EQ(base_decryptor->GetCiphertextLength(ciphertext), written);

  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  int32_t recovered = decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get());
  ASSERT_EQ(recovered, static_cast<int32_t>(plaintext.size()));
  std::vector<uint8_t> recovered_bytes(plaintext_buf->data(),
                                       plaintext_buf->data() + recovered);
  EXPECT_EQ(recovered_bytes, plaintext);
}

// A caller that peeks a larger-than-necessary buffer (mirroring
// SerializedPageReader::NextPage()'s growing page-header peek) gets back the
// correct boundary from GetCiphertextLength(), and DecryptWithManagedBuffer()
// ignores trailing bytes beyond that boundary instead of treating them as part
// of the ciphertext.
TEST(ParquetCryptoProviderAdapterLengthPrefixTest, IgnoresTrailingBytesBeyondPrefix) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  int32_t written = encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get());

  std::vector<uint8_t> oversized(ciphertext_buf->data(),
                                 ciphertext_buf->data() + written);
  oversized.insert(oversized.end(), {0xDE, 0xAD, 0xBE, 0xEF});

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  auto* base_decryptor = static_cast<encryption::DecryptorInterface*>(&decryptor);
  EXPECT_EQ(base_decryptor->GetCiphertextLength(oversized), written);

  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  int32_t recovered = decryptor.DecryptWithManagedBuffer(oversized, plaintext_buf.get());
  ASSERT_EQ(recovered, static_cast<int32_t>(plaintext.size()));
  std::vector<uint8_t> recovered_bytes(plaintext_buf->data(),
                                       plaintext_buf->data() + recovered);
  EXPECT_EQ(recovered_bytes, plaintext);
}

// A buffer shorter than the 4-byte length prefix itself is rejected,
// instead of reading past its end.
TEST(ParquetCryptoProviderAdapterLengthPrefixTest, BufferShorterThanPrefixThrows) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  auto* base_decryptor = static_cast<encryption::DecryptorInterface*>(&decryptor);

  const std::vector<uint8_t> too_short = {1, 2, 3};
  EXPECT_THROW((void)base_decryptor->GetCiphertextLength(too_short), ParquetException);

  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  EXPECT_THROW(decryptor.DecryptWithManagedBuffer(too_short, plaintext_buf.get()),
               ParquetException);
}

// A corrupted prefix that claims more payload than the buffer actually
// contains is rejected, instead of reading past the buffer's end.
TEST(ParquetCryptoProviderAdapterLengthPrefixTest, PrefixExceedingBufferThrows) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  auto* base_decryptor = static_cast<encryption::DecryptorInterface*>(&decryptor);

  // Little-endian 1000-byte claim, but only 2 bytes actually follow the prefix.
  const std::vector<uint8_t> corrupted = {0xE8, 0x03, 0x00, 0x00, 0xAA, 0xBB};
  EXPECT_THROW((void)base_decryptor->GetCiphertextLength(corrupted), ParquetException);

  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  EXPECT_THROW(decryptor.DecryptWithManagedBuffer(corrupted, plaintext_buf.get()),
               ParquetException);
}

// Adapter stubs documented as unreachable: direct construction and invocation
// confirms each one actually throws, instead of relying on the dispatch logic
// never calling them.

// CanCalculateCiphertextLength()/CanCalculateLengths() always return false --
// every real call must go through EncryptWithManagedBuffer()/
// DecryptWithManagedBuffer() instead of the pre-allocated-buffer path.
TEST(ParquetCryptoProviderAdapterUnreachableStubsTest, ManagedBufferPathAlwaysReported) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  EXPECT_FALSE(encryptor.CanCalculateCiphertextLength());

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  EXPECT_FALSE(decryptor.CanCalculateLengths());
}

// CiphertextLength() and Encrypt() are only reachable when
// CanCalculateCiphertextLength() is true, which the adapter never returns;
// calling them directly throws instead of silently returning a bogus length.
TEST(ParquetCryptoProviderAdapterUnreachableStubsTest,
     EncryptorPreallocatedPathStubsThrow) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);

  EXPECT_THROW((void)encryptor.CiphertextLength(10), ParquetException);

  const std::vector<uint8_t> plaintext = {1, 2, 3};
  std::vector<uint8_t> ciphertext(plaintext.size());
  EXPECT_THROW(encryptor.Encrypt(plaintext, /*key=*/{}, /*aad=*/{}, ciphertext),
               ParquetException);
}

// SignedFooterEncrypt() is a future extension: provider footer signing is not
// yet dispatched to this adapter, so it always throws.
TEST(ParquetCryptoProviderAdapterUnreachableStubsTest,
     SignedFooterEncryptNotYetImplemented) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kFooter);

  const std::vector<uint8_t> footer = {1, 2, 3};
  std::vector<uint8_t> encrypted_footer(footer.size());
  EXPECT_THROW(encryptor.SignedFooterEncrypt(footer, /*key=*/{}, /*aad=*/{},
                                             /*nonce=*/{}, encrypted_footer),
               ParquetException);
}

// PlaintextLength(), CiphertextLength(), and Decrypt() are only reachable when
// CanCalculateLengths() is true, which the adapter never returns; calling them
// directly throws instead of silently returning a bogus length.
TEST(ParquetCryptoProviderAdapterUnreachableStubsTest,
     DecryptorPreallocatedPathStubsThrow) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);

  EXPECT_THROW((void)decryptor.PlaintextLength(10), ParquetException);
  EXPECT_THROW((void)decryptor.CiphertextLength(10), ParquetException);

  const std::vector<uint8_t> ciphertext = {1, 2, 3};
  std::vector<uint8_t> plaintext(ciphertext.size());
  EXPECT_THROW(decryptor.Decrypt(ciphertext, /*key=*/{}, /*aad=*/{}, plaintext),
               ParquetException);
}

// UseCellPath() gating: the adapter only takes the cell path when the provider
// supports typed values AND the dispatch module is a data or dictionary page --
// never for footer/column-metadata modules, even if the provider would otherwise
// prefer the cell path -- and the cell path requires EncodingProperties to
// decompress/recompress the page.

// A block-path-only provider (SupportsTypedValues()==false) always uses the
// block path, even for a data-page module.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     BlockOnlyProviderNeverUsesCellPathForDataPage) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);

  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  // No EncodingProperties passed: if the cell path were mistakenly taken, this
  // would throw "EncodingProperties required for cell path" instead of succeeding.
  EXPECT_NO_THROW(encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get()));
  EXPECT_EQ(provider->encrypt_block_calls(), 1);
  EXPECT_EQ(provider->encrypt_cells_calls(), 0);
}

// A typed-values-capable provider (SupportsTypedValues()==true) still uses the
// block path for a column-metadata module, since only data/dictionary pages are
// cell-path eligible.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     TypedValuesProviderIgnoresCellPathForColumnMetadataOnEncrypt) {
  auto provider = std::make_shared<XorCellCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter encryptor(
      provider, ctx, /*dispatch_module_type=*/kColumnMetaData);

  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  // The block path calls EncryptBlock(), which this provider always fails with a
  // distinct message; if the cell path were mistakenly taken instead (no
  // EncodingProperties passed here), the error would be "EncodingProperties
  // required for cell path".
  try {
    encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get());
    FAIL() << "ParquetException should have been raised";
  } catch (const ParquetException& xcp) {
    EXPECT_THAT(xcp.what(), HasSubstr("EncryptBlock is unreachable"));
  } catch (...) {
    FAIL() << "Caught unexpected exception type";
  }
}

// Symmetric to the encrypt-side check above, for the footer module on decrypt.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     TypedValuesProviderIgnoresCellPathForFooterOnDecrypt) {
  auto provider = std::make_shared<XorCellCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kFooter);

  // A validly-framed (4-byte length prefix + 3-byte payload) block-path buffer:
  // the footer module always uses the block path, so GetCiphertextLength()'s
  // prefix parsing must succeed before DecryptBlock() is even reached.
  const std::vector<uint8_t> ciphertext = {3, 0, 0, 0, 1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  try {
    decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get());
    FAIL() << "ParquetException should have been raised";
  } catch (const ParquetException& xcp) {
    EXPECT_THAT(xcp.what(), HasSubstr("DecryptBlock is unreachable"));
  } catch (...) {
    FAIL() << "Caught unexpected exception type";
  }
}

// A typed-values-capable provider still uses the block path for a kDataPage
// module when the page's actual on-disk encoding is not PLAIN (e.g. a
// dictionary-encoded page's indices) -- EncryptCells()/DecryptCells() must never
// see dictionary indices as if they were real values.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     DictionaryEncodedDataPageUsesBlockPathNeverCells) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  auto enc_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE_V2)
                       .PageEncoding(Encoding::RLE_DICTIONARY)
                       .Build();
  EXPECT_NO_THROW(encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get(), {},
                                                     {}, std::move(enc_props)));
  EXPECT_EQ(provider->encrypt_block_calls(), 1);
  EXPECT_EQ(provider->encrypt_cells_calls(), 0);

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(ciphertext_buf->size()));
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  auto dec_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE_V2)
                       .PageEncoding(Encoding::RLE_DICTIONARY)
                       .Build();
  EXPECT_NO_THROW(decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get(), {},
                                                     {}, std::move(dec_props)));
  EXPECT_EQ(provider->decrypt_block_calls(), 1);
  EXPECT_EQ(provider->decrypt_cells_calls(), 0);
}

// Same as above, for DataPageV1 -- the gate's page_encoding == PLAIN check applies
// identically regardless of page version, so a V1 dictionary-encoded page's
// indices must fall back to the block path too.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     DictionaryEncodedDataPageV1UsesBlockPathNeverCells) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  auto enc_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE)
                       .PageEncoding(Encoding::RLE_DICTIONARY)
                       .Build();
  EXPECT_NO_THROW(encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get(), {},
                                                     {}, std::move(enc_props)));
  EXPECT_EQ(provider->encrypt_block_calls(), 1);
  EXPECT_EQ(provider->encrypt_cells_calls(), 0);

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(ciphertext_buf->size()));
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  auto dec_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE)
                       .PageEncoding(Encoding::RLE_DICTIONARY)
                       .Build();
  EXPECT_NO_THROW(decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get(), {},
                                                     {}, std::move(dec_props)));
  EXPECT_EQ(provider->decrypt_block_calls(), 1);
  EXPECT_EQ(provider->decrypt_cells_calls(), 0);
}

// A typed-values-capable provider still uses the block path for a PLAIN-encoded
// DataPage when its compression codec is BZ2 -- ParquetPageDecoder's one-shot
// CompressBuffer()/DecompressBuffer() can never support BZ2 (Arrow's BZ2Codec has
// no one-shot API at all), so the gate must fall back here exactly as it does for
// a non-PLAIN value encoding, rather than let EncryptWithManagedBuffer()/
// DecryptWithManagedBuffer() reach ParquetPageDecoder and throw.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     Bz2CompressedPageUsesBlockPathNeverCells) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  auto enc_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE_V2)
                       .PageEncoding(Encoding::PLAIN)
                       .CompressionCodec(::arrow::Compression::BZ2)
                       .Build();
  EXPECT_NO_THROW(encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get(), {},
                                                     {}, std::move(enc_props)));
  EXPECT_EQ(provider->encrypt_block_calls(), 1);
  EXPECT_EQ(provider->encrypt_cells_calls(), 0);

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(ciphertext_buf->size()));
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  auto dec_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE_V2)
                       .PageEncoding(Encoding::PLAIN)
                       .CompressionCodec(::arrow::Compression::BZ2)
                       .Build();
  EXPECT_NO_THROW(decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get(), {},
                                                     {}, std::move(dec_props)));
  EXPECT_EQ(provider->decrypt_block_calls(), 1);
  EXPECT_EQ(provider->decrypt_cells_calls(), 0);
}

// A real DictionaryPage is a flat, non-nullable list of real (non-index) values,
// always PLAIN-encoded -- unlike a dictionary-encoded DataPage's indices, it does
// take the cell path. dispatch_module_type is kDataPage even here, since real
// DictionaryPages share the kDataPage adapter; the per-call EncodingProperties'
// PageType, not dispatch_module_type_, is what distinguishes it.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest, DictionaryPageUsesCellPath) {
  auto provider = std::make_shared<XorTypedValuesCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  // 3 INT32 values, PLAIN-encoded (4 raw bytes each, no framing) -- exact numeric
  // content doesn't matter, only that it round-trips byte-for-byte through XOR.
  const std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  auto enc_props = EncodingProperties::Builder()
                       .PageType(PageType::DICTIONARY_PAGE)
                       .PhysicalType(Type::INT32)
                       .PageEncoding(Encoding::PLAIN)
                       .CompressionCodec(::arrow::Compression::UNCOMPRESSED)
                       .DictPageNumValues(3)
                       .Build();
  EXPECT_NO_THROW(encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get(), {},
                                                     {}, std::move(enc_props)));
  EXPECT_EQ(provider->encrypt_block_calls(), 0);
  EXPECT_EQ(provider->encrypt_cells_calls(), 1);

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(ciphertext_buf->size()));
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  auto dec_props = EncodingProperties::Builder()
                       .PageType(PageType::DICTIONARY_PAGE)
                       .PhysicalType(Type::INT32)
                       .PageEncoding(Encoding::PLAIN)
                       .CompressionCodec(::arrow::Compression::UNCOMPRESSED)
                       .DictPageNumValues(3)
                       .Build();
  EXPECT_NO_THROW(decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get(), {},
                                                     {}, std::move(dec_props)));
  EXPECT_EQ(provider->decrypt_block_calls(), 0);
  EXPECT_EQ(provider->decrypt_cells_calls(), 1);
  // XOR is self-inverse: the recovered bytes must exactly match the original.
  EXPECT_EQ(std::vector<uint8_t>(plaintext_buf->data(),
                                 plaintext_buf->data() + plaintext_buf->size()),
            plaintext);
}

// EncryptWithManagedBuffer() on the cell path requires EncodingProperties to
// decompress/recompress the page; omitting it throws instead of dereferencing
// a null pointer.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     CellPathRequiresEncodingPropertiesOnEncrypt) {
  auto provider = std::make_shared<XorCellCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);

  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  try {
    encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get());
    FAIL() << "ParquetException should have been raised";
  } catch (const ParquetException& xcp) {
    EXPECT_THAT(xcp.what(), HasSubstr("EncodingProperties required for cell path"));
  } catch (...) {
    FAIL() << "Caught unexpected exception type";
  }
}

// Symmetric to the encrypt-side check above, for DecryptWithManagedBuffer().
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     CellPathRequiresEncodingPropertiesOnDecrypt) {
  auto provider = std::make_shared<XorCellCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);

  // The cell path's null-EncodingProperties check runs before any length-prefix
  // parsing, so this buffer need not be validly framed.
  const std::vector<uint8_t> ciphertext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  try {
    decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf.get());
    FAIL() << "ParquetException should have been raised";
  } catch (const ParquetException& xcp) {
    EXPECT_THAT(xcp.what(), HasSubstr("EncodingProperties required for cell path"));
  } catch (...) {
    FAIL() << "Caught unexpected exception type";
  }
}

// GetCiphertextLength() on the cell path returns the buffer's exact size, with
// no 4-byte length prefix to parse (the surrounding PageHeader already states
// the page's exact size for the cell path, unlike the block path -- see
// ParquetCryptoProviderAdapterLengthPrefixTest above).
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     GetCiphertextLengthReturnsSizeDirectlyOnCellPath) {
  auto provider = std::make_shared<XorCellCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  auto* base_decryptor = static_cast<encryption::DecryptorInterface*>(&decryptor);

  const std::vector<uint8_t> ciphertext = {1, 2, 3, 4, 5};
  EXPECT_EQ(base_decryptor->GetCiphertextLength(ciphertext),
            static_cast<int32_t>(ciphertext.size()));
}

// DataPageV1 now takes the cell path, same as DataPageV2 -- a flat
// (non-nested, non-null) BYTE_ARRAY column round-trips through EncryptCells()/
// DecryptCells() at the adapter-gating level (XorCellCryptoProvider only
// supports BYTE_ARRAY, see its class comment). See parquet_page_decoder_test.cc
// for the lower-level buffer-framing coverage (nested columns, compression,
// BIT_PACKED level decoding, and the RLE-only recompress limitation).
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     CellPathAcceptsDataPageV1EncodingProperties) {
  auto provider = std::make_shared<XorCellCryptoProvider>();
  ParquetCryptoContext ctx;

  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  // PLAIN BYTE_ARRAY: a 4-byte little-endian length prefix followed by the raw
  // bytes, per value -- "a", "bb", "ccc".
  const std::vector<uint8_t> plaintext = {1, 0, 0, 0, 'a',       //
                                          2, 0, 0, 0, 'b', 'b',  //
                                          3, 0, 0, 0, 'c', 'c', 'c'};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  auto enc_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE)
                       .PageEncoding(Encoding::PLAIN)
                       .PhysicalType(Type::BYTE_ARRAY)
                       .CompressionCodec(::arrow::Compression::UNCOMPRESSED)
                       .DataPageNumValues(3)
                       .DataPageMaxDefinitionLevel(0)
                       .DataPageMaxRepetitionLevel(0)
                       .Build();
  int32_t encrypted_len = encryptor.EncryptWithManagedBuffer(
      plaintext, ciphertext_buf.get(), {}, {}, std::move(enc_props));
  EXPECT_EQ(provider->encrypt_cells_calls(), 1);

  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(encrypted_len));
  ASSERT_OK_AND_ASSIGN(auto plaintext_buf, ::arrow::AllocateResizableBuffer(0));
  auto dec_props = EncodingProperties::Builder()
                       .PageType(PageType::DATA_PAGE)
                       .PageEncoding(Encoding::PLAIN)
                       .PhysicalType(Type::BYTE_ARRAY)
                       .CompressionCodec(::arrow::Compression::UNCOMPRESSED)
                       .DataPageNumValues(3)
                       .DataPageMaxDefinitionLevel(0)
                       .DataPageMaxRepetitionLevel(0)
                       .Build();
  int32_t decrypted_len = decryptor.DecryptWithManagedBuffer(
      ciphertext, plaintext_buf.get(), {}, {}, std::move(dec_props));
  EXPECT_EQ(provider->decrypt_cells_calls(), 1);

  ASSERT_EQ(decrypted_len, static_cast<int32_t>(plaintext.size()));
  EXPECT_EQ(
      std::vector<uint8_t>(plaintext_buf->data(), plaintext_buf->data() + decrypted_len),
      plaintext);
}

// Block-path aad/dek forwarding: both are passed through to the provider
// exactly as given, including the empty (not supplied) case.
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     BlockPathForwardsAadAndDekVerbatimOnEncrypt) {
  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter encryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);

  const std::vector<uint8_t> plaintext = {1, 2, 3};
  const std::vector<uint8_t> aad = {9, 9, 9};
  const std::vector<uint8_t> dek = {7, 7, 7, 7};

  ASSERT_OK_AND_ASSIGN(auto buf1, ::arrow::AllocateResizableBuffer(0));
  encryptor.EncryptWithManagedBuffer(plaintext, buf1.get(), aad, dek);
  ASSERT_EQ(provider->seen_module_aads().size(), 1u);
  EXPECT_EQ(provider->seen_module_aads().back(), aad);
  EXPECT_EQ(provider->calls_with_dek(), 1);

  ASSERT_OK_AND_ASSIGN(auto buf2, ::arrow::AllocateResizableBuffer(0));
  encryptor.EncryptWithManagedBuffer(plaintext, buf2.get());
  EXPECT_TRUE(provider->seen_module_aads().back().empty());
  EXPECT_EQ(provider->calls_with_dek(), 1);  // Second call passed no dek.
}

// Symmetric to the encrypt-side check above, for DecryptWithManagedBuffer().
TEST(ParquetCryptoProviderAdapterCellPathGatingTest,
     BlockPathForwardsAadAndDekVerbatimOnDecrypt) {
  // A throwaway provider/adapter, only used to produce a validly-framed
  // block-path ciphertext buffer for the decrypt-side assertions below.
  auto framing_provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoContext ctx;
  ParquetCryptoProviderEncryptorAdapter framing_encryptor(
      framing_provider, ctx, /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> plaintext = {1, 2, 3};
  ASSERT_OK_AND_ASSIGN(auto ciphertext_buf, ::arrow::AllocateResizableBuffer(0));
  framing_encryptor.EncryptWithManagedBuffer(plaintext, ciphertext_buf.get());
  std::span<const uint8_t> ciphertext(ciphertext_buf->data(),
                                      static_cast<size_t>(ciphertext_buf->size()));

  auto provider = std::make_shared<XorBlockCryptoProvider>();
  ParquetCryptoProviderDecryptorAdapter decryptor(provider, ctx,
                                                  /*dispatch_module_type=*/kDataPage);
  const std::vector<uint8_t> aad = {9, 9, 9};
  const std::vector<uint8_t> dek = {7, 7, 7, 7};

  ASSERT_OK_AND_ASSIGN(auto plaintext_buf1, ::arrow::AllocateResizableBuffer(0));
  decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf1.get(), aad, dek);
  ASSERT_EQ(provider->seen_module_aads().size(), 1u);
  EXPECT_EQ(provider->seen_module_aads().back(), aad);
  EXPECT_EQ(provider->calls_with_dek(), 1);

  ASSERT_OK_AND_ASSIGN(auto plaintext_buf2, ::arrow::AllocateResizableBuffer(0));
  decryptor.DecryptWithManagedBuffer(ciphertext, plaintext_buf2.get());
  EXPECT_TRUE(provider->seen_module_aads().back().empty());
  EXPECT_EQ(provider->calls_with_dek(), 1);  // Second call passed no dek.
}

}  // namespace parquet::encryption::test
