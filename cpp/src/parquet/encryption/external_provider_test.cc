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

#include <memory>
#include <thread>
#include <vector>

#include "arrow/io/memory.h"
#include "arrow/testing/gtest_util.h"
#include "arrow/util/config.h"
#include "arrow/util/key_value_metadata.h"
#include "arrow/util/secure_string.h"

#include "parquet/column_reader.h"
#include "parquet/column_writer.h"
#include "parquet/encryption/encryption.h"
#include "parquet/encryption/mock_decryptor_provider.h"
#include "parquet/encryption/mock_encryptor_provider.h"
#include "parquet/file_reader.h"
#include "parquet/file_writer.h"
#include "parquet/properties.h"
#include "parquet/schema.h"
#include "parquet/types.h"

#ifndef PARQUET_REQUIRE_ENCRYPTION
// All tests in this file require OpenSSL; skip the entire suite in no-SSL builds.
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::GTEST_FLAG(filter) = "-*";
  return RUN_ALL_TESTS();
}
#else

namespace parquet::encryption::test {

namespace {

using ::arrow::util::SecureString;
using schema::GroupNode;
using schema::PrimitiveNode;

// 16-byte keys for footer and column AES metadata encryption.
const SecureString kFooterKey("0123456789012345");
const SecureString kColumnAesKey("1234567890123456");

const char kColExt[] = "ext_col";
const char kColAes[] = "aes_col";
const char kKeyId[] = "test-key-id";

// Builds ColumnEncryptionProperties for the external provider data path.
std::shared_ptr<ColumnEncryptionProperties> ExtColProps(const char* col_name) {
  ColumnEncryptionProperties::Builder b(col_name);
  b.key(kColumnAesKey);  // AES key for column metadata encryption
  b.key_metadata(kKeyId)->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
  return b.build();
}

// Builds FileDecryptionProperties for reading files with external-provider columns.
std::shared_ptr<FileDecryptionProperties> ExtDecProps(
    const char* col_name, std::shared_ptr<ExternalDecryptorProvider> dec_provider) {
  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(col_name);
  dec_cols[col_name] = dcb.key(kColumnAesKey)->build();

  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)
      ->column_keys(dec_cols)
      ->external_decryptor_provider(std::move(dec_provider));
  return db.build();
}

// Writes a single-INT32-column Parquet file and returns its buffer.
std::shared_ptr< ::arrow::Buffer> WriteOneColumn(
    const char* col_name, const std::vector<int32_t>& values,
    std::shared_ptr<FileEncryptionProperties> enc_props) {
  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(col_name, Repetition::REQUIRED, Type::INT32)});
  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props =
      WriterProperties::Builder().encryption(std::move(enc_props))->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  col->WriteBatch(static_cast<int64_t>(values.size()), nullptr, nullptr, values.data());
  col->Close();
  file_writer->Close();
  return sink->Finish().ValueOrDie();
}

// Reads back INT32 values from a single-column Parquet buffer.
std::vector<int32_t> ReadOneColumn(std::shared_ptr< ::arrow::Buffer> buf,
                                   std::shared_ptr<FileDecryptionProperties> dec_props) {
  ReaderProperties reader_props;
  if (dec_props) reader_props.file_decryption_properties(std::move(dec_props));
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);
  auto rg_reader = file_reader->RowGroup(0);
  auto col_reader =
      std::static_pointer_cast<TypedColumnReader<Int32Type> >(rg_reader->Column(0));
  int64_t total_rows = file_reader->metadata()->RowGroup(0)->num_rows();
  std::vector<int32_t> out(static_cast<size_t>(total_rows));
  int64_t read = 0;
  col_reader->ReadBatch(static_cast<int>(total_rows), nullptr, nullptr, out.data(),
                        &read);
  out.resize(static_cast<size_t>(read));
  return out;
}

}  // namespace

// TC1: MockEncryptorProvider::GetColumnEncryptor() is called when writing with
// EXTERNAL_DBPA_V1.
TEST(TestExternalEncryptionProvider, ProviderIsCalled) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);
  auto enc_props = fb.build();

  const std::vector<int32_t> values = {1, 2, 3, 4, 5};
  EXPECT_NO_THROW(WriteOneColumn(kColExt, values, std::move(enc_props)));
  EXPECT_GT(mock_enc->call_count(), 0);
}

// TC2: Full encrypt + decrypt round-trip — plaintext is recovered correctly.
TEST(TestExternalEncryptionProvider, RoundTrip) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {10, 20, 30};
  auto buf = WriteOneColumn(kColExt, values, fb.build());
  auto dec_props = ExtDecProps(kColExt, mock_dec);
  auto result = ReadOneColumn(buf, std::move(dec_props));
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC3: No provider set — file written and read with standard AES; no throw.
TEST(TestExternalEncryptionProvider, NullProviderFallsBackToAES) {
  ColumnPathToEncryptionPropertiesMap cols;
  ColumnEncryptionProperties::Builder cb(kColAes);
  cb.key(kColumnAesKey);
  cols[kColAes] = cb.build();

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.encrypted_columns(cols);  // no external_encryptor_provider
  auto enc_props = fb.build();

  const std::vector<int32_t> values = {7, 8, 9};
  std::shared_ptr< ::arrow::Buffer> buf;
  EXPECT_NO_THROW(buf = WriteOneColumn(kColAes, values, std::move(enc_props)));

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColAes);
  dec_cols[kColAes] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols);
  auto dec_props = db.build();

  auto result = ReadOneColumn(buf, std::move(dec_props));
  EXPECT_EQ(values, result);
}

// TC4: Provider stays alive after Builder goes out of scope — no use-after-free.
TEST(TestExternalEncryptionProvider, ProviderLifetime) {
  std::shared_ptr<FileEncryptionProperties> enc_props;
  std::shared_ptr<MockEncryptorProvider> enc_handle;
  {
    auto p = std::make_shared<MockEncryptorProvider>();
    enc_handle = p;

    ColumnPathToEncryptionPropertiesMap cols;
    cols[kColExt] = ExtColProps(kColExt);

    FileEncryptionProperties::Builder fb(kFooterKey);
    fb.external_encryptor_provider(p)->encrypted_columns(cols);
    enc_props = fb.build();
    // p goes out of scope; enc_props still holds the shared_ptr
  }

  const std::vector<int32_t> values = {100, 200};
  std::shared_ptr< ::arrow::Buffer> buf;
  EXPECT_NO_THROW(buf = WriteOneColumn(kColExt, values, std::move(enc_props)));
  EXPECT_GT(enc_handle->call_count(), 0);

  auto mock_dec = std::make_shared<MockDecryptorProvider>();
  auto result = ReadOneColumn(buf, ExtDecProps(kColExt, mock_dec));
  EXPECT_EQ(values, result);
}

// TC5: One provider instance handles multiple encrypted columns — call_count matches.
TEST(TestExternalEncryptionProvider, MultiColumnSameProvider) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make("col_a", Repetition::REQUIRED, Type::INT32),
                       PrimitiveNode::Make("col_b", Repetition::REQUIRED, Type::INT32)});

  const SecureString kColumnAesKey2("1234567890123457");

  ColumnPathToEncryptionPropertiesMap cols;
  {
    ColumnEncryptionProperties::Builder ba("col_a");
    ba.key(kColumnAesKey);
    ba.key_metadata("key-a")->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
    cols["col_a"] = ba.build();
  }
  {
    ColumnEncryptionProperties::Builder bb("col_b");
    bb.key(kColumnAesKey2);
    bb.key_metadata("key-b")->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
    cols["col_b"] = bb.build();
  }

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder().encryption(fb.build())->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> a_vals = {1, 2, 3};
  const std::vector<int32_t> b_vals = {4, 5, 6};
  auto* col_a = static_cast<Int32Writer*>(rg->NextColumn());
  col_a->WriteBatch(a_vals.size(), nullptr, nullptr, a_vals.data());
  col_a->Close();
  auto* col_b = static_cast<Int32Writer*>(rg->NextColumn());
  col_b->WriteBatch(b_vals.size(), nullptr, nullptr, b_vals.data());
  col_b->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  {
    ColumnDecryptionProperties::Builder da("col_a");
    dec_cols["col_a"] = da.key(kColumnAesKey)->build();
  }
  {
    ColumnDecryptionProperties::Builder db("col_b");
    dec_cols["col_b"] = db.key(kColumnAesKey2)->build();
  }
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols)->external_decryptor_provider(mock_dec);
  auto dec_props = db.build();

  ReaderProperties reader_props;
  reader_props.file_decryption_properties(std::move(dec_props));
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);
  auto rg_reader = file_reader->RowGroup(0);

  auto read_col = [&](int col_idx) {
    auto col_reader = std::static_pointer_cast<TypedColumnReader<Int32Type> >(
        rg_reader->Column(col_idx));
    std::vector<int32_t> out(3);
    int64_t read = 0;
    col_reader->ReadBatch(3, nullptr, nullptr, out.data(), &read);
    out.resize(static_cast<size_t>(read));
    return out;
  };

  EXPECT_EQ(a_vals, read_col(0));
  EXPECT_EQ(b_vals, read_col(1));
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC6: Mixed-algorithm file — one AES column and one external column in the same file.
// The external provider is called only for the EXTERNAL_DBPA_V1 column.
TEST(TestExternalEncryptionProvider, MixedAesAndExternalColumn) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColAes, Repetition::REQUIRED, Type::INT32),
                       PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});

  ColumnPathToEncryptionPropertiesMap cols;
  {
    ColumnEncryptionProperties::Builder b(kColAes);
    b.key(kColumnAesKey);  // standard AES path — no parquet_cipher() override
    cols[kColAes] = b.build();
  }
  cols[kColExt] = ExtColProps(kColExt);

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder().encryption(fb.build())->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> aes_vals = {11, 22, 33};
  const std::vector<int32_t> ext_vals = {44, 55, 66};
  auto* wa = static_cast<Int32Writer*>(rg->NextColumn());
  wa->WriteBatch(aes_vals.size(), nullptr, nullptr, aes_vals.data());
  wa->Close();
  auto* we = static_cast<Int32Writer*>(rg->NextColumn());
  we->WriteBatch(ext_vals.size(), nullptr, nullptr, ext_vals.data());
  we->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  {
    ColumnDecryptionProperties::Builder da(kColAes);
    dec_cols[kColAes] = da.key(kColumnAesKey)->build();
  }
  {
    ColumnDecryptionProperties::Builder de(kColExt);
    dec_cols[kColExt] = de.key(kColumnAesKey)->build();  // for metadata decryption
  }
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols)->external_decryptor_provider(mock_dec);

  ReaderProperties reader_props;
  reader_props.file_decryption_properties(db.build());
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);
  auto rg_reader = file_reader->RowGroup(0);

  auto read_col = [&](int col_idx) {
    auto col_reader = std::static_pointer_cast<TypedColumnReader<Int32Type> >(
        rg_reader->Column(col_idx));
    std::vector<int32_t> out(3);
    int64_t read = 0;
    col_reader->ReadBatch(3, nullptr, nullptr, out.data(), &read);
    out.resize(static_cast<size_t>(read));
    return out;
  };

  EXPECT_EQ(aes_vals, read_col(0));
  EXPECT_EQ(ext_vals, read_col(1));
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC7: EXTERNAL_DBPA_V1 column with provider NOT set → throws with a clear message.
TEST(TestExternalEncryptionProvider, ProviderNotSetThrows) {
  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  // No external_encryptor_provider() call — provider is nullptr.
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.encrypted_columns(cols);
  auto enc_props = fb.build();

  const std::vector<int32_t> values = {1, 2, 3};
  EXPECT_THROW(WriteOneColumn(kColExt, values, std::move(enc_props)), ParquetException);
}

// TC8: EXTERNAL_DBPA_V1 column with provider set but key_metadata empty → throws.
TEST(TestExternalEncryptionProvider, EmptyKeyMetadataThrows) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();

  // key_metadata intentionally omitted.
  ColumnEncryptionProperties::Builder cb(kColExt);
  cb.key(kColumnAesKey)->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
  // Note: no key_metadata() call — key_metadata_ stays empty.
  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = cb.build();

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);
  auto enc_props = fb.build();

  const std::vector<int32_t> values = {1, 2, 3};
  EXPECT_THROW(WriteOneColumn(kColExt, values, std::move(enc_props)), ParquetException);
}

// TC9: Plaintext footer + EXTERNAL_DBPA_V1 per-column — file readable without footer key.
TEST(TestExternalEncryptionProvider, PlaintextFooterWithExternalColumn) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.set_plaintext_footer();
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {7, 14, 21};
  auto buf = WriteOneColumn(kColExt, values, fb.build());

  EXPECT_GT(mock_enc->call_count(), 0);

  // Footer is plaintext — no footer_key needed on the read side.
  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.column_keys(dec_cols)->external_decryptor_provider(mock_dec);
  // required when reading a plaintext footer without a footer key
  db.disable_footer_signature_verification();

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC10: Multiple row groups — column_data_map_ cache is reused; call_count reflects all
// pages.
TEST(TestExternalEncryptionProvider, MultiRowGroupRoundTrip) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder().encryption(fb.build())->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);

  // Write 3 row groups — same Encryptor is reused from column_data_map_ for each.
  const std::vector<int32_t> vals = {1, 2, 3};
  for (int rg = 0; rg < 3; ++rg) {
    auto row_group = file_writer->AppendRowGroup();
    auto* col = static_cast<Int32Writer*>(row_group->NextColumn());
    col->WriteBatch(vals.size(), nullptr, nullptr, vals.data());
    col->Close();
  }
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);

  auto dec_props = ExtDecProps(kColExt, mock_dec);
  ReaderProperties reader_props;
  reader_props.file_decryption_properties(std::move(dec_props));
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);

  ASSERT_EQ(file_reader->metadata()->num_row_groups(), 3);
  for (int rg = 0; rg < 3; ++rg) {
    auto rg_reader = file_reader->RowGroup(rg);
    auto col_reader =
        std::static_pointer_cast<TypedColumnReader<Int32Type> >(rg_reader->Column(0));
    std::vector<int32_t> out(vals.size());
    int64_t read = 0;
    col_reader->ReadBatch(vals.size(), nullptr, nullptr, out.data(), &read);
    EXPECT_EQ(vals, out) << "row group " << rg;
  }
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC11: Reading an EXTERNAL_DBPA_V1 file without setting external_decryptor_provider
// throws — symmetric to TC7 which covers the encryptor side.
TEST(TestExternalEncryptionProvider, DecryptorProviderNotSetThrows) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {5, 6, 7};
  auto buf = WriteOneColumn(kColExt, values, fb.build());

  // No external_decryptor_provider — opening the column reader must throw.
  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols);  // no external_decryptor_provider
  auto dec_props = db.build();

  ReaderProperties reader_props;
  reader_props.file_decryption_properties(std::move(dec_props));
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);
  auto rg_reader = file_reader->RowGroup(0);
  // Throw must surface here — on column read, not on file open.
  EXPECT_THROW(
      {
        auto col_reader =
            std::static_pointer_cast<TypedColumnReader<Int32Type> >(rg_reader->Column(0));
        std::vector<int32_t> out(values.size());
        int64_t read = 0;
        col_reader->ReadBatch(static_cast<int>(values.size()), nullptr, nullptr,
                              out.data(), &read);
      },
      ParquetException);
}

// TC12: external_encryptor_provider set, but the column uses AES_GCM_V1 (no
// parquet_cipher override) — provider must NOT be called; AES handles it.
TEST(TestExternalEncryptionProvider, ProviderIgnoredForAesAlgorithmColumn) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  ColumnEncryptionProperties::Builder cb(kColAes);
  cb.key(kColumnAesKey);  // AES_GCM_V1 (default) — no parquet_cipher override
  cols[kColAes] = cb.build();

  FileEncryptionProperties::Builder fb(kFooterKey);
  // Provider is set, but the only column uses AES — provider must not be called.
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {1, 2, 3};
  std::shared_ptr< ::arrow::Buffer> buf;
  EXPECT_NO_THROW(buf = WriteOneColumn(kColAes, values, fb.build()));
  EXPECT_EQ(mock_enc->call_count(), 0);  // provider must NOT have been called

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColAes);
  dec_cols[kColAes] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols);
  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
}

// TC13: params.column_path and params.key_metadata received by the provider
// exactly match what was set via ColumnEncryptionProperties::Builder.
TEST(TestExternalEncryptionProvider, ColumnPathAndKeyMetadataPropagated) {
  // Capturing provider — records params from GetColumnEncryptor().
  struct CapturingProvider : public ExternalEncryptorProvider {
    ColumnEncryptionParams last_params;
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams& params) override {
      last_params = params;
      struct XorEnc : public EncryptorInterface {
        bool CanCalculateCiphertextLength() const override { return true; }
        int32_t CiphertextLength(int64_t n) const override {
          return static_cast<int32_t>(n);
        }
        int32_t Encrypt(std::span<const uint8_t> plain, std::span<const uint8_t>,
                        std::span<const uint8_t>, std::span<uint8_t> cipher,
                        std::unique_ptr<EncodingProperties>) override {
          std::transform(plain.begin(), plain.end(), cipher.begin(),
                         [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
          return static_cast<int32_t>(plain.size());
        }
        int32_t EncryptWithManagedBuffer(std::span<const uint8_t>,
                                         ::arrow::ResizableBuffer*,
                                         std::unique_ptr<EncodingProperties>) override {
          throw ParquetException("not expected in this test");
        }
        int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<uint8_t>) override {
          throw ParquetException("not supported");
        }
      };
      return std::make_unique<XorEnc>();
    }
  };

  auto cap = std::make_shared<CapturingProvider>();
  const std::string expected_key_metadata = "my-unique-key-id";
  const char* col_name = "my_column";

  ColumnEncryptionProperties::Builder cb(col_name);
  cb.key(kColumnAesKey);
  cb.key_metadata(expected_key_metadata)->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
  ColumnPathToEncryptionPropertiesMap cols;
  cols[col_name] = cb.build();

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(cap)->encrypted_columns(cols);

  EXPECT_NO_THROW(WriteOneColumn(col_name, {1, 2, 3}, fb.build()));
  EXPECT_EQ(cap->last_params.key_metadata, expected_key_metadata);
  EXPECT_EQ(cap->last_params.column_path, std::string(col_name));
}

// TC15: Provider with non-zero ciphertext overhead (e.g. +4 bytes nonce).
TEST(TestExternalEncryptionProvider, ProviderWithCiphertextOverhead) {
  static constexpr int32_t kNonceLen = 4;

  struct NoncePrependEncImpl : public EncryptorInterface {
    bool CanCalculateCiphertextLength() const override { return true; }
    int32_t CiphertextLength(int64_t n) const override {
      return kNonceLen + static_cast<int32_t>(n);
    }
    int32_t Encrypt(std::span<const uint8_t> plain, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t> cipher,
                    std::unique_ptr<EncodingProperties>) override {
      cipher[0] = 0xDE;
      cipher[1] = 0xAD;
      cipher[2] = 0xBE;
      cipher[3] = 0xEF;
      for (size_t i = 0; i < plain.size(); ++i)
        cipher[kNonceLen + i] = static_cast<uint8_t>(plain[i] ^ 0xABu);
      return kNonceLen + static_cast<int32_t>(plain.size());
    }
    int32_t EncryptWithManagedBuffer(std::span<const uint8_t>, ::arrow::ResizableBuffer*,
                                     std::unique_ptr<EncodingProperties>) override {
      throw ParquetException("not expected in this test");
    }
    int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<uint8_t>) override {
      throw ParquetException("not supported");
    }
  };
  struct NoncePrependDecImpl : public DecryptorInterface {
    bool CanCalculateLengths() const override { return true; }
    int32_t PlaintextLength(int32_t n) const override { return n - kNonceLen; }
    int32_t CiphertextLength(int32_t n) const override { return n; }
    int32_t Decrypt(std::span<const uint8_t> cipher, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t> plain,
                    std::unique_ptr<EncodingProperties>) override {
      for (size_t i = 0; i < plain.size(); ++i)
        plain[i] = static_cast<uint8_t>(cipher[kNonceLen + i] ^ 0xABu);
      return static_cast<int32_t>(plain.size());
    }
    int32_t DecryptWithManagedBuffer(std::span<const uint8_t>, ::arrow::ResizableBuffer*,
                                     std::unique_ptr<EncodingProperties>) override {
      throw ParquetException("not expected in this test");
    }
  };
  struct NoncePrependEncryptor : public ExternalEncryptorProvider {
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<NoncePrependEncImpl>();
    }
  };
  struct NoncePrependDecryptor : public ExternalDecryptorProvider {
    std::unique_ptr<DecryptorInterface> GetColumnDecryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<NoncePrependDecImpl>();
    }
  };

  auto enc = std::make_shared<NoncePrependEncryptor>();
  auto dec = std::make_shared<NoncePrependDecryptor>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {42, 43, 44};
  auto buf = WriteOneColumn(kColExt, values, fb.build());
  auto result = ReadOneColumn(buf, ExtDecProps(kColExt, dec));
  EXPECT_EQ(values, result);
}

// TC16: Footer key retrieved via key_retriever (KMS-style) alongside
// EXTERNAL_DBPA_V1 column using ExternalDecryptorProvider — both paths active.
TEST(TestExternalEncryptionProvider, FooterKeyMetadataWithExternalColumn) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  // Write: footer key bytes provided; footer_key_metadata stored as KMS identifier.
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.footer_key_metadata("kf");  // stored in file; used by retriever on read side
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {1, 2, 3};
  auto buf = WriteOneColumn(kColExt, values, fb.build());
  EXPECT_GT(mock_enc->call_count(), 0);

  // Read: no explicit footer_key — retriever resolves "kf" → kFooterKey.
  auto retriever = std::make_shared<StringKeyIdRetriever>();
  retriever->PutKey("kf", kFooterKey);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.key_retriever(retriever)->column_keys(dec_cols)->external_decryptor_provider(
      mock_dec);

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC17: Footer_key_metadata present in file but key_retriever returns empty key
// — must throw with a clear message at footer decryption time.
TEST(TestExternalEncryptionProvider, FooterKeyMetadataMissingRetrieverThrows) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.footer_key_metadata("kf");
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto buf = WriteOneColumn(kColExt, {1, 2, 3}, fb.build());

  // Retriever that returns empty — simulates a KMS that cannot provide the key.
  struct EmptyKeyRetriever : public DecryptionKeyRetriever {
    SecureString GetKey(const std::string& /*key_id*/) override { return {}; }
  };

  FileDecryptionProperties::Builder db;
  db.key_retriever(std::make_shared<EmptyKeyRetriever>());
  EXPECT_THROW(
      {
        ReaderProperties reader_props;
        reader_props.file_decryption_properties(db.build());
        ParquetFileReader::Open(std::make_shared< ::arrow::io::BufferReader>(buf),
                                reader_props);
      },
      ParquetException);
}

// TC-Cache1: Unencrypted column (not in encrypted_columns map) returns no data
// from the encryptor even when an ExternalEncryptorProvider is set on the file.
// The provider must NOT be called for columns that are not configured for encryption.
TEST(TestExternalEncryptionProvider, UnencryptedColumnNotPassedToProvider) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  // Two columns: only col_b is in encrypted_columns. col_a is plaintext.
  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make("col_a", Repetition::REQUIRED, Type::INT32),
                       PrimitiveNode::Make("col_b", Repetition::REQUIRED, Type::INT32)});

  ColumnPathToEncryptionPropertiesMap cols;
  ColumnEncryptionProperties::Builder cb("col_b");
  cb.key(kColumnAesKey);
  cb.key_metadata("key-b")->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
  cols["col_b"] = cb.build();  // col_a NOT in the map — stays plaintext

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder().encryption(fb.build())->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> plain_vals = {1, 2, 3};
  const std::vector<int32_t> enc_vals = {4, 5, 6};
  auto* wa = static_cast<Int32Writer*>(rg->NextColumn());
  wa->WriteBatch(plain_vals.size(), nullptr, nullptr, plain_vals.data());
  wa->Close();
  auto* wb = static_cast<Int32Writer*>(rg->NextColumn());
  wb->WriteBatch(enc_vals.size(), nullptr, nullptr, enc_vals.data());
  wb->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  // Provider called only for col_b, never for col_a.
  EXPECT_GT(mock_enc->call_count(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder db("col_b");
  dec_cols["col_b"] = db.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder dfb;
  dfb.footer_key(kFooterKey)
      ->column_keys(dec_cols)
      ->external_decryptor_provider(mock_dec);

  ReaderProperties reader_props;
  reader_props.file_decryption_properties(dfb.build());
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);
  auto rg_reader = file_reader->RowGroup(0);

  auto read_int = [&](int col_idx) {
    auto col = std::static_pointer_cast<TypedColumnReader<Int32Type> >(
        rg_reader->Column(col_idx));
    std::vector<int32_t> out(3);
    int64_t n = 0;
    col->ReadBatch(3, nullptr, nullptr, out.data(), &n);
    out.resize(static_cast<size_t>(n));
    return out;
  };

  // col_a is plaintext — value must be readable with no decryption.
  EXPECT_EQ(plain_vals, read_int(0));
  // col_b is external-encrypted — value must be recovered via provider.
  EXPECT_EQ(enc_vals, read_int(1));
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Comp1: Snappy compression + external provider — compress-then-encrypt
// ordering works end-to-end; CiphertextLength called with compressed page size.
TEST(TestExternalEncryptionProvider, SnappyCompressionWithExternalProvider) {
#  ifndef ARROW_WITH_SNAPPY
  GTEST_SKIP() << "Test requires Snappy compression";
#  endif
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  // Snappy compression: page is compressed first, then passed to external provider.
  auto writer_props = WriterProperties::Builder()
                          .compression(Compression::SNAPPY)
                          ->encryption(fb.build())
                          ->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  col->WriteBatch(values.size(), nullptr, nullptr, values.data());
  col->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);
  auto result = ReadOneColumn(buf, ExtDecProps(kColExt, mock_dec));
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Comp2: LZ4 compression + external provider — same ordering validation.
TEST(TestExternalEncryptionProvider, LZ4CompressionWithExternalProvider) {
#  ifndef ARROW_WITH_LZ4
  GTEST_SKIP() << "Test requires LZ4 compression";
#  endif
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder()
                          .compression(Compression::LZ4_HADOOP)
                          ->encryption(fb.build())
                          ->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> values = {10, 20, 30, 40, 50};
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  col->WriteBatch(values.size(), nullptr, nullptr, values.data());
  col->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);
  auto result = ReadOneColumn(buf, ExtDecProps(kColExt, mock_dec));
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Comp3: Snappy compression + nonce-prepend provider (non-zero overhead) —
// CiphertextLength must work correctly with variable compressed page sizes.
TEST(TestExternalEncryptionProvider, SnappyWithCiphertextOverheadProvider) {
#  ifndef ARROW_WITH_SNAPPY
  GTEST_SKIP() << "Test requires Snappy compression";
#  endif
  static constexpr int32_t kNonceLen = 4;

  struct NoncePrependEncImpl : public EncryptorInterface {
    bool CanCalculateCiphertextLength() const override { return true; }
    int32_t CiphertextLength(int64_t n) const override {
      return kNonceLen + static_cast<int32_t>(n);
    }
    int32_t Encrypt(std::span<const uint8_t> plain, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t> cipher,
                    std::unique_ptr<EncodingProperties>) override {
      cipher[0] = 0xDE;
      cipher[1] = 0xAD;
      cipher[2] = 0xBE;
      cipher[3] = 0xEF;
      for (size_t i = 0; i < plain.size(); ++i)
        cipher[kNonceLen + i] = static_cast<uint8_t>(plain[i] ^ 0xABu);
      return kNonceLen + static_cast<int32_t>(plain.size());
    }
    int32_t EncryptWithManagedBuffer(std::span<const uint8_t>, ::arrow::ResizableBuffer*,
                                     std::unique_ptr<EncodingProperties>) override {
      throw ParquetException("not expected in this test");
    }
    int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<uint8_t>) override {
      throw ParquetException("not supported");
    }
  };
  struct NoncePrependDecImpl : public DecryptorInterface {
    bool CanCalculateLengths() const override { return true; }
    int32_t PlaintextLength(int32_t n) const override { return n - kNonceLen; }
    int32_t CiphertextLength(int32_t n) const override { return n; }
    int32_t Decrypt(std::span<const uint8_t> cipher, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t> plain,
                    std::unique_ptr<EncodingProperties>) override {
      for (size_t i = 0; i < plain.size(); ++i)
        plain[i] = static_cast<uint8_t>(cipher[kNonceLen + i] ^ 0xABu);
      return static_cast<int32_t>(plain.size());
    }
    int32_t DecryptWithManagedBuffer(std::span<const uint8_t>, ::arrow::ResizableBuffer*,
                                     std::unique_ptr<EncodingProperties>) override {
      throw ParquetException("not expected in this test");
    }
  };
  struct NoncePrependEncryptor : public ExternalEncryptorProvider {
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<NoncePrependEncImpl>();
    }
  };
  struct NoncePrependDecryptor : public ExternalDecryptorProvider {
    std::unique_ptr<DecryptorInterface> GetColumnDecryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<NoncePrependDecImpl>();
    }
  };

  auto enc = std::make_shared<NoncePrependEncryptor>();
  auto dec = std::make_shared<NoncePrependDecryptor>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(enc)->encrypted_columns(cols);

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder()
                          .compression(Compression::SNAPPY)
                          ->encryption(fb.build())
                          ->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> values = {100, 200, 300, 400, 500};
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  col->WriteBatch(values.size(), nullptr, nullptr, values.data());
  col->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols)->external_decryptor_provider(dec);

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
}

// TC-Aad1: aad_prefix set on FileEncryptionProperties alongside external provider
// — the prefix is stored in the file and must be supplied on the read side.
// The external adapter ignores the AAD, but the footer AAD verification must pass.
TEST(TestExternalEncryptionProvider, AadPrefixWithExternalProvider) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  const std::string kAadPrefix = "my-app-v1";
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.aad_prefix(kAadPrefix);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {1, 2, 3};
  auto buf = WriteOneColumn(kColExt, values, fb.build());
  EXPECT_GT(mock_enc->call_count(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  // Reader must supply the same aad_prefix for footer verification.
  db.footer_key(kFooterKey)
      ->aad_prefix(kAadPrefix)
      ->column_keys(dec_cols)
      ->external_decryptor_provider(mock_dec);

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Aad2: disable_aad_prefix_storage() — prefix not stored in file; reader must
// supply it explicitly via aad_prefix(). External adapter still ignores AAD.
TEST(TestExternalEncryptionProvider, AadPrefixNotStoredWithExternalProvider) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);

  const std::string kAadPrefix = "app-prefix-not-stored";
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.aad_prefix(kAadPrefix);
  fb.disable_aad_prefix_storage();  // prefix NOT written into the file
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {10, 20, 30};
  auto buf = WriteOneColumn(kColExt, values, fb.build());
  EXPECT_GT(mock_enc->call_count(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  // Reader must supply aad_prefix explicitly since it was not stored.
  db.footer_key(kFooterKey)
      ->aad_prefix(kAadPrefix)
      ->column_keys(dec_cols)
      ->external_decryptor_provider(mock_dec);

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Enc1: FIXED_LEN_BYTE_ARRAY column with external provider — EncodingProperties
// carries fixed_length_bytes but the adapter drops it; round-trip must still work.
TEST(TestExternalEncryptionProvider, FixedLenByteArrayColumnRoundTrip) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  constexpr int kFlbaLen = 8;
  auto schema_node = GroupNode::Make(
      "schema", Repetition::REQUIRED,
      {PrimitiveNode::Make("flba_col", Repetition::REQUIRED, Type::FIXED_LEN_BYTE_ARRAY,
                           ConvertedType::NONE, kFlbaLen)});

  ColumnEncryptionProperties::Builder cb("flba_col");
  cb.key(kColumnAesKey);
  cb.key_metadata("flba-key")->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
  ColumnPathToEncryptionPropertiesMap cols;
  cols["flba_col"] = cb.build();

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder().encryption(fb.build())->build();
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();

  // Write three 8-byte fixed-length values.
  const std::string kVal1 = "ABCDEFGH";
  const std::string kVal2 = "12345678";
  const std::string kVal3 = "abcdefgh";
  std::vector<parquet::ByteArray> values = {
      {kFlbaLen, reinterpret_cast<const uint8_t*>(kVal1.data())},
      {kFlbaLen, reinterpret_cast<const uint8_t*>(kVal2.data())},
      {kFlbaLen, reinterpret_cast<const uint8_t*>(kVal3.data())}};
  auto* col = static_cast<FixedLenByteArrayWriter*>(rg->NextColumn());
  std::vector<FixedLenByteArray> flba_vals;
  for (auto& v : values) flba_vals.push_back(FixedLenByteArray{v.ptr});
  col->WriteBatch(flba_vals.size(), nullptr, nullptr, flba_vals.data());
  col->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb("flba_col");
  dec_cols["flba_col"] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols)->external_decryptor_provider(mock_dec);

  ReaderProperties reader_props;
  reader_props.file_decryption_properties(db.build());
  auto file_reader = ParquetFileReader::Open(
      std::make_shared< ::arrow::io::BufferReader>(buf), reader_props);
  auto rg_reader = file_reader->RowGroup(0);
  auto col_reader =
      std::static_pointer_cast<TypedColumnReader<FLBAType> >(rg_reader->Column(0));
  std::vector<FixedLenByteArray> out(flba_vals.size());
  int64_t n = 0;
  col_reader->ReadBatch(static_cast<int>(flba_vals.size()), nullptr, nullptr, out.data(),
                        &n);
  ASSERT_EQ(static_cast<int64_t>(flba_vals.size()), n);
  for (size_t i = 0; i < flba_vals.size(); ++i)
    EXPECT_EQ(0, std::memcmp(flba_vals[i].ptr, out[i].ptr, kFlbaLen)) << "value " << i;
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Enc2: Dictionary encoding + external provider — dictionary pages go through
// the same Encryptor::Encrypt() path as data pages; round-trip must work.
TEST(TestExternalEncryptionProvider, DictionaryEncodedColumnRoundTrip) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  // Enable dictionary encoding — causes a dictionary page to be written.
  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props =
      WriterProperties::Builder().enable_dictionary()->encryption(fb.build())->build();
  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  // Repeated values cause dictionary encoding.
  std::vector<int32_t> values(50, 42);
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  col->WriteBatch(values.size(), nullptr, nullptr, values.data());
  col->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);
  auto result = ReadOneColumn(buf, ExtDecProps(kColExt, mock_dec));
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Enc3: DataPage V2 format + external provider — V2 pages have a different
// serialization (levels not encoded into compressed payload) but same encrypt path.
TEST(TestExternalEncryptionProvider, DataPageV2WithExternalProvider) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();
  auto mock_dec = std::make_shared<MockDecryptorProvider>();

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder()
                          .data_page_version(ParquetDataPageVersion::V2)
                          ->encryption(fb.build())
                          ->build();
  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});
  auto file_writer = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = file_writer->AppendRowGroup();
  const std::vector<int32_t> values = {1, 2, 3, 4, 5};
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  col->WriteBatch(values.size(), nullptr, nullptr, values.data());
  col->Close();
  file_writer->Close();
  auto buf = sink->Finish().ValueOrDie();

  EXPECT_GT(mock_enc->call_count(), 0);
  auto result = ReadOneColumn(buf, ExtDecProps(kColExt, mock_dec));
  EXPECT_EQ(values, result);
  EXPECT_GT(mock_dec->call_count(), 0);
}

// TC-Thread1: Two writers sharing the same provider instance write concurrently —
// no data race; call_count is atomic so both increments are visible.
TEST(TestExternalEncryptionProvider, ConcurrentWritesWithSharedProvider) {
  auto mock_enc = std::make_shared<MockEncryptorProvider>();

  auto write_file = [&]() -> std::shared_ptr< ::arrow::Buffer> {
    ColumnPathToEncryptionPropertiesMap cols;
    cols[kColExt] = ExtColProps(kColExt);
    FileEncryptionProperties::Builder fb(kFooterKey);
    fb.external_encryptor_provider(mock_enc)->encrypted_columns(cols);
    return WriteOneColumn(kColExt, {1, 2, 3}, fb.build());
  };

  std::shared_ptr< ::arrow::Buffer> buf1, buf2;
  std::thread t1([&]() { buf1 = write_file(); });
  std::thread t2([&]() { buf2 = write_file(); });
  t1.join();
  t2.join();

  EXPECT_GT(mock_enc->call_count(), 0);

  auto dec1 = std::make_shared<MockDecryptorProvider>();
  auto dec2 = std::make_shared<MockDecryptorProvider>();
  const std::vector<int32_t> expected = {1, 2, 3};
  EXPECT_EQ(expected, ReadOneColumn(buf1, ExtDecProps(kColExt, dec1)));
  EXPECT_EQ(expected, ReadOneColumn(buf2, ExtDecProps(kColExt, dec2)));
}

// TC-Err1: Provider encryptor throws — exception propagates out of WriteOneColumn.
TEST(TestExternalEncryptionProvider, ProviderEncryptThrowsPropagates) {
  struct ThrowingProvider : public ExternalEncryptorProvider {
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams&) override {
      struct ThrowingEncryptor : public EncryptorInterface {
        bool CanCalculateCiphertextLength() const override { return true; }
        int32_t CiphertextLength(int64_t n) const override {
          return static_cast<int32_t>(n);
        }
        int32_t Encrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                        std::span<const uint8_t>, std::span<uint8_t>,
                        std::unique_ptr<EncodingProperties>) override {
          throw std::runtime_error("provider failure");
        }
        int32_t EncryptWithManagedBuffer(std::span<const uint8_t>,
                                         ::arrow::ResizableBuffer*,
                                         std::unique_ptr<EncodingProperties>) override {
          throw std::runtime_error("provider failure");
        }
        int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<uint8_t>) override {
          throw ParquetException("not supported");
        }
      };
      return std::make_unique<ThrowingEncryptor>();
    }
  };

  auto enc = std::make_shared<ThrowingProvider>();
  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(enc)->encrypted_columns(cols);

  EXPECT_THROW(WriteOneColumn(kColExt, {1, 2, 3}, fb.build()), std::exception);
}

// TC14: params.data_type passed to GetColumnEncryptor() matches the column physical type.
TEST(TestExternalEncryptionProvider, DataTypeInParamsMatchesColumnSchema) {
  Type::type captured_type = Type::BOOLEAN;  // sentinel; must become INT32 after write
  struct DataTypeCapturingProvider : public ExternalEncryptorProvider {
    Type::type& out;
    explicit DataTypeCapturingProvider(Type::type& t) : out(t) {}
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams& params) override {
      out = params.data_type;
      struct XorEnc : public EncryptorInterface {
        bool CanCalculateCiphertextLength() const override { return true; }
        int32_t CiphertextLength(int64_t n) const override {
          return static_cast<int32_t>(n);
        }
        int32_t Encrypt(std::span<const uint8_t> plain, std::span<const uint8_t>,
                        std::span<const uint8_t>, std::span<uint8_t> cipher,
                        std::unique_ptr<EncodingProperties>) override {
          std::transform(plain.begin(), plain.end(), cipher.begin(),
                         [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
          return static_cast<int32_t>(plain.size());
        }
        int32_t EncryptWithManagedBuffer(std::span<const uint8_t>,
                                         ::arrow::ResizableBuffer*,
                                         std::unique_ptr<EncodingProperties>) override {
          throw ParquetException("not expected in this test");
        }
        int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<uint8_t>) override {
          throw ParquetException("not supported");
        }
      };
      return std::make_unique<XorEnc>();
    }
  };

  auto cap = std::make_shared<DataTypeCapturingProvider>(captured_type);
  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(cap)->encrypted_columns(cols);

  ASSERT_NO_THROW(WriteOneColumn(kColExt, {1, 2, 3}, fb.build()));
  EXPECT_EQ(captured_type, Type::INT32);
}

// TC-Managed1: CanCalculateCiphertextLength()=false forces EncryptWithManagedBuffer();
// Encrypt() is never called; EncodingProperties is non-null; round-trip recovers values.
TEST(TestExternalEncryptionProvider, ManagedBufferPathRoundTrip) {
  std::atomic<int> enc_managed_calls{0};
  std::atomic<int> dec_managed_calls{0};

  struct ManagedEncImpl : public EncryptorInterface {
    std::atomic<int>& calls;
    explicit ManagedEncImpl(std::atomic<int>& c) : calls(c) {}
    bool CanCalculateCiphertextLength() const override { return false; }
    int32_t CiphertextLength(int64_t) const override { return -1; }
    int32_t Encrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t>,
                    std::unique_ptr<EncodingProperties>) override {
      throw ParquetException(
          "Encrypt() must not be called when CanCalculateCiphertextLength=false");
    }
    int32_t EncryptWithManagedBuffer(std::span<const uint8_t> plain,
                                     ::arrow::ResizableBuffer* cipher,
                                     std::unique_ptr<EncodingProperties> props) override {
      if (!props)
        throw ParquetException("EncodingProperties is null in EncryptWithManagedBuffer");
      PARQUET_THROW_NOT_OK(cipher->Resize(static_cast<int64_t>(plain.size())));
      std::transform(plain.begin(), plain.end(), cipher->mutable_data(),
                     [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
      ++calls;
      return static_cast<int32_t>(plain.size());
    }
    int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<uint8_t>) override {
      throw ParquetException("not supported");
    }
  };
  struct ManagedDecImpl : public DecryptorInterface {
    std::atomic<int>& calls;
    explicit ManagedDecImpl(std::atomic<int>& c) : calls(c) {}
    bool CanCalculateLengths() const override { return false; }
    int32_t PlaintextLength(int32_t) const override { return -1; }
    int32_t CiphertextLength(int32_t n) const override { return n; }
    int32_t Decrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t>,
                    std::unique_ptr<EncodingProperties>) override {
      throw ParquetException(
          "Decrypt() must not be called when CanCalculateLengths=false");
    }
    int32_t DecryptWithManagedBuffer(std::span<const uint8_t> cipher,
                                     ::arrow::ResizableBuffer* plain,
                                     std::unique_ptr<EncodingProperties> props) override {
      if (!props)
        throw ParquetException("EncodingProperties is null in DecryptWithManagedBuffer");
      PARQUET_THROW_NOT_OK(plain->Resize(static_cast<int64_t>(cipher.size())));
      std::transform(cipher.begin(), cipher.end(), plain->mutable_data(),
                     [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
      ++calls;
      return static_cast<int32_t>(cipher.size());
    }
  };
  struct ManagedEncProvider : public ExternalEncryptorProvider {
    std::atomic<int>& calls;
    explicit ManagedEncProvider(std::atomic<int>& c) : calls(c) {}
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<ManagedEncImpl>(calls);
    }
  };
  struct ManagedDecProvider : public ExternalDecryptorProvider {
    std::atomic<int>& calls;
    explicit ManagedDecProvider(std::atomic<int>& c) : calls(c) {}
    std::unique_ptr<DecryptorInterface> GetColumnDecryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<ManagedDecImpl>(calls);
    }
  };

  auto enc = std::make_shared<ManagedEncProvider>(enc_managed_calls);
  auto dec = std::make_shared<ManagedDecProvider>(dec_managed_calls);

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {10, 20, 30};
  std::shared_ptr< ::arrow::Buffer> buf;
  ASSERT_NO_THROW(buf = WriteOneColumn(kColExt, values, fb.build()));
  EXPECT_GT(enc_managed_calls.load(), 0);

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols)->external_decryptor_provider(dec);

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);
  EXPECT_GT(dec_managed_calls.load(), 0);
}

// TC-Params1: params.compression_type reflects the file writer's configured codec.
TEST(TestExternalEncryptionProvider, CompressionTypeInParamsPropagated) {
#  ifndef ARROW_WITH_SNAPPY
  GTEST_SKIP() << "Test requires Snappy compression";
#  endif
  Compression::type captured = Compression::UNCOMPRESSED;  // sentinel
  struct ComprCapturingProvider : public ExternalEncryptorProvider {
    Compression::type& out;
    explicit ComprCapturingProvider(Compression::type& t) : out(t) {}
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams& params) override {
      out = params.compression_type;
      struct XorEnc : public EncryptorInterface {
        bool CanCalculateCiphertextLength() const override { return true; }
        int32_t CiphertextLength(int64_t n) const override {
          return static_cast<int32_t>(n);
        }
        int32_t Encrypt(std::span<const uint8_t> p, std::span<const uint8_t>,
                        std::span<const uint8_t>, std::span<uint8_t> c,
                        std::unique_ptr<EncodingProperties>) override {
          std::transform(p.begin(), p.end(), c.begin(),
                         [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
          return static_cast<int32_t>(p.size());
        }
        int32_t EncryptWithManagedBuffer(std::span<const uint8_t>,
                                         ::arrow::ResizableBuffer*,
                                         std::unique_ptr<EncodingProperties>) override {
          throw ParquetException("not expected");
        }
        int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<uint8_t>) override {
          throw ParquetException("not supported");
        }
      };
      return std::make_unique<XorEnc>();
    }
  };

  auto cap = std::make_shared<ComprCapturingProvider>(captured);
  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(cap)->encrypted_columns(cols);

  auto schema_node =
      GroupNode::Make("schema", Repetition::REQUIRED,
                      {PrimitiveNode::Make(kColExt, Repetition::REQUIRED, Type::INT32)});
  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder()
                          .compression(Compression::SNAPPY)
                          ->encryption(fb.build())
                          ->build();
  auto fw = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = fw->AppendRowGroup();
  auto* col = static_cast<Int32Writer*>(rg->NextColumn());
  const std::vector<int32_t> vals = {1, 2, 3};
  col->WriteBatch(vals.size(), nullptr, nullptr, vals.data());
  col->Close();
  fw->Close();

  EXPECT_EQ(captured, Compression::SNAPPY);
}

// TC-Params2: params.datatype_length is set for FIXED_LEN_BYTE_ARRAY;
// params.data_type is FIXED_LEN_BYTE_ARRAY (distinct from TC14's INT32 path).
TEST(TestExternalEncryptionProvider, FixedLenByteArrayDataTypeLengthInParams) {
  constexpr int kFlbaLen = 12;
  Type::type captured_type = Type::BOOLEAN;  // sentinel
  std::optional<int> captured_length = std::nullopt;

  struct FlbaCapturingProvider : public ExternalEncryptorProvider {
    Type::type& out_type;
    std::optional<int>& out_len;
    FlbaCapturingProvider(Type::type& t, std::optional<int>& l)
        : out_type(t), out_len(l) {}
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams& params) override {
      out_type = params.data_type;
      out_len = params.datatype_length;
      struct XorEnc : public EncryptorInterface {
        bool CanCalculateCiphertextLength() const override { return true; }
        int32_t CiphertextLength(int64_t n) const override {
          return static_cast<int32_t>(n);
        }
        int32_t Encrypt(std::span<const uint8_t> p, std::span<const uint8_t>,
                        std::span<const uint8_t>, std::span<uint8_t> c,
                        std::unique_ptr<EncodingProperties>) override {
          std::transform(p.begin(), p.end(), c.begin(),
                         [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
          return static_cast<int32_t>(p.size());
        }
        int32_t EncryptWithManagedBuffer(std::span<const uint8_t>,
                                         ::arrow::ResizableBuffer*,
                                         std::unique_ptr<EncodingProperties>) override {
          throw ParquetException("not expected");
        }
        int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<const uint8_t>, std::span<const uint8_t>,
                                    std::span<uint8_t>) override {
          throw ParquetException("not supported");
        }
      };
      return std::make_unique<XorEnc>();
    }
  };

  auto cap = std::make_shared<FlbaCapturingProvider>(captured_type, captured_length);

  auto schema_node = GroupNode::Make(
      "schema", Repetition::REQUIRED,
      {PrimitiveNode::Make("flba_col", Repetition::REQUIRED, Type::FIXED_LEN_BYTE_ARRAY,
                           ConvertedType::NONE, kFlbaLen)});

  ColumnEncryptionProperties::Builder cb("flba_col");
  cb.key(kColumnAesKey);
  cb.key_metadata("flba-key")->parquet_cipher(ParquetCipher::EXTERNAL_DBPA_V1);
  ColumnPathToEncryptionPropertiesMap cols;
  cols["flba_col"] = cb.build();

  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(cap)->encrypted_columns(cols);

  auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
  auto writer_props = WriterProperties::Builder().encryption(fb.build())->build();
  auto fw = ParquetFileWriter::Open(
      sink, std::static_pointer_cast<GroupNode>(schema_node), writer_props);
  auto rg = fw->AppendRowGroup();
  auto* col = static_cast<FixedLenByteArrayWriter*>(rg->NextColumn());
  const std::string kVal = "ABCDEFGHIJKL";  // exactly kFlbaLen bytes
  FixedLenByteArray flba{reinterpret_cast<const uint8_t*>(kVal.data())};
  col->WriteBatch(1, nullptr, nullptr, &flba);
  col->Close();
  fw->Close();

  EXPECT_EQ(captured_type, Type::FIXED_LEN_BYTE_ARRAY);
  ASSERT_TRUE(captured_length.has_value());
  EXPECT_EQ(*captured_length, kFlbaLen);
}

// TC-Params3: key_value_metadata stored by GetKeyValueMetadata() on write is
// forwarded into params.key_value_metadata on the read path via GetColumnDecryptor().
TEST(TestExternalEncryptionProvider, KeyValueMetadataRoundTripToDecryptorParams) {
  const std::string kMetaKey = "token-lookup-key";
  const std::string kMetaVal = "lookup-handle-abc";

  // Encryptor that stores one KV pair after each page via GetKeyValueMetadata().
  struct KvMetaEncImpl : public EncryptorInterface {
    std::string meta_key, meta_val;
    KvMetaEncImpl(std::string k, std::string v)
        : meta_key(std::move(k)), meta_val(std::move(v)) {}
    bool CanCalculateCiphertextLength() const override { return true; }
    int32_t CiphertextLength(int64_t n) const override { return static_cast<int32_t>(n); }
    int32_t Encrypt(std::span<const uint8_t> p, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::span<uint8_t> c,
                    std::unique_ptr<EncodingProperties>) override {
      std::transform(p.begin(), p.end(), c.begin(),
                     [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
      return static_cast<int32_t>(p.size());
    }
    int32_t EncryptWithManagedBuffer(std::span<const uint8_t>, ::arrow::ResizableBuffer*,
                                     std::unique_ptr<EncodingProperties>) override {
      throw ParquetException("not expected");
    }
    int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<const uint8_t>, std::span<const uint8_t>,
                                std::span<uint8_t>) override {
      throw ParquetException("not supported");
    }
    // Returns same KV pair for every page; column_writer deduplicates identical keys.
    std::shared_ptr< ::arrow::KeyValueMetadata> GetKeyValueMetadata(
        int8_t /*module_type*/) override {
      return ::arrow::key_value_metadata({meta_key}, {meta_val});
    }
  };
  struct KvMetaEncProvider : public ExternalEncryptorProvider {
    std::string k, v;
    KvMetaEncProvider(std::string k_, std::string v_)
        : k(std::move(k_)), v(std::move(v_)) {}
    std::unique_ptr<EncryptorInterface> GetColumnEncryptor(
        const ColumnEncryptionParams&) override {
      return std::make_unique<KvMetaEncImpl>(k, v);
    }
  };

  // Decryptor provider captures params.key_value_metadata at GetColumnDecryptor()
  // time into a shared_ptr that outlives the reader.
  std::shared_ptr<const ::arrow::KeyValueMetadata> captured_kv;
  struct KvMetaDecProvider : public ExternalDecryptorProvider {
    std::shared_ptr<const ::arrow::KeyValueMetadata>& out;
    explicit KvMetaDecProvider(std::shared_ptr<const ::arrow::KeyValueMetadata>& o)
        : out(o) {}
    std::unique_ptr<DecryptorInterface> GetColumnDecryptor(
        const ColumnEncryptionParams& params) override {
      out = params.key_value_metadata;  // captured before returning; safe after read
      struct XorDec : public DecryptorInterface {
        bool CanCalculateLengths() const override { return true; }
        int32_t PlaintextLength(int32_t n) const override { return n; }
        int32_t CiphertextLength(int32_t n) const override { return n; }
        int32_t Decrypt(std::span<const uint8_t> c, std::span<const uint8_t>,
                        std::span<const uint8_t>, std::span<uint8_t> p,
                        std::unique_ptr<EncodingProperties>) override {
          std::transform(c.begin(), c.end(), p.begin(),
                         [](uint8_t b) { return static_cast<uint8_t>(b ^ 0xABu); });
          return static_cast<int32_t>(c.size());
        }
        int32_t DecryptWithManagedBuffer(std::span<const uint8_t>,
                                         ::arrow::ResizableBuffer*,
                                         std::unique_ptr<EncodingProperties>) override {
          throw ParquetException("not expected");
        }
      };
      return std::make_unique<XorDec>();
    }
  };

  auto enc = std::make_shared<KvMetaEncProvider>(kMetaKey, kMetaVal);
  auto dec = std::make_shared<KvMetaDecProvider>(captured_kv);

  ColumnPathToEncryptionPropertiesMap cols;
  cols[kColExt] = ExtColProps(kColExt);
  FileEncryptionProperties::Builder fb(kFooterKey);
  fb.external_encryptor_provider(enc)->encrypted_columns(cols);

  const std::vector<int32_t> values = {1, 2, 3};
  auto buf = WriteOneColumn(kColExt, values, fb.build());

  ColumnPathToDecryptionPropertiesMap dec_cols;
  ColumnDecryptionProperties::Builder dcb(kColExt);
  dec_cols[kColExt] = dcb.key(kColumnAesKey)->build();
  FileDecryptionProperties::Builder db;
  db.footer_key(kFooterKey)->column_keys(dec_cols)->external_decryptor_provider(dec);

  auto result = ReadOneColumn(buf, db.build());
  EXPECT_EQ(values, result);

  ASSERT_NE(captured_kv, nullptr);
  const int64_t idx = captured_kv->FindKey(kMetaKey);
  ASSERT_GE(idx, 0);
  EXPECT_EQ(captured_kv->value(idx), kMetaVal);
}

// Symmetry contract: MockDecryptorProvider must recover exactly what
// MockEncryptorProvider encrypted — all integration round-trip tests depend on this.
TEST(TestMockProviderSymmetry, DecryptEncryptRoundTrip) {
  MockEncryptorProvider enc_provider;
  MockDecryptorProvider dec_provider;
  ColumnEncryptionParams params;
  params.key_metadata = "key-id";
  params.column_path = "col";

  auto enc = enc_provider.GetColumnEncryptor(params);
  auto dec = dec_provider.GetColumnDecryptor(params);

  const std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x7F, 0x80, 0xFF};
  std::vector<uint8_t> cipher(original.size());
  std::vector<uint8_t> recovered(original.size());

  // XorEncryptor/XorDecryptor ignore key and aad.
  enc->Encrypt(original, {}, {}, cipher, nullptr);
  dec->Decrypt(cipher, {}, {}, recovered, nullptr);

  EXPECT_EQ(original, recovered);
}

}  // namespace parquet::encryption::test

#endif  // PARQUET_REQUIRE_ENCRYPTION
