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
// Covers ParquetPageDecoder::SplitAndDecompressDataPageV2() (the levels/values
// buffer-framing step) and Decompress()'s rep/def level decoding.
// Per-physical-type value decode and Recompress() remain unimplemented.

#include <cstdint>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "arrow/testing/gtest_util.h"
#include "arrow/util/compression.h"
#include "parquet/column_writer.h"

#include "parquet/encryption/encoding_properties.h"
#include "parquet/encryption/parquet_page_decoder_internal.h"
#include "parquet/exception.h"
#include "parquet/types.h"

namespace parquet::encryption::test {

namespace {

std::unique_ptr<EncodingProperties> MakeDataPageV2Props(
    int32_t definition_levels_byte_length, int32_t repetition_levels_byte_length,
    bool is_compressed,
    ::arrow::Compression::type codec = ::arrow::Compression::UNCOMPRESSED,
    int64_t uncompressed_page_size = 0) {
  return EncodingProperties::Builder()
      .PageType(PageType::DATA_PAGE_V2)
      .PageEncoding(Encoding::PLAIN)
      .CompressionCodec(codec)
      .PageV2DefinitionLevelsByteLength(definition_levels_byte_length)
      .PageV2RepetitionLevelsByteLength(repetition_levels_byte_length)
      .PageV2NumNulls(0)
      .PageV2IsCompressed(is_compressed)
      .PageV2UncompressedPageSize(uncompressed_page_size)
      .DataPageNumValues(0)
      .DataPageMaxDefinitionLevel(0)
      .DataPageMaxRepetitionLevel(0)
      .Build();
}

// RLE-encodes `levels` the same way column_writer.cc's BuildDataPageV2() does,
// via the real (encode-side) LevelEncoder -- so Decompress() is tested against
// genuine on-wire bytes, not a hand-crafted stand-in.
std::vector<uint8_t> EncodeLevelsRLE(const std::vector<int16_t>& levels,
                                     int16_t max_level) {
  std::vector<uint8_t> buffer(LevelEncoder::MaxBufferSize(
      Encoding::RLE, max_level, static_cast<int>(levels.size())));
  LevelEncoder encoder;
  encoder.Init(Encoding::RLE, max_level, static_cast<int>(levels.size()), buffer.data(),
               static_cast<int>(buffer.size()));
  int num_encoded = encoder.Encode(static_cast<int>(levels.size()), levels.data());
  if (num_encoded != static_cast<int>(levels.size())) {
    throw ParquetException("EncodeLevelsRLE: failed to encode all levels");
  }
  buffer.resize(static_cast<size_t>(encoder.len()));
  return buffer;
}

std::unique_ptr<EncodingProperties> MakeDataPageV2PropsForDecompress(
    int32_t definition_levels_byte_length, int32_t repetition_levels_byte_length,
    int64_t num_values, int16_t max_definition_level, int16_t max_repetition_level) {
  return EncodingProperties::Builder()
      .PageType(PageType::DATA_PAGE_V2)
      .PhysicalType(Type::INT32)
      .PageEncoding(Encoding::PLAIN)
      .CompressionCodec(::arrow::Compression::UNCOMPRESSED)
      .PageV2DefinitionLevelsByteLength(definition_levels_byte_length)
      .PageV2RepetitionLevelsByteLength(repetition_levels_byte_length)
      .PageV2NumNulls(0)
      .PageV2IsCompressed(false)
      .DataPageNumValues(num_values)
      .DataPageMaxDefinitionLevel(max_definition_level)
      .DataPageMaxRepetitionLevel(max_repetition_level)
      .Build();
}

}  // namespace

TEST(ParquetPageDecoderTest, UncompressedValuesSplitVerbatim) {
  const std::vector<uint8_t> levels = {1, 2, 3, 4};
  const std::vector<uint8_t> values = {10, 20, 30, 40, 50};
  std::vector<uint8_t> page = levels;
  page.insert(page.end(), values.begin(), values.end());

  auto props = MakeDataPageV2Props(/*definition_levels_byte_length=*/2,
                                   /*repetition_levels_byte_length=*/2,
                                   /*is_compressed=*/false);

  auto result = ParquetPageDecoder::SplitAndDecompressDataPageV2(page, *props);
  ASSERT_EQ(result.size(), levels.size() + values.size());
  EXPECT_EQ(std::vector<uint8_t>(result.begin(), result.begin() + levels.size()), levels);
  EXPECT_EQ(std::vector<uint8_t>(result.begin() + levels.size(), result.end()), values);
}

TEST(ParquetPageDecoderTest, CompressedValuesDecompressToOriginal) {
  // Pick whichever real codec this build actually compiled in -- host dev
  // builds commonly disable all optional compression libraries.
  ::arrow::Compression::type codec_type = ::arrow::Compression::UNCOMPRESSED;
  bool found_codec = false;
  for (auto candidate : {::arrow::Compression::SNAPPY, ::arrow::Compression::GZIP,
                         ::arrow::Compression::ZSTD, ::arrow::Compression::LZ4,
                         ::arrow::Compression::BROTLI, ::arrow::Compression::BZ2}) {
    if (::arrow::util::Codec::IsAvailable(candidate)) {
      codec_type = candidate;
      found_codec = true;
      break;
    }
  }
  if (!found_codec) {
    GTEST_SKIP() << "No optional compression codec built into this Arrow build";
  }

  const std::vector<uint8_t> levels = {9, 8, 7};
  const std::vector<uint8_t> values(1000, 0x5A);  // Highly compressible.

  ASSERT_OK_AND_ASSIGN(auto codec, ::arrow::util::Codec::Create(codec_type));
  std::vector<uint8_t> compressed(
      codec->MaxCompressedLen(static_cast<int64_t>(values.size()), values.data()));
  ASSERT_OK_AND_ASSIGN(
      int64_t compressed_len,
      codec->Compress(static_cast<int64_t>(values.size()), values.data(),
                      static_cast<int64_t>(compressed.size()), compressed.data()));
  compressed.resize(static_cast<size_t>(compressed_len));

  std::vector<uint8_t> page = levels;
  page.insert(page.end(), compressed.begin(), compressed.end());

  auto props = MakeDataPageV2Props(
      /*definition_levels_byte_length=*/2,
      /*repetition_levels_byte_length=*/1,
      /*is_compressed=*/true, codec_type,
      /*uncompressed_page_size=*/static_cast<int64_t>(levels.size() + values.size()));

  auto result = ParquetPageDecoder::SplitAndDecompressDataPageV2(page, *props);
  ASSERT_EQ(result.size(), levels.size() + values.size());
  EXPECT_EQ(std::vector<uint8_t>(result.begin(), result.begin() + levels.size()), levels);
  EXPECT_EQ(std::vector<uint8_t>(result.begin() + levels.size(), result.end()), values);
}

TEST(ParquetPageDecoderTest, RejectsNonDataPageV2) {
  auto props = EncodingProperties::Builder()
                   .PageType(PageType::DATA_PAGE)
                   .PageEncoding(Encoding::PLAIN)
                   .Build();
  const std::vector<uint8_t> page = {1, 2, 3};
  EXPECT_THROW(ParquetPageDecoder::SplitAndDecompressDataPageV2(page, *props),
               ParquetException);
}

TEST(ParquetPageDecoderTest, RejectsLevelLengthsExceedingBuffer) {
  auto props = MakeDataPageV2Props(/*definition_levels_byte_length=*/10,
                                   /*repetition_levels_byte_length=*/10,
                                   /*is_compressed=*/false);
  const std::vector<uint8_t> page = {1, 2, 3};
  EXPECT_THROW(ParquetPageDecoder::SplitAndDecompressDataPageV2(page, *props),
               ParquetException);
}

TEST(ParquetPageDecoderTest, DecompressFlatSchemaDefinitionLevelsOnly) {
  // OPTIONAL, non-repeated column: 5 values, 2 nulls, no repetition levels at all.
  const std::vector<int16_t> def_levels = {1, 0, 1, 1, 0};
  std::vector<uint8_t> def_bytes = EncodeLevelsRLE(def_levels, /*max_level=*/1);
  const std::vector<uint8_t> values = {1, 2, 3, 4};  // 3 present values, padded.

  std::vector<uint8_t> page = def_bytes;
  page.insert(page.end(), values.begin(), values.end());

  auto props = MakeDataPageV2PropsForDecompress(
      /*definition_levels_byte_length=*/static_cast<int32_t>(def_bytes.size()),
      /*repetition_levels_byte_length=*/0, /*num_values=*/5,
      /*max_definition_level=*/1, /*max_repetition_level=*/0);

  TypedColumnValues result = ParquetPageDecoder::Decompress(page, *props);
  EXPECT_EQ(result.physical_type(), Type::INT32);
  EXPECT_EQ(result.max_definition_level(), 1);
  EXPECT_EQ(result.max_repetition_level(), 0);
  EXPECT_EQ(result.definition_levels(), def_levels);
  EXPECT_TRUE(result.repetition_levels().empty());
  EXPECT_EQ(result.num_values(), 5);
}

TEST(ParquetPageDecoderTest, DecompressNestedSchemaDefinitionAndRepetitionLevels) {
  // repeated string field, max_definition_level=2, max_repetition_level=1:
  // row 1 = ["a", "b"], row 2 = [] (empty list), row 3 = ["c"].
  const std::vector<int16_t> def_levels = {2, 2, 0, 2};
  const std::vector<int16_t> rep_levels = {0, 1, 0, 0};
  std::vector<uint8_t> def_bytes = EncodeLevelsRLE(def_levels, /*max_level=*/2);
  std::vector<uint8_t> rep_bytes = EncodeLevelsRLE(rep_levels, /*max_level=*/1);

  std::vector<uint8_t> page = rep_bytes;
  page.insert(page.end(), def_bytes.begin(), def_bytes.end());

  auto props = MakeDataPageV2PropsForDecompress(
      /*definition_levels_byte_length=*/static_cast<int32_t>(def_bytes.size()),
      /*repetition_levels_byte_length=*/static_cast<int32_t>(rep_bytes.size()),
      /*num_values=*/4, /*max_definition_level=*/2, /*max_repetition_level=*/1);

  TypedColumnValues result = ParquetPageDecoder::Decompress(page, *props);
  EXPECT_EQ(result.definition_levels(), def_levels);
  EXPECT_EQ(result.repetition_levels(), rep_levels);
  EXPECT_EQ(result.num_values(), 4);
}

TEST(ParquetPageDecoderTest, DecompressRequiredColumnFillsImplicitDefinitionLevels) {
  // REQUIRED (non-nullable, non-repeated) column: no level bytes at all on the
  // wire, but definition_levels() must still report one entry per value (all 0).
  const std::vector<uint8_t> values = {7, 8, 9};

  auto props = MakeDataPageV2PropsForDecompress(
      /*definition_levels_byte_length=*/0, /*repetition_levels_byte_length=*/0,
      /*num_values=*/3, /*max_definition_level=*/0, /*max_repetition_level=*/0);

  TypedColumnValues result = ParquetPageDecoder::Decompress(values, *props);
  EXPECT_EQ(result.definition_levels(), (std::vector<int16_t>{0, 0, 0}));
  EXPECT_TRUE(result.repetition_levels().empty());
  EXPECT_EQ(result.num_values(), 3);
}

}  // namespace parquet::encryption::test
