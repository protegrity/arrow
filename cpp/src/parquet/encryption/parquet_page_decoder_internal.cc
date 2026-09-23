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

#include "parquet/encryption/parquet_page_decoder_internal.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "arrow/util/bit_util.h"
#include "arrow/util/compression.h"
#include "arrow/util/int_util_overflow.h"
#include "parquet/column_reader.h"
#include "parquet/encoding.h"
#include "parquet/encryption/encoding_properties.h"
#include "parquet/exception.h"

namespace parquet {

namespace {

// Number of leaf values PLAIN encoding actually stores in the values portion of a
// page: nulls contribute a definition level below the max but no bytes at all, so
// only entries at max_definition_level are "present" and need decoding.
int64_t CountNonNullValues(const std::vector<int16_t>& definition_levels,
                           int16_t max_definition_level) {
  if (max_definition_level == 0) {
    return static_cast<int64_t>(definition_levels.size());
  }
  return std::count(definition_levels.begin(), definition_levels.end(),
                    max_definition_level);
}

// Decodes `num_non_null` PLAIN-encoded values of DType from `values_bytes` into a
// freshly allocated, tightly-sized vector.
template <typename DType>
std::vector<typename DType::c_type> DecodePlainValues(
    std::span<const uint8_t> values_bytes, int64_t num_non_null) {
  if (num_non_null < 0 || num_non_null > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid non-null value count");
  }
  if (values_bytes.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw ParquetException("ParquetPageDecoder: values buffer too large to decode");
  }
  auto decoder = MakeTypedDecoder<DType>(Encoding::PLAIN);
  decoder->SetData(static_cast<int>(num_non_null), values_bytes.data(),
                   static_cast<int>(values_bytes.size()));
  std::vector<typename DType::c_type> values(static_cast<size_t>(num_non_null));
  int decoded = decoder->Decode(values.data(), static_cast<int>(num_non_null));
  if (decoded != static_cast<int>(num_non_null)) {
    throw ParquetException("ParquetPageDecoder: failed to decode all values");
  }
  return values;
}

// Decodes `num_non_null` PLAIN-encoded BOOLEAN values into a bit-packed buffer,
// matching Parquet's on-disk PLAIN BOOLEAN layout exactly (LSB-first) -- no
// unpacking to one-bool-per-byte, since CryptoValueBuffer's BOOLEAN alternative
// is the packed span<uint8_t> itself (see parquet_crypto_provider.h).
std::vector<uint8_t> DecodePlainBooleanValues(std::span<const uint8_t> values_bytes,
                                              int64_t num_non_null) {
  if (num_non_null < 0 || num_non_null > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid non-null value count");
  }
  if (values_bytes.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw ParquetException("ParquetPageDecoder: values buffer too large to decode");
  }
  auto decoder = MakeTypedDecoder<BooleanType>(Encoding::PLAIN);
  decoder->SetData(static_cast<int>(num_non_null), values_bytes.data(),
                   static_cast<int>(values_bytes.size()));
  std::vector<uint8_t> packed(
      static_cast<size_t>(::arrow::bit_util::BytesForBits(num_non_null)));
  int decoded = decoder->Decode(packed.data(), static_cast<int>(num_non_null));
  if (decoded != static_cast<int>(num_non_null)) {
    throw ParquetException("ParquetPageDecoder: failed to decode all values");
  }
  return packed;
}

// Copies `num_non_null * type_length` raw bytes out of `values_bytes` for a
// FIXED_LEN_BYTE_ARRAY column. PLAIN FIXED_LEN_BYTE_ARRAY has no per-value framing
// at all (schema-fixed width, no length prefix), so this is a straight copy rather
// than a decoder call -- deliberately avoids FLBADecoder/DecodePlain<FixedLenByteArray>,
// which return FixedLenByteArray structs whose `ptr` aliases the original page buffer
// (see decoder.cc); that buffer is a local variable in Decompress() and would leave
// CryptoValueBuffer's span dangling once this function returns.
std::vector<uint8_t> DecodePlainFixedLenByteArrayValues(
    std::span<const uint8_t> values_bytes, int64_t num_non_null, int64_t type_length) {
  if (num_non_null < 0 || type_length < 0) {
    throw ParquetException("ParquetPageDecoder: invalid FIXED_LEN_BYTE_ARRAY parameters");
  }
  int64_t total_bytes = 0;
  if (::arrow::internal::MultiplyWithOverflow(num_non_null, type_length, &total_bytes) ||
      total_bytes > static_cast<int64_t>(values_bytes.size())) {
    throw ParquetException(
        "ParquetPageDecoder: FIXED_LEN_BYTE_ARRAY values exceed the page buffer");
  }
  return std::vector<uint8_t>(values_bytes.begin(),
                              values_bytes.begin() + static_cast<size_t>(total_bytes));
}

}  // namespace

std::vector<uint8_t> ParquetPageDecoder::SplitAndDecompressDataPageV2(
    std::span<const uint8_t> page, const encryption::EncodingProperties& props) {
  if (props.GetPageType() != PageType::DATA_PAGE_V2) {
    throw ParquetException(
        "ParquetPageDecoder::SplitAndDecompressDataPageV2 only supports DataPageV2 "
        "pages");
  }

  // Matches column_reader.cc's SerializedPageReader::NextPage() level-length
  // addition: an overflow-checked int32 add (level lengths are int32_t on the
  // wire), widened to int64_t only for the buffer-size comparison below.
  int32_t levels_len = 0;
  if (::arrow::internal::AddWithOverflow(props.GetPageV2DefinitionLevelsByteLength(),
                                         props.GetPageV2RepetitionLevelsByteLength(),
                                         &levels_len) ||
      levels_len < 0 ||
      static_cast<int64_t>(levels_len) > static_cast<int64_t>(page.size())) {
    throw ParquetException(
        "ParquetPageDecoder: DataPageV2 level byte lengths exceed the page buffer");
  }

  std::span<const uint8_t> levels = page.subspan(0, static_cast<size_t>(levels_len));
  std::span<const uint8_t> values_portion = page.subspan(static_cast<size_t>(levels_len));

  std::vector<uint8_t> decompressed_values;
  if (!props.GetPageV2IsCompressed()) {
    decompressed_values.assign(values_portion.begin(), values_portion.end());
  } else {
    // PageV2UncompressedPageSize is the whole page (levels + values); subtract the
    // level bytes to get the values' one-shot decompression output size. A known
    // output size lets this use Codec::Decompress() directly instead of a
    // streaming Decompressor, which not every codec implements (e.g. Snappy).
    const int64_t uncompressed_values_len =
        props.GetPageV2UncompressedPageSize() - static_cast<int64_t>(levels_len);
    if (uncompressed_values_len < 0) {
      throw ParquetException(
          "ParquetPageDecoder: DataPageV2 uncompressed page size is smaller than "
          "its level byte lengths");
    }
    decompressed_values.resize(static_cast<size_t>(uncompressed_values_len));
    if (uncompressed_values_len > 0) {
      // A page may have zero values when every row is null (GH-31992); some
      // codecs reject a zero-length compressed input, so skip the call entirely.
      PARQUET_ASSIGN_OR_THROW(auto codec,
                              ::arrow::util::Codec::Create(props.GetCompressionCodec()));
      PARQUET_ASSIGN_OR_THROW(
          int64_t actual_len,
          codec->Decompress(static_cast<int64_t>(values_portion.size()),
                            values_portion.data(), uncompressed_values_len,
                            decompressed_values.data()));
      if (actual_len != uncompressed_values_len) {
        throw ParquetException(
            "ParquetPageDecoder: DataPageV2 values did not decompress to the "
            "expected size");
      }
    }
  }

  // One contiguous buffer, levels then values -- mirrors DataPageV2's own
  // single-buffer-plus-offset convention instead of returning a span/vector pair.
  std::vector<uint8_t> result;
  result.reserve(levels.size() + decompressed_values.size());
  result.insert(result.end(), levels.begin(), levels.end());
  result.insert(result.end(), decompressed_values.begin(), decompressed_values.end());
  return result;
}

// Decompress() decodes rep/def levels and, for PLAIN-encoded fixed-width types
// (numeric, BOOLEAN, FIXED_LEN_BYTE_ARRAY), the values themselves. BYTE_ARRAY value
// decode is not yet implemented. Recompress() remains a throwing stub until value
// decode is implemented for every physical type.
TypedColumnValues ParquetPageDecoder::Decompress(
    std::span<const uint8_t> compressed_page,
    const encryption::EncodingProperties& props) {
  std::vector<uint8_t> page = SplitAndDecompressDataPageV2(compressed_page, props);

  if (props.GetPageEncoding() != Encoding::PLAIN) {
    throw ParquetException(
        "ParquetPageDecoder::Decompress: only PLAIN value encoding is currently "
        "supported");
  }

  TypedColumnValues result(props.GetPhysicalType(), props.GetDataPageMaxDefinitionLevel(),
                           props.GetDataPageMaxRepetitionLevel());

  const int32_t rep_len = props.GetPageV2RepetitionLevelsByteLength();
  const int32_t def_len = props.GetPageV2DefinitionLevelsByteLength();
  const int64_t num_values = props.GetDataPageNumValues();
  if (num_values < 0 || num_values > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid DataPageV2 num_values");
  }

  const uint8_t* buffer = page.data();

  // Matches TypedColumnValues's documented contract: repetition_levels() stays
  // empty for non-repeated (non-list) columns, unlike definition_levels() (below),
  // which is always fully populated.
  if (result.max_repetition_level() > 0) {
    LevelDecoder rep_decoder(result.max_repetition_level());
    rep_decoder.SetDataV2(rep_len, result.max_repetition_level(),
                          static_cast<int>(num_values), buffer);
    result.repetition_levels().resize(static_cast<size_t>(num_values));
    int decoded = rep_decoder.Decode(static_cast<int>(num_values),
                                     result.repetition_levels().data());
    if (decoded != static_cast<int>(num_values)) {
      throw ParquetException(
          "ParquetPageDecoder: failed to decode all repetition levels");
    }
  }
  // Unconditional: some writers emit repetition-level bytes even when
  // max_repetition_level()==0 (mirrors column_reader.cc's ARROW-17453 fix).
  buffer += rep_len;

  // definition_levels() is always fully populated, even for a required (no-null)
  // column -- TypedColumnValues::num_values() relies on its size to report the
  // page's total logical value count.
  result.definition_levels().resize(static_cast<size_t>(num_values));
  if (result.max_definition_level() > 0) {
    LevelDecoder def_decoder(result.max_definition_level());
    def_decoder.SetDataV2(def_len, result.max_definition_level(),
                          static_cast<int>(num_values), buffer);
    int decoded = def_decoder.Decode(static_cast<int>(num_values),
                                     result.definition_levels().data());
    if (decoded != static_cast<int>(num_values)) {
      throw ParquetException(
          "ParquetPageDecoder: failed to decode all definition levels");
    }
  } else {
    // Required column: every value is present, definition level 0 for all.
    std::fill(result.definition_levels().begin(), result.definition_levels().end(), 0);
  }
  // Unconditional for the same reason as the repetition-level advance above --
  // buffer must reach the values portion regardless of whether def_len was 0.
  buffer += def_len;

  // Defensive: SplitAndDecompressDataPageV2() already guarantees rep_len+def_len
  // fits within page.size(), but that invariant is established in a different
  // function -- re-check here rather than rely on it silently holding, since a
  // violation would otherwise underflow the size passed to values_bytes below.
  if (buffer > page.data() + page.size()) {
    throw ParquetException("ParquetPageDecoder: level bytes exceed the page buffer");
  }

  const int64_t num_non_null =
      CountNonNullValues(result.definition_levels(), result.max_definition_level());
  std::span<const uint8_t> values_bytes(
      buffer, static_cast<size_t>(page.data() + page.size() - buffer));

  switch (result.physical_type()) {
    case Type::INT32:
      result.SetFixedWidthValues(
          DecodePlainValues<Int32Type>(values_bytes, num_non_null));
      break;
    case Type::INT64:
      result.SetFixedWidthValues(
          DecodePlainValues<Int64Type>(values_bytes, num_non_null));
      break;
    case Type::INT96:
      result.SetFixedWidthValues(
          DecodePlainValues<Int96Type>(values_bytes, num_non_null));
      break;
    case Type::FLOAT:
      result.SetFixedWidthValues(
          DecodePlainValues<FloatType>(values_bytes, num_non_null));
      break;
    case Type::DOUBLE:
      result.SetFixedWidthValues(
          DecodePlainValues<DoubleType>(values_bytes, num_non_null));
      break;
    case Type::BOOLEAN:
      result.SetFixedWidthValues(DecodePlainBooleanValues(values_bytes, num_non_null));
      break;
    case Type::FIXED_LEN_BYTE_ARRAY:
      result.SetFixedWidthValues(DecodePlainFixedLenByteArrayValues(
          values_bytes, num_non_null, props.GetFixedLengthBytes()));
      break;
    case Type::BYTE_ARRAY:
      throw ParquetException(
          "ParquetPageDecoder::Decompress: value decoding for this physical type is "
          "not yet implemented");
    case Type::UNDEFINED:
    default:
      throw ParquetException("ParquetPageDecoder: unsupported physical type");
  }

  return result;
}

std::vector<uint8_t> ParquetPageDecoder::Recompress(
    const TypedColumnValues& values, const encryption::EncodingProperties& props) {
  throw ParquetException(
      "ParquetPageDecoder::Recompress is not implemented: the cell path is a future "
      "extension, not yet dispatched to this adapter");
}

}  // namespace parquet
