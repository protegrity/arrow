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

#include "arrow/util/compression.h"
#include "arrow/util/int_util_overflow.h"
#include "parquet/column_reader.h"
#include "parquet/encryption/encoding_properties.h"
#include "parquet/exception.h"

namespace parquet {

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

// Decompress() decodes rep/def levels; per-physical-type value decode is not yet
// implemented, so values() is left in its default (empty) state. Recompress()
// remains a throwing stub until value decode is implemented.
TypedColumnValues ParquetPageDecoder::Decompress(
    std::span<const uint8_t> compressed_page,
    const encryption::EncodingProperties& props) {
  std::vector<uint8_t> page = SplitAndDecompressDataPageV2(compressed_page, props);

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

  return result;
}

std::vector<uint8_t> ParquetPageDecoder::Recompress(
    const TypedColumnValues& values, const encryption::EncodingProperties& props) {
  throw ParquetException(
      "ParquetPageDecoder::Recompress is not implemented: the cell path is a future "
      "extension, not yet dispatched to this adapter");
}

}  // namespace parquet
