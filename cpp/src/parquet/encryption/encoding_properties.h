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

#include <map>
#include <memory>
#include <optional>
#include <string>

#include "parquet/platform.h"
#include "parquet/type_fwd.h"
#include "parquet/types.h"

namespace parquet {

class Page;

}  // namespace parquet

namespace parquet::encryption {

class PARQUET_EXPORT EncodingProperties {
 public:
  class PARQUET_EXPORT Builder {
   public:
    Builder() = default;

    // Column-level properties (required)
    Builder& ColumnPath(const std::string& column_path);
    Builder& PhysicalType(parquet::Type::type physical_type);
    Builder& CompressionCodec(::arrow::Compression::type compression_codec);
    Builder& PageType(parquet::PageType::type page_type);

    // Column-level optional fields
    Builder& FixedLengthBytes(std::int64_t fixed_length_bytes);

    // Data page properties
    Builder& PageEncoding(parquet::Encoding::type page_encoding);
    Builder& DataPageNumValues(int64_t data_page_num_values);

    // V1 data page properties
    Builder& PageV1DefinitionLevelEncoding(parquet::Encoding::type encoding);
    Builder& PageV1RepetitionLevelEncoding(parquet::Encoding::type encoding);

    // Data page common properties (apply to V1 and V2)
    Builder& DataPageMaxDefinitionLevel(int16_t level);
    Builder& DataPageMaxRepetitionLevel(int16_t level);

    // V2 data page properties
    Builder& PageV2DefinitionLevelsByteLength(int32_t byte_length);
    Builder& PageV2RepetitionLevelsByteLength(int32_t byte_length);
    Builder& PageV2NumNulls(int32_t num_nulls);
    Builder& PageV2IsCompressed(bool is_compressed);
    // Applies to DataPageV1, DataPageV2, and DictionaryPage; see
    // uncompressed_page_size_'s comment.
    Builder& UncompressedPageSize(int64_t uncompressed_page_size);

    // Dictionary page properties
    Builder& DictPageNumValues(int32_t num_values);
    Builder& DictPageIsSorted(bool is_sorted);

    // Build the final object
    std::unique_ptr<EncodingProperties> Build();

   private:
    friend class EncodingProperties;

    // Required fields
    std::optional<std::string> column_path_;
    std::optional<parquet::Type::type> physical_type_;
    std::optional<::arrow::Compression::type> compression_codec_;
    std::optional<parquet::PageType::type> page_type_;

    // column metadata
    std::optional<std::int64_t> fixed_length_bytes_;

    // data page properties
    std::optional<parquet::Encoding::type> page_encoding_;
    std::optional<int64_t> data_page_num_values_;
    std::optional<int16_t> data_page_max_definition_level_;
    std::optional<int16_t> data_page_max_repetition_level_;

    // V1 data page properties
    std::optional<parquet::Encoding::type> page_v1_definition_level_encoding_;
    std::optional<parquet::Encoding::type> page_v1_repetition_level_encoding_;

    // V2 data page properties
    std::optional<int32_t> page_v2_definition_levels_byte_length_;
    std::optional<int32_t> page_v2_repetition_levels_byte_length_;
    std::optional<int32_t> page_v2_num_nulls_;
    std::optional<bool> page_v2_is_compressed_;
    std::optional<int64_t> uncompressed_page_size_;

    // Dictionary page properties
    std::optional<int32_t> dict_page_num_values_;
    std::optional<bool> dict_page_is_sorted_;
  };  // class Builder

  // dictionary_page_uncompressed_size is only meaningful (and only read) when
  // column_page is a DictionaryPage -- unlike DataPageV2, DictionaryPage carries no
  // uncompressed-size accessor of its own, so the caller (column_writer.cc, which
  // already computes this value before compressing the page) must pass it in.
  static std::unique_ptr<EncodingProperties> MakeFromMetadata(
      const ColumnDescriptor* column_descriptor,
      const WriterProperties* writer_properties, const Page& column_page,
      std::optional<int64_t> dictionary_page_uncompressed_size = std::nullopt);

  // Setters for column-level properties
  void set_column_path(const std::string& column_path);
  void set_physical_type(
      parquet::Type::type physical_type,
      const std::optional<std::int64_t>& fixed_length_bytes = std::nullopt);
  void set_compression_codec(::arrow::Compression::type compression_codec);

  void validate();

  // False when built without a column descriptor, which leaves the physical type and
  // the max levels unset.
  [[nodiscard]] bool HasPhysicalType() const { return physical_type_.has_value(); }

  std::map<std::string, std::string> ToPropertiesMap() const;

  // Lightweight accessors to avoid building a map when only one field is needed.
  [[nodiscard]] parquet::PageType::type GetPageType() const { return page_type_; }
  [[nodiscard]] parquet::Encoding::type GetPageEncoding() const {
    return page_encoding_.value();
  }
  [[nodiscard]] parquet::Type::type GetPhysicalType() const {
    return physical_type_.value();
  }
  [[nodiscard]] int64_t GetFixedLengthBytes() const {
    return fixed_length_bytes_.value();
  }
  [[nodiscard]] ::arrow::Compression::type GetCompressionCodec() const {
    return compression_codec_.value();
  }
  [[nodiscard]] int64_t GetDataPageNumValues() const {
    return data_page_num_values_.value();
  }
  [[nodiscard]] int16_t GetDataPageMaxDefinitionLevel() const {
    return data_page_max_definition_level_.value();
  }
  [[nodiscard]] int16_t GetDataPageMaxRepetitionLevel() const {
    return data_page_max_repetition_level_.value();
  }
  [[nodiscard]] parquet::Encoding::type GetPageV1DefinitionLevelEncoding() const {
    return page_v1_definition_level_encoding_.value();
  }
  [[nodiscard]] parquet::Encoding::type GetPageV1RepetitionLevelEncoding() const {
    return page_v1_repetition_level_encoding_.value();
  }
  [[nodiscard]] int32_t GetPageV2DefinitionLevelsByteLength() const {
    return page_v2_definition_levels_byte_length_.value();
  }
  [[nodiscard]] int32_t GetPageV2RepetitionLevelsByteLength() const {
    return page_v2_repetition_levels_byte_length_.value();
  }
  [[nodiscard]] bool GetPageV2IsCompressed() const {
    return page_v2_is_compressed_.value();
  }
  [[nodiscard]] int64_t GetUncompressedPageSize() const {
    return uncompressed_page_size_.value();
  }
  [[nodiscard]] int32_t GetDictPageNumValues() const {
    return dict_page_num_values_.value();
  }

 private:
  // Private constructor for builder
  explicit EncodingProperties(const Builder& builder);

  //--------------------------------
  // from column metadata. does not change across chunks nor data pages.
  std::optional<std::string> column_path_;
  std::optional<parquet::Type::type>
      physical_type_;  // BOOLEAN, INT32, INT64, INT96, FLOAT, DOUBLE, BYTE_ARRAY,
                       // FIXED_LEN_BYTE_ARRAY, etc
  std::optional<::arrow::Compression::type> compression_codec_;

  std::optional<std::int64_t> fixed_length_bytes_;  // for FIXED_LEN_BYTE_ARRAY

  //--------------------------------
  // page type. - applies across all types of pages. non optional.
  parquet::PageType::type page_type_;  // V1, V2, DICTIONARY_PAGE

  //--------------------------------
  // from data page. changes across chunks and data pages.
  // page-level properties can be seen in parquet/column_page.h
  std::optional<parquet::Encoding::type> page_encoding_;

  // common between V1 and V2 data pages.
  std::optional<int64_t> data_page_num_values_;
  std::optional<int16_t> data_page_max_definition_level_;
  std::optional<int16_t> data_page_max_repetition_level_;

  //--------------------------------
  // V1 data page properties.
  std::optional<parquet::Encoding::type> page_v1_definition_level_encoding_;
  std::optional<parquet::Encoding::type> page_v1_repetition_level_encoding_;

  //--------------------------------
  // V2 data page properties.
  std::optional<int32_t>
      page_v2_definition_levels_byte_length_;  // note that typing is different from V1
  std::optional<int32_t>
      page_v2_repetition_levels_byte_length_;  // note that typing is different from V1
  std::optional<int32_t> page_v2_num_nulls_;
  std::optional<bool>
      page_v2_is_compressed_;  // this does not exist in V1 nor dictionary pages.
  // Whole-page (levels + values, when present) uncompressed size, i.e. the wire
  // format's PageHeader.uncompressed_page_size -- needed to one-shot decompress the
  // page without requiring a streaming Decompressor (not all codecs, e.g. Snappy,
  // implement one). Populated for DataPageV1, DataPageV2, and DictionaryPage. A V1
  // page's levels and values are compressed together as one blob (unlike V2, which
  // compresses only the values), so this is the whole-blob size for V1.
  std::optional<int64_t> uncompressed_page_size_;

  //--------------------------------
  // Dictionary page properties.
  std::optional<int32_t> dict_page_num_values_;
  std::optional<bool> dict_page_is_sorted_;

  //--------------------------------
};  // class EncodingProperties

//--------------------------------
// Parquet has no PageType-to-string helper (unlike Type, Encoding and Compression, see
// TypeToString(), EncodingToString() and Codec::GetCodecAsString()).
// Throws ParquetException for a value outside the enum.
PARQUET_EXPORT std::string EnumToString(parquet::PageType::type t);

}  // namespace parquet::encryption
