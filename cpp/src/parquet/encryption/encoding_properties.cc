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

#include "parquet/encryption/encoding_properties.h"
#include "arrow/util/compression.h"
#include "parquet/column_page.h"
#include "parquet/exception.h"
#include "parquet/metadata.h"

namespace parquet::encryption {

using parquet::ColumnDescriptor;
using parquet::WriterProperties;

// Private constructor for builder
EncodingProperties::EncodingProperties(const Builder& builder)
    : column_path_(builder.column_path_),
      physical_type_(builder.physical_type_),
      compression_codec_(builder.compression_codec_),
      fixed_length_bytes_(builder.fixed_length_bytes_),
      page_type_(builder.page_type_.value()),
      page_encoding_(builder.page_encoding_),
      data_page_num_values_(builder.data_page_num_values_),
      data_page_max_definition_level_(builder.data_page_max_definition_level_),
      data_page_max_repetition_level_(builder.data_page_max_repetition_level_),
      page_v1_definition_level_encoding_(builder.page_v1_definition_level_encoding_),
      page_v1_repetition_level_encoding_(builder.page_v1_repetition_level_encoding_),
      page_v2_definition_levels_byte_length_(
          builder.page_v2_definition_levels_byte_length_),
      page_v2_repetition_levels_byte_length_(
          builder.page_v2_repetition_levels_byte_length_),
      page_v2_num_nulls_(builder.page_v2_num_nulls_),
      page_v2_is_compressed_(builder.page_v2_is_compressed_),
      uncompressed_page_size_(builder.uncompressed_page_size_),
      dict_page_num_values_(builder.dict_page_num_values_),
      dict_page_is_sorted_(builder.dict_page_is_sorted_) {}

// Checks that every property required for the page type is set.
void EncodingProperties::validate() {
  // Validate required fields
  if ((!column_path_.has_value()) || column_path_.value().empty()) {
    throw ParquetException("ColumnPath is required");
  }

  // page encoding is required for all page types (data and dictionary)
  if (!page_encoding_.has_value()) {
    throw ParquetException("PageEncoding is required");
  }

  // Validate page-level properties.
  // First, let's validate common properties across data pages.
  // DATA_PAGE is equivalent to DATA_PAGE_V1.
  if ((page_type_ == parquet::PageType::DATA_PAGE) ||
      (page_type_ == parquet::PageType::DATA_PAGE_V2)) {
    if (!data_page_num_values_.has_value()) {
      throw ParquetException("DataPageNumValues is required");
    }

    if (physical_type_ == parquet::Type::type::FIXED_LEN_BYTE_ARRAY) {
      if (!fixed_length_bytes_.has_value()) {
        throw ParquetException(
            "FixedLengthBytes is required for column page with "
            "FIXED_LEN_BYTE_ARRAY data type");
      }
    }

    if (fixed_length_bytes_.has_value()) {
      if (physical_type_ != parquet::Type::type::FIXED_LEN_BYTE_ARRAY) {
        throw ParquetException(
            "FixedLengthBytes is only allowed for FIXED_LEN_BYTE_ARRAY "
            "physical type");
      }
    }

    // max levels may be required  for decoding both data page types
    if (!data_page_max_definition_level_.has_value()) {
      throw ParquetException("DataPageMaxDefinitionLevel is required");
    }
    if (!data_page_max_repetition_level_.has_value()) {
      throw ParquetException("DataPageMaxRepetitionLevel is required");
    }
  }

  // then, let's validate properties specific to each page type.
  // DATA_PAGE is equivalent to DATA_PAGE_V1.
  if (page_type_ == parquet::PageType::DATA_PAGE) {
    if (!page_v1_definition_level_encoding_.has_value()) {
      throw ParquetException("PageV1DefinitionLevelEncoding is required");
    }
    if (!page_v1_repetition_level_encoding_.has_value()) {
      throw ParquetException("PageV1RepetitionLevelEncoding is required");
    }
  } else if (page_type_ == parquet::PageType::DATA_PAGE_V2) {
    if (!page_v2_num_nulls_.has_value()) {
      throw ParquetException("PageV2NumNulls is required");
    }
    if (!page_v2_definition_levels_byte_length_.has_value()) {
      throw ParquetException("PageV2DefinitionLevelsByteLength is required");
    }
    if (!page_v2_repetition_levels_byte_length_.has_value()) {
      throw ParquetException("PageV2RepetitionLevelsByteLength is required");
    }
    if (!page_v2_is_compressed_.has_value()) {
      throw ParquetException("PageV2IsCompressed is required");
    }
  } else if (page_type_ == parquet::PageType::DICTIONARY_PAGE) {
    if (!dict_page_num_values_.has_value()) {
      throw ParquetException("DictPageNumValues is required for DICTIONARY_PAGE");
    }
    // is_sorted is optional per the Parquet spec, so no validation needed.
  }
}  // validate()

std::unique_ptr<EncodingProperties> EncodingProperties::MakeFromMetadata(
    const ColumnDescriptor* column_descriptor, const WriterProperties* writer_properties,
    const Page& column_page, std::optional<int64_t> dictionary_page_uncompressed_size) {
  EncodingProperties::Builder builder;

  builder.ColumnPath(column_descriptor->path()->ToDotString());
  builder.PhysicalType(column_descriptor->physical_type());
  builder.CompressionCodec(writer_properties->compression(column_descriptor->path()));
  builder.PageType(column_page.type());

  // If the physical type is FIXED_LEN_BYTE_ARRAY, propagate the byte width
  // from the column descriptor so a provider has access to the length.
  // Validation also requires this for data pages.
  if (column_descriptor->physical_type() == parquet::Type::FIXED_LEN_BYTE_ARRAY) {
    builder.FixedLengthBytes(column_descriptor->type_length());
  }

  bool is_data_page = (column_page.type() == parquet::PageType::DATA_PAGE) ||
                      (column_page.type() == parquet::PageType::DATA_PAGE_V2);

  // properties common to V1 and V2 data pages.
  if (is_data_page) {
    const auto& data_page = static_cast<const DataPage&>(column_page);
    builder.PageEncoding(data_page.encoding());
    builder.DataPageNumValues(data_page.num_values());
    builder.DataPageMaxDefinitionLevel(column_descriptor->max_definition_level());
    builder.DataPageMaxRepetitionLevel(column_descriptor->max_repetition_level());
  }

  // properties specific to each type of page
  if (column_page.type() == parquet::PageType::DATA_PAGE) {
    const auto& data_page_v1 = static_cast<const DataPageV1&>(column_page);
    builder.PageV1DefinitionLevelEncoding(data_page_v1.definition_level_encoding());
    builder.PageV1RepetitionLevelEncoding(data_page_v1.repetition_level_encoding());
    builder.UncompressedPageSize(data_page_v1.uncompressed_size());
  } else if (column_page.type() == parquet::PageType::DATA_PAGE_V2) {
    const auto& data_page_v2 = static_cast<const DataPageV2&>(column_page);
    builder.PageV2DefinitionLevelsByteLength(
        data_page_v2.definition_levels_byte_length());
    builder.PageV2RepetitionLevelsByteLength(
        data_page_v2.repetition_levels_byte_length());
    builder.PageV2NumNulls(data_page_v2.num_nulls());
    builder.PageV2IsCompressed(data_page_v2.is_compressed());
    builder.UncompressedPageSize(data_page_v2.uncompressed_size());
  } else if (column_page.type() == parquet::PageType::DICTIONARY_PAGE) {
    const auto& dict_page = static_cast<const DictionaryPage&>(column_page);
    builder.PageEncoding(dict_page.encoding());
    builder.DictPageNumValues(dict_page.num_values());
    builder.DictPageIsSorted(dict_page.is_sorted());
    if (dictionary_page_uncompressed_size.has_value()) {
      builder.UncompressedPageSize(dictionary_page_uncompressed_size.value());
    }
  } else {
    throw ParquetException(std::string("Unknown Page Type:: ") +
                           EnumToString(column_page.type()));
  }

  return builder.Build();
}

std::map<std::string, std::string> EncodingProperties::ToPropertiesMap() const {
  std::map<std::string, std::string> result;

  result["column_path"] = std::string(column_path_.value());
  result["physical_type"] = TypeToString(physical_type_.value());
  result["compression_codec"] =
      ::arrow::util::Codec::GetCodecAsString(compression_codec_.value());
  result["page_type"] = EnumToString(page_type_);
  result["page_encoding"] = EncodingToString(page_encoding_.value());

  if (fixed_length_bytes_.has_value()) {
    result["fixed_length_bytes"] = std::to_string(fixed_length_bytes_.value());
  }

  if (page_type_ == parquet::PageType::DATA_PAGE ||
      page_type_ == parquet::PageType::DATA_PAGE_V2) {
    result["data_page_max_definition_level"] =
        std::to_string(data_page_max_definition_level_.value());
    result["data_page_max_repetition_level"] =
        std::to_string(data_page_max_repetition_level_.value());
  }

  if (page_type_ == parquet::PageType::DATA_PAGE) {  // DATA_PAGE_V1
    result["data_page_num_values"] = std::to_string(data_page_num_values_.value());
    result["page_v1_definition_level_encoding"] =
        EncodingToString(page_v1_definition_level_encoding_.value());
    result["page_v1_repetition_level_encoding"] =
        EncodingToString(page_v1_repetition_level_encoding_.value());
  } else if (page_type_ == parquet::PageType::DATA_PAGE_V2) {
    result["data_page_num_values"] = std::to_string(data_page_num_values_.value());
    result["page_v2_definition_levels_byte_length"] =
        std::to_string(page_v2_definition_levels_byte_length_.value());
    result["page_v2_repetition_levels_byte_length"] =
        std::to_string(page_v2_repetition_levels_byte_length_.value());
    result["page_v2_num_nulls"] = std::to_string(page_v2_num_nulls_.value());
    result["page_v2_is_compressed"] = (page_v2_is_compressed_.value() ? "true" : "false");
  } else if (page_type_ == parquet::PageType::DICTIONARY_PAGE) {
    result["dict_page_num_values"] = std::to_string(dict_page_num_values_.value());
    if (dict_page_is_sorted_.has_value()) {
      result["dict_page_is_sorted"] = (dict_page_is_sorted_.value() ? "true" : "false");
    }
  }

  return result;
}

//--------------------------------
// Builder method implementations

std::unique_ptr<EncodingProperties> EncodingProperties::Builder::Build() {
  // while we will perform validation upon construction,
  // we know that these properties are required.
  // validating here simplifies our code.

  if (!page_type_) {
    throw ParquetException("EncodingProperties::Builder::Build - PageType is required");
  }

  return std::unique_ptr<EncodingProperties>(new EncodingProperties(*this));
}

EncodingProperties::Builder& EncodingProperties::Builder::ColumnPath(
    const std::string& column_path) {
  column_path_ = column_path;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PhysicalType(
    parquet::Type::type physical_type) {
  physical_type_ = physical_type;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::CompressionCodec(
    ::arrow::Compression::type compression_codec) {
  compression_codec_ = compression_codec;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::FixedLengthBytes(
    std::int64_t fixed_length_bytes) {
  fixed_length_bytes_ = fixed_length_bytes;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PageType(
    parquet::PageType::type page_type) {
  page_type_ = page_type;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PageEncoding(
    parquet::Encoding::type page_encoding) {
  page_encoding_ = page_encoding;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::DataPageNumValues(
    int64_t data_page_num_values) {
  data_page_num_values_ = data_page_num_values;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PageV1DefinitionLevelEncoding(
    parquet::Encoding::type encoding) {
  page_v1_definition_level_encoding_ = encoding;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PageV1RepetitionLevelEncoding(
    parquet::Encoding::type encoding) {
  page_v1_repetition_level_encoding_ = encoding;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::DataPageMaxDefinitionLevel(
    int16_t level) {
  data_page_max_definition_level_ = level;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::DataPageMaxRepetitionLevel(
    int16_t level) {
  data_page_max_repetition_level_ = level;
  return *this;
}

EncodingProperties::Builder&
EncodingProperties::Builder::PageV2DefinitionLevelsByteLength(int32_t byte_length) {
  page_v2_definition_levels_byte_length_ = byte_length;
  return *this;
}

EncodingProperties::Builder&
EncodingProperties::Builder::PageV2RepetitionLevelsByteLength(int32_t byte_length) {
  page_v2_repetition_levels_byte_length_ = byte_length;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PageV2NumNulls(
    int32_t num_nulls) {
  page_v2_num_nulls_ = num_nulls;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::PageV2IsCompressed(
    bool is_compressed) {
  page_v2_is_compressed_ = is_compressed;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::UncompressedPageSize(
    int64_t uncompressed_page_size) {
  uncompressed_page_size_ = uncompressed_page_size;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::DictPageNumValues(
    int32_t num_values) {
  dict_page_num_values_ = num_values;
  return *this;
}

EncodingProperties::Builder& EncodingProperties::Builder::DictPageIsSorted(
    bool is_sorted) {
  dict_page_is_sorted_ = is_sorted;
  return *this;
}

//--------------------------------
// Setters for column-level properties
// used to fill-in values provided in the encryptor/decryptor constructor.
void EncodingProperties::set_column_path(const std::string& column_path) {
  column_path_ = column_path;
}

void EncodingProperties::set_compression_codec(
    ::arrow::Compression::type compression_codec) {
  compression_codec_ = compression_codec;
}

void EncodingProperties::set_physical_type(
    parquet::Type::type physical_type,
    const std::optional<std::int64_t>& fixed_length_bytes) {
  physical_type_ = physical_type;
  if (fixed_length_bytes.has_value()) {
    fixed_length_bytes_ = fixed_length_bytes;
  }
}

// Parquet has no PageType-to-string helper; Type, Encoding and Compression names come
// from TypeToString(), EncodingToString() and Codec::GetCodecAsString().
std::string EnumToString(parquet::PageType::type t) {
  switch (t) {
    case parquet::PageType::DATA_PAGE:
      return "DATA_PAGE_V1";
    case parquet::PageType::DATA_PAGE_V2:
      return "DATA_PAGE_V2";
    case parquet::PageType::DICTIONARY_PAGE:
      return "DICTIONARY_PAGE";
    case parquet::PageType::INDEX_PAGE:
      return "INDEX_PAGE";
    case parquet::PageType::UNDEFINED:
      return "UNDEFINED";
    default:
      throw ParquetException(std::string("Unknown parquet PageType::type:: ") +
                             std::to_string(t));
  }
}

}  // namespace parquet::encryption
