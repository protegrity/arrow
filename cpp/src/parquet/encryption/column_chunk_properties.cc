// TODO: add license

#include <stdexcept>
#include <iostream>

#include "parquet/encryption/column_chunk_properties.h"
#include "parquet/metadata.h"
#include "parquet/column_page.h"

namespace parquet::encryption {

using parquet::ColumnDescriptor;
using parquet::WriterProperties;
    
// Private constructor for builder
ColumnChunkProperties::ColumnChunkProperties(const ColumnChunkPropertiesBuilder& builder)
    : column_path_(builder.column_path_),
      physical_type_(builder.physical_type_),
      compression_codec_(builder.compression_codec_),
      fixed_length_bytes_(builder.fixed_length_bytes_),
      page_type_(builder.page_type_.value()),
      page_encoding_(builder.page_encoding_),
      data_page_num_values_(builder.data_page_num_values_),
      page_v1_definition_level_encoding_(builder.page_v1_definition_level_encoding_),
      page_v1_repetition_level_encoding_(builder.page_v1_repetition_level_encoding_),
      page_v2_definition_levels_byte_length_(builder.page_v2_definition_levels_byte_length_),
      page_v2_repetition_levels_byte_length_(builder.page_v2_repetition_levels_byte_length_),
      page_v2_num_nulls_(builder.page_v2_num_nulls_),
      page_v2_is_compressed_(builder.page_v2_is_compressed_),
      dictionary_index_encoding_(builder.dictionary_index_encoding_) {
    }

// Builder static method
ColumnChunkPropertiesBuilder ColumnChunkProperties::Builder() {
    return ColumnChunkPropertiesBuilder();
}

// private method to validate the properties
void ColumnChunkProperties::validate() {
    // Validate required fields
    if ( (!column_path_.has_value()) || column_path_.value().empty()) {
        throw std::invalid_argument("ColumnPath is required");
    }

    if (!page_encoding_.has_value()) {
        throw std::invalid_argument("PageEncoding is required");
    }

    //Validate page-level properties
    // first, let's validate common properties across data pages.
    // DATA_PAGE is equivalent to DATA_PAGE_V1.
    if ((page_type_ == parquet::PageType::DATA_PAGE) || (page_type_ == parquet::PageType::DATA_PAGE_V2)) {
        if (!data_page_num_values_.has_value()) {
            throw std::invalid_argument("DataPageNumValues is required");
        }

        if (page_encoding_ == parquet::Type::type::FIXED_LEN_BYTE_ARRAY) {
            if (!fixed_length_bytes_.has_value()) {
                throw std::invalid_argument("FixedLengthBytes is required for column page with FIXED_LEN_BYTE_ARRAY encoding");
            }
        }

        if (fixed_length_bytes_.has_value())  {
            if (physical_type_ != parquet::Type::type::FIXED_LEN_BYTE_ARRAY) {
                throw std::invalid_argument("FixedLengthBytes is only allowed for FIXED_LEN_BYTE_ARRAY physical type");
            }
        }
    }

    // then, let's validate properties specific to each page type.
    // DATA_PAGE is equivalent to DATA_PAGE_V1.
    if (page_type_ == parquet::PageType::DATA_PAGE) {
        if (!page_v1_definition_level_encoding_.has_value()) {
            throw std::invalid_argument("PageV1DefinitionLevelEncoding is required");
        }
        if (!page_v1_repetition_level_encoding_.has_value()) {
            throw std::invalid_argument("PageV1RepetitionLevelEncoding is required");
        }
    }
    else if (page_type_ == parquet::PageType::DATA_PAGE_V2) {
        if (!page_v2_num_nulls_.has_value()) {
            throw std::invalid_argument("PageV2NumNulls is required");
        }
        if (!page_v2_definition_levels_byte_length_.has_value()) {
            throw std::invalid_argument("PageV2DefinitionLevelsByteLength is required");
        }
        if (!page_v2_repetition_levels_byte_length_.has_value()) {
            throw std::invalid_argument("PageV2RepetitionLevelsByteLength is required");
        }
        if (!page_v2_is_compressed_.has_value()) {
            throw std::invalid_argument("PageV2IsCompressed is required");
        }
    }
    else if (page_type_ == parquet::PageType::DICTIONARY_PAGE) {
        if (!dictionary_index_encoding_.has_value()) {
            throw std::invalid_argument("DictionaryIndexEncoding is required");
        }
    }
 } //validate()

std::unique_ptr<ColumnChunkProperties> ColumnChunkProperties::MakeFromMetadata(
    //const ColumnChunkMetaDataBuilder* column_chunk_metadata,
    const ColumnDescriptor* column_descriptor,
    const WriterProperties* writer_properties,
    const Page& column_page) {

    ColumnChunkPropertiesBuilder builder;

    builder.ColumnPath(column_descriptor->path()->ToDotString());
    builder.PhysicalType(column_descriptor->physical_type());
    builder.CompressionCodec(writer_properties->compression(column_descriptor->path()));
    builder.PageType(column_page.type());

    bool is_data_page = (column_page.type() == parquet::PageType::DATA_PAGE) || (column_page.type() == parquet::PageType::DATA_PAGE_V2);

    //properties common to V1 and V2 data pages.
    if (is_data_page) {
        DataPage data_page = static_cast<const DataPage&>(column_page);
        builder.PageEncoding(data_page.encoding());
        builder.DataPageNumValues(data_page.num_values());
    }

    //properties specific to each type of page
    if (column_page.type() == parquet::PageType::DATA_PAGE) {
        DataPageV1 data_page_v1 = static_cast<const DataPageV1&>(column_page);
        builder.PageV1DefinitionLevelEncoding(data_page_v1.definition_level_encoding());
        builder.PageV1RepetitionLevelEncoding(data_page_v1.repetition_level_encoding());
    }
    else if (column_page.type() == parquet::PageType::DATA_PAGE_V2) {
        DataPageV2 data_page_v2 = static_cast<const DataPageV2&>(column_page);
        builder.PageV2DefinitionLevelsByteLength(data_page_v2.definition_levels_byte_length());
        builder.PageV2RepetitionLevelsByteLength(data_page_v2.repetition_levels_byte_length());
        builder.PageV2IsCompressed(data_page_v2.is_compressed());
    }
    else if (column_page.type() == parquet::PageType::DICTIONARY_PAGE) {
        DictionaryPage dict_page = static_cast<const DictionaryPage&>(column_page);
        builder.PageEncoding(dict_page.encoding());
        builder.DictionaryIndexEncoding(writer_properties->dictionary_index_encoding());
    }
    else {
        throw std::invalid_argument("Unknown Page Type:: " + std::to_string(column_page.type()));
    }

    return builder.Build();
}

std::unique_ptr<ColumnChunkProperties> ColumnChunkProperties::MakeFromDecryptionMetadata(
    PageHeader& page_header) {

    ColumnChunkPropertiesBuilder builder;

    format::PageType::type page_type_from_header = page_header.type;

    if (page_type_from_header == format::PageType::DICTIONARY_PAGE) {
        std::cout << "ColumnChunkProperties::MakeFromDecryptionMetadata - PageType::DICTIONARY_PAGE" << std::endl;
  
        format::DictionaryPageHeader dictionary_page_header = page_header.dictionary_page_header;
  
        builder.PageType(parquet::PageType::type::DICTIONARY_PAGE);  
        builder.PageEncoding(ToParquetEncoding(dictionary_page_header.encoding));

        // TODO:>>>> triple check this.
        // TODO:>>>> triple check this!!!
        // This 'normalization' seems valid.
        // A per the official Parquet spec on Encodings (https://parquet.apache.org/docs/file-format/data-pages/encodings/)
        // PLAIN_DICTIONARY is deprecated, and RLE_DICTIONARY is the new standard.
        //
        // This is confirmed in the Parquet Format repository, https://github.com/apache/parquet-format/blob/master/src/main/thrift/parquet.thrif 
        // where PLAIN_DICTIONARY ... complete
        // also, check this out inside column_reader.cc, InitializeDataDecoder()

        /**    Encoding::type encoding = page.encoding();
                if (IsDictionaryIndexEncoding(encoding)) {
                    // Normalizing the PLAIN_DICTIONARY to RLE_DICTIONARY encoding
                    // in decoder.
                    encoding = Encoding::RLE_DICTIONARY;
                }

         */
        builder.DictionaryIndexEncoding(parquet::Encoding::type::RLE_DICTIONARY);
  
      }
      else if (page_type_from_header == format::PageType::DATA_PAGE) {
        std::cout << "ColumnChunkProperties::MakeFromDecryptionMetadata - PageType::DATA_PAGE" << std::endl;
  
        format::DataPageHeader data_page_header = page_header.data_page_header;
  
        builder.PageType(parquet::PageType::type::DATA_PAGE);
        builder.PageEncoding(ToParquetEncoding(data_page_header.encoding));
        builder.DataPageNumValues(data_page_header.num_values);
        builder.PageV1DefinitionLevelEncoding(ToParquetEncoding(data_page_header.definition_level_encoding));
        builder.PageV1RepetitionLevelEncoding(ToParquetEncoding(data_page_header.repetition_level_encoding));
      }
      else if (page_type_from_header == format::PageType::DATA_PAGE_V2) {
        
        format::DataPageHeaderV2 data_page_header_v2 = page_header.data_page_header_v2;
  
        builder.PageType(parquet::PageType::type::DATA_PAGE_V2);
        builder.PageEncoding(ToParquetEncoding(data_page_header_v2.encoding));
        builder.DataPageNumValues(data_page_header_v2.num_values);
        builder.PageV2NumNulls(data_page_header_v2.num_nulls);
        builder.PageV2DefinitionLevelsByteLength(data_page_header_v2.definition_levels_byte_length);
        builder.PageV2RepetitionLevelsByteLength(data_page_header_v2.repetition_levels_byte_length);
        builder.PageV2IsCompressed(data_page_header_v2.is_compressed);
      }
  
    return builder.Build();
}


//--------------------------------
// Builder method implementations

std::unique_ptr<ColumnChunkProperties> ColumnChunkPropertiesBuilder::Build() {
    // while we will perform validation upon construction, 
    // we know that these properties are required. 
    // validating here simplifies our code.

    //TODO: clean this up.
    // if (!column_path_) {
    //     throw std::invalid_argument("ColumnChunkPropertiesBuilder::Build - ColumnPath is required");
    // }
    // if (!physical_type_) {
    //     throw std::invalid_argument("ColumnChunkPropertiesBuilder::Build - PhysicalType is required");
    // }
    // if (!compression_codec_) {
    //     throw std::invalid_argument("ColumnChunkPropertiesBuilder::Build - CompressionCodec is required");
    // }

    if (!page_type_) {
        throw std::invalid_argument("ColumnChunkPropertiesBuilder::Build - PageType is required");
    }

    return std::unique_ptr<ColumnChunkProperties>(new ColumnChunkProperties(*this));
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::ColumnPath(const std::string& column_path) {
    column_path_ = column_path;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PhysicalType(parquet::Type::type physical_type) {
    physical_type_ = physical_type;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::CompressionCodec(::arrow::Compression::type compression_codec) {
    compression_codec_ = compression_codec;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::FixedLengthBytes(std::int64_t fixed_length_bytes) {
    fixed_length_bytes_ = fixed_length_bytes;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageType(parquet::PageType::type page_type) {
    page_type_ = page_type;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageEncoding(parquet::Encoding::type page_encoding) {
    page_encoding_ = page_encoding;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::DataPageNumValues(int64_t data_page_num_values) {
    data_page_num_values_ = data_page_num_values;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageV1DefinitionLevelEncoding(parquet::Encoding::type encoding) {
    page_v1_definition_level_encoding_ = encoding;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageV1RepetitionLevelEncoding(parquet::Encoding::type encoding) {
    page_v1_repetition_level_encoding_ = encoding;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageV2DefinitionLevelsByteLength(int32_t byte_length) {
    page_v2_definition_levels_byte_length_ = byte_length;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageV2RepetitionLevelsByteLength(int32_t byte_length) {
    page_v2_repetition_levels_byte_length_ = byte_length;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageV2NumNulls(int32_t num_nulls) {
    page_v2_num_nulls_ = num_nulls;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::PageV2IsCompressed(bool is_compressed) {
    page_v2_is_compressed_ = is_compressed;
    return *this;
}

ColumnChunkPropertiesBuilder& ColumnChunkPropertiesBuilder::DictionaryIndexEncoding(parquet::Encoding::type encoding) {
    dictionary_index_encoding_ = encoding;
    return *this;
}

//--------------------------------
// Setters for column-level properties
// used to fill-in values provided in the encryptor/decryptor constructor.
void ColumnChunkProperties::set_column_path(const std::string& column_path) {
    column_path_ = column_path;
}

void ColumnChunkProperties::set_compression_codec(::arrow::Compression::type compression_codec) {
    compression_codec_ = compression_codec;
}

void ColumnChunkProperties::set_physical_type(parquet::Type::type physical_type, 
                                                const std::optional<std::int64_t>& fixed_length_bytes) {
    //TODO: validate.

    physical_type_ = physical_type;                                                        
    if (fixed_length_bytes.has_value()) {
        fixed_length_bytes_ = fixed_length_bytes;
    }
}

} // namespace parquet::encryption
