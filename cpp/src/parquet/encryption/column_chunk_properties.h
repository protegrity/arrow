// TODO: add license

#pragma once

#include <memory>
#include <string>
#include <optional>

#include "parquet/types.h"
#include "parquet/encoding.h"
#include "parquet/metadata.h"
#include "parquet/column_page.h"
#include "arrow/util/compression.h"

namespace parquet::encryption {

class ColumnChunkPropertiesBuilder;

class ColumnChunkProperties {
public:
    static std::unique_ptr<ColumnChunkProperties> MakeFromMetadata(
        const ColumnDescriptor* column_descriptor,
        const WriterProperties* writer_properties,
        const Page& column_page);


    // Builder pattern
    static ColumnChunkPropertiesBuilder Builder();

    // Setters for column-level properties
    void set_column_path(const std::string& column_path);
    void set_physical_type(parquet::Type::type physical_type, 
                          const std::optional<std::int64_t>& fixed_length_bytes = std::nullopt);
    void set_compression_codec(::arrow::Compression::type compression_codec);

    void validate();

private:
    // Private constructor for builder
    ColumnChunkProperties(const ColumnChunkPropertiesBuilder& builder);

    ColumnChunkProperties(
        std::optional<std::string> column_path,
        std::optional<parquet::Type::type> physical_type,
        std::optional<::arrow::Compression::type> compression_codec,
        std::int64_t fixed_length_bytes,
        parquet::PageType::type page_type,
        parquet::Encoding::type page_encoding,
        int64_t data_page_num_values,
        parquet::Encoding::type page_v1_definition_level_encoding,
        parquet::Encoding::type page_v1_repetition_level_encoding,
        int32_t page_v2_definition_levels_byte_length,
        int32_t page_v2_repetition_levels_byte_length,
        int32_t page_v2_num_nulls,
        bool page_v2_is_compressed
    );

    // Allow the builder to access private constructor
    friend class ColumnChunkPropertiesBuilder;

    //--------------------------------
    //from column metadata. does not change across chunks nor data pages.
    std::optional<std::string> column_path_; 
    std::optional<parquet::Type::type> physical_type_; // BOOLEAN, INT32, INT64, INT96, FLOAT, DOUBLE, BYTE_ARRAY, FIXED_LEN_BYTE_ARRAY, etc
    std::optional<::arrow::Compression::type> compression_codec_;

    std::optional<std::int64_t> fixed_length_bytes_; // for FIXED_LEN_BYTE_ARRAY

    //--------------------------------
    //page type. - applies across all types of pages. non optional.
    parquet::PageType::type page_type_; // V1, V2, DICTIONARY_PAGE

    //--------------------------------
    //from data page. changes across chunks and data pages.
    //page-level properties can be seen in parquet/column_page.h
    std::optional<parquet::Encoding::type> page_encoding_; 

    //common between V1 and V2 data pages.
    std::optional<int64_t> data_page_num_values_;

    //--------------------------------
    // V1 data page properties.
    std::optional<parquet::Encoding::type> page_v1_definition_level_encoding_;
    std::optional<parquet::Encoding::type> page_v1_repetition_level_encoding_;

    //--------------------------------
    // V2 data page properties.
    std::optional<int32_t> page_v2_definition_levels_byte_length_; //note that typing is different from V1
    std::optional<int32_t> page_v2_repetition_levels_byte_length_; //note that typing is different from V1
    std::optional<int32_t> page_v2_num_nulls_;
    std::optional<bool> page_v2_is_compressed_; //this does not exist in V1 nor dictionary pages.

    //--------------------------------
    // Dictionary page properties.

    // there are not specific properties for dictionary pages,
    // other than the page encoding (captured above).

    //--------------------------------
}; //class ColumnChunkProperties

class ColumnChunkPropertiesBuilder {
public:
    ColumnChunkPropertiesBuilder() = default;
    
    // Column-level properties (required)
    ColumnChunkPropertiesBuilder& ColumnPath(const std::string& column_path);
    ColumnChunkPropertiesBuilder& PhysicalType(parquet::Type::type physical_type);
    ColumnChunkPropertiesBuilder& CompressionCodec(::arrow::Compression::type compression_codec);
    ColumnChunkPropertiesBuilder& PageType(parquet::PageType::type page_type);
    
    // Column-level optional fields
    ColumnChunkPropertiesBuilder& FixedLengthBytes(std::int64_t fixed_length_bytes);
    
    // Data page properties
    ColumnChunkPropertiesBuilder& PageEncoding(parquet::Encoding::type page_encoding);
    ColumnChunkPropertiesBuilder& DataPageNumValues(int64_t data_page_num_values);
    
    // V1 data page properties
    ColumnChunkPropertiesBuilder& PageV1DefinitionLevelEncoding(parquet::Encoding::type encoding);
    ColumnChunkPropertiesBuilder& PageV1RepetitionLevelEncoding(parquet::Encoding::type encoding);
    
    // V2 data page properties
    ColumnChunkPropertiesBuilder& PageV2DefinitionLevelsByteLength(int32_t byte_length);
    ColumnChunkPropertiesBuilder& PageV2RepetitionLevelsByteLength(int32_t byte_length);
    ColumnChunkPropertiesBuilder& PageV2NumNulls(int32_t num_nulls);
    ColumnChunkPropertiesBuilder& PageV2IsCompressed(bool is_compressed);
        
    // Build the final object
    std::unique_ptr<ColumnChunkProperties> Build();

private:
    friend class ColumnChunkProperties;

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
    
    // V1 data page properties
    std::optional<parquet::Encoding::type> page_v1_definition_level_encoding_;
    std::optional<parquet::Encoding::type> page_v1_repetition_level_encoding_;
    
    // V2 data page properties
    std::optional<int32_t> page_v2_definition_levels_byte_length_;
    std::optional<int32_t> page_v2_repetition_levels_byte_length_;
    std::optional<int32_t> page_v2_num_nulls_;
    std::optional<bool> page_v2_is_compressed_;    
}; // class ColumnChunkPropertiesBuilder

} //namespace parquet::encryption


