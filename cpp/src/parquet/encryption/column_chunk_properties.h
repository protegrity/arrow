// TODO: add license

#pragma once

#include <memory>
#include <string>

#include "parquet/metadata.h"

namespace parquet::encryption {

class ColumnChunkProperties {
public:
    ColumnChunkProperties(
        std::string column_path,
        parquet::ParquetDataPageVersion page_version,
        parquet::Type::type physical_type,
        parquet::Encoding::type dictionary_page_encoding,
        parquet::Encoding::type dictionary_index_encoding,
        parquet::Encoding::type data_page_encoding,
        ::arrow::Compression::type compression,
        std::int64_t fixed_length_bytes
    );

    static std::unique_ptr<ColumnChunkProperties> MakeFromMetadata(const ColumnChunkMetaDataBuilder* column_chunk_meta_data);

    std::string GetColumnPath();
    parquet::ParquetDataPageVersion GetPageVersion();
    parquet::Type::type GetPhysicalType();
    parquet::Encoding::type GetDictionaryPageEncoding();
    parquet::Encoding::type GetDictionaryIndexEncoding();
    parquet::Encoding::type GetDataPageEncoding();
    ::arrow::Compression::type GetCompression();

    //TODO: verify type.
    std::int64_t GetFixedLengthBytes();

    private:
        std::string column_path_;
        parquet::ParquetDataPageVersion page_version_;
        parquet::Type::type physical_type_;
        parquet::Encoding::type dictionary_page_encoding_;
        parquet::Encoding::type dictionary_index_encoding_;
        parquet::Encoding::type data_page_encoding_;
        ::arrow::Compression::type compression_;
        std::int64_t fixed_length_bytes_;
}; //class ColumnChunkProperties

} //namespace parquet::encryption


