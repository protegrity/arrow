// TODO: add license

#include "parquet/encryption/column_chunk_properties.h"

namespace parquet::encryption {

ColumnChunkProperties::ColumnChunkProperties(
    std::string column_path,
    parquet::ParquetDataPageVersion page_version,
    parquet::Type::type physical_type,
    parquet::Encoding::type dictionary_page_encoding,
    parquet::Encoding::type dictionary_index_encoding,
    parquet::Encoding::type data_page_encoding,
    ::arrow::Compression::type compression,
    std::int64_t fixed_length_bytes
) : column_path_(column_path),
    page_version_(page_version), 
    physical_type_(physical_type), 
    dictionary_page_encoding_(dictionary_page_encoding), 
    dictionary_index_encoding_(dictionary_index_encoding), 
    data_page_encoding_(data_page_encoding), 
    compression_(compression), 
    fixed_length_bytes_(fixed_length_bytes) {}

std::unique_ptr<ColumnChunkProperties> ColumnChunkProperties::MakeFromMetadata(const ColumnChunkMetaDataBuilder* column_chunk_metadata) {

    //TODO: validation
    auto column_path = column_chunk_metadata->descr()->path();
    auto column_path_string = column_path->ToDotString();

    //writer provided properties.
    auto writer_properties = column_chunk_metadata->properties();
    auto data_page_version = writer_properties->data_page_version();
    auto dictionary_page_encoding = writer_properties->dictionary_page_encoding();
    auto dictionary_index_encoding = writer_properties->dictionary_index_encoding();
    auto data_page_encoding = writer_properties->encoding(column_path);
    auto compression_type = writer_properties->compression(column_path);

    //column metadata properties.
    auto physical_type = column_chunk_metadata->descr()->physical_type();

    //TODO: what's the difference between this and writer_properties->data_page_encoding()
    //auto encoding_type = column_chunk_metadata->properties()->encoding(column_path);
    auto fixed_length_bytes = column_chunk_metadata->descr()->type_length();

    return std::make_unique<ColumnChunkProperties>(
        /*column_path*/ column_path_string,
        /*page_version*/ data_page_version, 
        /*physical_type*/ physical_type, 
        /*dictionary_page_encoding*/ dictionary_page_encoding, 
        /*dictionary_index_encoding*/ dictionary_index_encoding, 
        /*data_page_encoding*/ data_page_encoding, 
        /*compression_type*/ compression_type, 
        /*fixed_length_bytes*/ fixed_length_bytes);
}

std::string ColumnChunkProperties::GetColumnPath() {
    return column_path_;
}

parquet::ParquetDataPageVersion ColumnChunkProperties::GetPageVersion() {
    return page_version_;
}

parquet::Type::type ColumnChunkProperties::GetPhysicalType() {
    return physical_type_;
}

parquet::Encoding::type ColumnChunkProperties::GetDictionaryPageEncoding() {
    return dictionary_page_encoding_;
}

parquet::Encoding::type ColumnChunkProperties::GetDictionaryIndexEncoding() {
    return dictionary_index_encoding_;
}

parquet::Encoding::type ColumnChunkProperties::GetDataPageEncoding() {
    return data_page_encoding_;
}

::arrow::Compression::type ColumnChunkProperties::GetCompression() {
    return compression_;
}

std::int64_t ColumnChunkProperties::GetFixedLengthBytes() {
    return fixed_length_bytes_;
}

} // namespace parquet::encryption
