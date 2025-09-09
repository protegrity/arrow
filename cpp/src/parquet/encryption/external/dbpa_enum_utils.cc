//TODO: figure out licensing.
//https://github.com/protegrity/arrow/issues/112

#include "parquet/encryption/external/dbpa_enum_utils.h"

#include <stdexcept>
#include <unordered_map>

namespace parquet::encryption::external {

// Static map definitions for the class members

// ------------------------------------------------------------
// parquet::Type -> dbps::external::Type
// Parquet types are coming from parquet/types.h
// ------------------------------------------------------------
const std::unordered_map<parquet::Type::type, dbps::external::Type::type> DBPAEnumUtils::parquet_to_external_type_map = {
    {parquet::Type::BOOLEAN, dbps::external::Type::BOOLEAN},
    {parquet::Type::INT32, dbps::external::Type::INT32},
    {parquet::Type::INT64, dbps::external::Type::INT64},
    {parquet::Type::INT96, dbps::external::Type::INT96},
    {parquet::Type::FLOAT, dbps::external::Type::FLOAT},
    {parquet::Type::DOUBLE, dbps::external::Type::DOUBLE},
    {parquet::Type::BYTE_ARRAY, dbps::external::Type::BYTE_ARRAY},
    {parquet::Type::FIXED_LEN_BYTE_ARRAY, dbps::external::Type::FIXED_LEN_BYTE_ARRAY}
    //TODO: Parquet contains an UNDEFINED value which we'll need to handle.
};

// ------------------------------------------------------------
// dbps::external::Type -> parquet::Type
// Identical to the map above, but with the keys and values swapped.
// ------------------------------------------------------------
const std::unordered_map<dbps::external::Type::type, parquet::Type::type> DBPAEnumUtils::external_to_parquet_type_map = []() {
    std::unordered_map<dbps::external::Type::type, parquet::Type::type> map;
    for (const auto& pair : DBPAEnumUtils::parquet_to_external_type_map) {
        map[pair.second] = pair.first;
    }
    return map;
}();

// ------------------------------------------------------------
// arrow::Compression -> dbps::external::CompressionCodec
// values for arrow::Compression are coming from arrow/type_fwd.h
// Note: Some Arrow compression types don't have direct DBPS equivalents
// ------------------------------------------------------------
const std::unordered_map<::arrow::Compression::type, dbps::external::CompressionCodec::type> DBPAEnumUtils::arrow_to_external_compression_map = {
    {::arrow::Compression::UNCOMPRESSED, dbps::external::CompressionCodec::UNCOMPRESSED},
    {::arrow::Compression::SNAPPY, dbps::external::CompressionCodec::SNAPPY},
    {::arrow::Compression::GZIP, dbps::external::CompressionCodec::GZIP},
    {::arrow::Compression::LZO, dbps::external::CompressionCodec::LZO},
    {::arrow::Compression::BROTLI, dbps::external::CompressionCodec::BROTLI},
    {::arrow::Compression::LZ4, dbps::external::CompressionCodec::LZ4},
    {::arrow::Compression::ZSTD, dbps::external::CompressionCodec::ZSTD}
    // TODO: Arrow-specific compression types that don't have direct DBPS equivalents:
    // LZ4_FRAME, BZ2, LZ4_HADOOP are not supported by DBPS. We'll need to handle this.
};

// ------------------------------------------------------------
// dbps::external::CompressionCodec -> arrow::Compression
// Note: LZ4_RAW from DBPS doesn't have a direct Arrow equivalent
// ------------------------------------------------------------
const std::unordered_map<dbps::external::CompressionCodec::type, ::arrow::Compression::type> DBPAEnumUtils::external_to_arrow_compression_map = []() {
    std::unordered_map<dbps::external::CompressionCodec::type, ::arrow::Compression::type> map;
    for (const auto& pair : DBPAEnumUtils::arrow_to_external_compression_map) {
        map[pair.second] = pair.first;
    }
    // LZ4_RAW from DBPS doesn't have a direct Arrow equivalent
    // Could potentially map to LZ4, but that might be semantically incorrect
    return map;
}();


// ------------------------------------------------------------
// function which returns parquet::Type::type to dbps::external::Type::type
// ------------------------------------------------------------
dbps::external::Type::type DBPAEnumUtils::ParquetTypeToExternal(parquet::Type::type parquet_type) {

    //TODO: how should we handle this? 
    //UNDEFINED is a valid parquet::Type::type
    // Handle special case for UNDEFINED type
    if (parquet_type == parquet::Type::UNDEFINED) {
        throw std::invalid_argument("Invalid parquet::Type value: UNDEFINED");
    }
    
    // Look up the mapping in the static map
    auto it = parquet_to_external_type_map.find(parquet_type);
    if (it != parquet_to_external_type_map.end()) {
        return it->second;
    }
    
    throw std::invalid_argument("Invalid parquet::Type value");
}

// ------------------------------------------------------------
// function which returns dbps::external::Type::type to parquet::Type::type
// ------------------------------------------------------------
parquet::Type::type DBPAEnumUtils::ExternalTypeToParquet(dbps::external::Type::type external_type) {
    // Look up the mapping in the static map
    auto it = external_to_parquet_type_map.find(external_type);
    if (it != external_to_parquet_type_map.end()) {
        return it->second;
    }
    
    throw std::invalid_argument("Invalid dbps::external::Type value");
}

// ------------------------------------------------------------
// function which returns arrow::Compression::type to dbps::external::CompressionCodec::type
// ------------------------------------------------------------
dbps::external::CompressionCodec::type DBPAEnumUtils::ArrowCompressionToExternal(::arrow::Compression::type arrow_compression) {
    // Look up the mapping in the static map
    auto it = arrow_to_external_compression_map.find(arrow_compression);
    if (it != arrow_to_external_compression_map.end()) {
        return it->second;
    }
    
    throw std::invalid_argument("Invalid arrow::Compression value");
}

// ------------------------------------------------------------
// function which returns dbps::external::CompressionCodec::type to arrow::Compression::type
// ------------------------------------------------------------
::arrow::Compression::type DBPAEnumUtils::ExternalCompressionToArrow(dbps::external::CompressionCodec::type external_compression) {
    // Look up the mapping in the static map
    auto it = external_to_arrow_compression_map.find(external_compression);
    if (it != external_to_arrow_compression_map.end()) {
        return it->second;
    }
    
    throw std::invalid_argument("Invalid dbps::external::CompressionCodec value");
}

} // namespace parquet::encryption::external
