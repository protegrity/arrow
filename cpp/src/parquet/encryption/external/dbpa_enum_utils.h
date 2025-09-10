// TODO: Figure out licensing.
// https://github.com/protegrity/arrow/issues/112

#pragma once

#include <stdexcept>
#include <unordered_map>

#include "parquet/encryption/external/third_party/dbpa_interface.h"
#include "parquet/types.h"
#include "arrow/type_fwd.h" // For arrow::Compression

namespace parquet::encryption::external {

/**
 * Utility class for translating between Parquet/Arrow enums and dbps::external enums.
 * 
 * This class provides methods to convert between:
 * - parquet::Type and dbps::external::Type
 * - arrow::Compression and dbps::external::CompressionCodec
 */
class DBPAEnumUtils {
public:
    // Static maps for type conversions
    static const std::unordered_map<parquet::Type::type, dbps::external::Type::type> parquet_to_external_type_map;
    static const std::unordered_map<::arrow::Compression::type, dbps::external::CompressionCodec::type> arrow_to_external_compression_map;

    /**
     * Convert parquet::Type to dbps::external::Type
     * 
     * @param parquet_type The parquet type to convert
     * @return The corresponding dbps::external::Type
     */
    static dbps::external::Type::type ParquetTypeToDBPA(parquet::Type::type parquet_type);
        
    /**
     * Convert arrow::Compression to dbps::external::CompressionCodec
     * 
     * @param arrow_compression The Arrow compression type to convert
     * @return The corresponding dbps::external::CompressionCodec
     * @throws std::invalid_argument if the Arrow compression type cannot be mapped
     */
    static dbps::external::CompressionCodec::type ArrowCompressionToDBPA(::arrow::Compression::type arrow_compression);    
};

} // namespace parquet::encryption::external
