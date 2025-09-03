// TODO: Figure out licensing.
// https://github.com/protegrity/arrow/issues/112

#pragma once

#include <stdexcept>

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
class dbpa_utils {
public:
    /**
     * Convert parquet::Type to dbps::external::Type
     * 
     * @param parquet_type The parquet type to convert
     * @return The corresponding dbps::external::Type
     */
    static dbps::external::Type::type ParquetTypeToExternal(parquet::Type::type parquet_type);
    
    /**
     * Convert dbps::external::Type to parquet::Type
     * 
     * @param external_type The dbps::external type to convert
     * @return The corresponding parquet::Type
     */
    static parquet::Type::type ExternalTypeToParquet(dbps::external::Type::type external_type);
    
    /**
     * Convert arrow::Compression to dbps::external::CompressionCodec
     * 
     * @param arrow_compression The Arrow compression type to convert
     * @return The corresponding dbps::external::CompressionCodec
     * @throws std::invalid_argument if the Arrow compression type cannot be mapped
     */
    static dbps::external::CompressionCodec::type ArrowCompressionToExternal(::arrow::Compression::type arrow_compression);
    
    /**
     * Convert dbps::external::CompressionCodec to arrow::Compression
     * 
     * @param external_compression The dbps::external compression type to convert
     * @return The corresponding arrow::Compression
     * @throws std::invalid_argument if the external compression type cannot be mapped
     */
    static ::arrow::Compression::type ExternalCompressionToArrow(dbps::external::CompressionCodec::type external_compression);
};

} // namespace parquet::encryption::external
