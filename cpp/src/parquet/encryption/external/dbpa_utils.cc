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

#include "parquet/encryption/external/dbpa_utils.h"

#include <stdexcept>

namespace parquet::encryption::external {

dbps::external::Type::type dbpa_utils::ParquetTypeToExternal(parquet::Type::type parquet_type) {
    // The enums have identical values, so we can do a direct cast
    switch (parquet_type) {
        case parquet::Type::BOOLEAN:
            return dbps::external::Type::BOOLEAN;
        case parquet::Type::INT32:
            return dbps::external::Type::INT32;
        case parquet::Type::INT64:
            return dbps::external::Type::INT64;
        case parquet::Type::INT96:
            return dbps::external::Type::INT96;
        case parquet::Type::FLOAT:
            return dbps::external::Type::FLOAT;
        case parquet::Type::DOUBLE:
            return dbps::external::Type::DOUBLE;
        case parquet::Type::BYTE_ARRAY:
            return dbps::external::Type::BYTE_ARRAY;
        case parquet::Type::FIXED_LEN_BYTE_ARRAY:
            return dbps::external::Type::FIXED_LEN_BYTE_ARRAY;
        case parquet::Type::UNDEFINED:
        default:
            throw std::invalid_argument("Invalid parquet::Type value");
    }
}

parquet::Type::type dbpa_utils::ExternalTypeToParquet(dbps::external::Type::type external_type) {
    // The enums have identical values, so we can do a direct cast
    switch (external_type) {
        case dbps::external::Type::BOOLEAN:
            return parquet::Type::BOOLEAN;
        case dbps::external::Type::INT32:
            return parquet::Type::INT32;
        case dbps::external::Type::INT64:
            return parquet::Type::INT64;
        case dbps::external::Type::INT96:
            return parquet::Type::INT96;
        case dbps::external::Type::FLOAT:
            return parquet::Type::FLOAT;
        case dbps::external::Type::DOUBLE:
            return parquet::Type::DOUBLE;
        case dbps::external::Type::BYTE_ARRAY:
            return parquet::Type::BYTE_ARRAY;
        case dbps::external::Type::FIXED_LEN_BYTE_ARRAY:
            return parquet::Type::FIXED_LEN_BYTE_ARRAY;
        default:
            throw std::invalid_argument("Invalid dbps::external::Type value");
    }
}

dbps::external::CompressionCodec::type dbpa_utils::ArrowCompressionToExternal(::arrow::Compression::type arrow_compression) {
    switch (arrow_compression) {
        case ::arrow::Compression::UNCOMPRESSED:
            return dbps::external::CompressionCodec::UNCOMPRESSED;
        case ::arrow::Compression::SNAPPY:
            return dbps::external::CompressionCodec::SNAPPY;
        case ::arrow::Compression::GZIP:
            return dbps::external::CompressionCodec::GZIP;
        case ::arrow::Compression::LZO:
            return dbps::external::CompressionCodec::LZO;
        case ::arrow::Compression::BROTLI:
            return dbps::external::CompressionCodec::BROTLI;
        case ::arrow::Compression::LZ4:
            return dbps::external::CompressionCodec::LZ4;
        case ::arrow::Compression::ZSTD:
            return dbps::external::CompressionCodec::ZSTD;
        default:
            throw std::invalid_argument("Invalid arrow::Compression value");
    }
}

::arrow::Compression::type dbpa_utils::ExternalCompressionToArrow(dbps::external::CompressionCodec::type external_compression) {
    switch (external_compression) {
        case dbps::external::CompressionCodec::UNCOMPRESSED:
            return ::arrow::Compression::UNCOMPRESSED;
        case dbps::external::CompressionCodec::SNAPPY:
            return ::arrow::Compression::SNAPPY;
        case dbps::external::CompressionCodec::GZIP:
            return ::arrow::Compression::GZIP;
        case dbps::external::CompressionCodec::LZO:
            return ::arrow::Compression::LZO;
        case dbps::external::CompressionCodec::BROTLI:
            return ::arrow::Compression::BROTLI;
        case dbps::external::CompressionCodec::LZ4:
            return ::arrow::Compression::LZ4;
        case dbps::external::CompressionCodec::ZSTD:
            return ::arrow::Compression::ZSTD;
        default:
            throw std::invalid_argument("Invalid dbps::external::CompressionCodec value");
    }
}

} // namespace parquet::encryption::external
