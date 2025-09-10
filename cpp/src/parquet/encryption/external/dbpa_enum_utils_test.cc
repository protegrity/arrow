//TODO: figure out the licensing.

#include <gtest/gtest.h>

#include "parquet/platform.h"
#include "parquet/types.h"
#include "arrow/util/type_fwd.h"
#include "parquet/encryption/external/third_party/dbpa_interface.h"
#include "parquet/encryption/external/dbpa_enum_utils.h"

namespace parquet::encryption::external {

class DBPAUtilsTest : public ::testing::Test {
 protected:
  void SetUp() override {}
};

TEST_F(DBPAUtilsTest, ParquetTypeToExternal) {
  // Test all valid parquet types
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::BOOLEAN), 
            dbps::external::Type::BOOLEAN);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::INT32), 
            dbps::external::Type::INT32);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::INT64), 
            dbps::external::Type::INT64);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::INT96), 
            dbps::external::Type::INT96);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::FLOAT), 
            dbps::external::Type::FLOAT);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::DOUBLE), 
            dbps::external::Type::DOUBLE);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::BYTE_ARRAY), 
            dbps::external::Type::BYTE_ARRAY);
  EXPECT_EQ(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::FIXED_LEN_BYTE_ARRAY), 
            dbps::external::Type::FIXED_LEN_BYTE_ARRAY);
}

TEST_F(DBPAUtilsTest, ArrowCompressionToExternal) {
  // Test all valid arrow compression types that have mappings
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::UNCOMPRESSED), 
            dbps::external::CompressionCodec::UNCOMPRESSED);
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::SNAPPY), 
            dbps::external::CompressionCodec::SNAPPY);
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::GZIP), 
            dbps::external::CompressionCodec::GZIP);
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::LZO), 
            dbps::external::CompressionCodec::LZO);
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::BROTLI), 
            dbps::external::CompressionCodec::BROTLI);
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::LZ4), 
            dbps::external::CompressionCodec::LZ4);
  EXPECT_EQ(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::ZSTD), 
            dbps::external::CompressionCodec::ZSTD);
}

// TODO: this needs to be deleted.
// TEST_F(DBPAUtilsTest, InvalidParquetType) {
//   // Test that invalid parquet type throws exception
//   EXPECT_THROW(DBPAEnumUtils::ParquetTypeToDBPA(parquet::Type::UNDEFINED), 
//                std::invalid_argument);
// }

TEST_F(DBPAUtilsTest, UnsupportedArrowCompression) {
  // Test that unsupported arrow compression types throw exceptions
  EXPECT_THROW(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::LZ4_FRAME), 
               std::invalid_argument);
  EXPECT_THROW(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::BZ2), 
               std::invalid_argument);
  EXPECT_THROW(DBPAEnumUtils::ArrowCompressionToDBPA(::arrow::Compression::LZ4_HADOOP), 
               std::invalid_argument);
}

TEST_F(DBPAUtilsTest, AllValidTypeMappings) {
  // Test that all valid parquet types can be converted to external types
  // Using the actual enum values from parquet::Type (excluding UNDEFINED)
  std::vector<parquet::Type::type> valid_parquet_types = {
    parquet::Type::BOOLEAN,
    parquet::Type::INT32,
    parquet::Type::INT64,
    parquet::Type::INT96,
    parquet::Type::FLOAT,
    parquet::Type::DOUBLE,
    parquet::Type::BYTE_ARRAY,
    parquet::Type::FIXED_LEN_BYTE_ARRAY
    // TODO: add UNDEFINED
  };
  
  for (auto parquet_type : valid_parquet_types) {
    EXPECT_NO_THROW(DBPAEnumUtils::ParquetTypeToDBPA(parquet_type));
  }
}

TEST_F(DBPAUtilsTest, AllValidCompressionMappings) {
  // Test that all valid arrow compression types that have mappings work
  // Using the actual enum values from arrow::Compression that are supported
  std::vector<::arrow::Compression::type> valid_arrow_compressions = {
    ::arrow::Compression::UNCOMPRESSED,
    ::arrow::Compression::SNAPPY,
    ::arrow::Compression::GZIP,
    ::arrow::Compression::LZO,
    ::arrow::Compression::BROTLI,
    ::arrow::Compression::LZ4,
    ::arrow::Compression::ZSTD
    //TODO: check for completeness

  };
  
  for (auto arrow_compression : valid_arrow_compressions) {
    EXPECT_NO_THROW(DBPAEnumUtils::ArrowCompressionToDBPA(arrow_compression));
  }
}

TEST_F(DBPAUtilsTest, MapSizeAssertions) {
  // Test the actual map sizes by accessing the public static maps directly
  // This provides a direct way to verify map completeness
  
  // Expected sizes based on our implementation:
  // - parquet_to_external_type_map: 8 entries (all parquet types except UNDEFINED)
  // - external_to_parquet_type_map: 8 entries (same as above, just reversed)
  // - arrow_to_external_compression_map: 7 entries (supported arrow compressions)
  // - external_to_arrow_compression_map: 7 entries (same as above, just reversed)


  // TODO: this does not guarantee that the maps are complete.
  // It may be a risk we need to live with, given that there is no reflection-type of
  // mechanism to check all the values from the maps. 
  // however, "Magic Enum", a third-party library, provides a way to check all the values from the maps.
  // https://github.com/Neargye/magic_enum
  
  EXPECT_EQ(DBPAEnumUtils::parquet_to_external_type_map.size(), 8) 
    << "Expected 8 parquet type mappings (excluding UNDEFINED)";
  
  EXPECT_EQ(DBPAEnumUtils::arrow_to_external_compression_map.size(), 7) 
    << "Expected 7 arrow compression mappings";
}
} // namespace parquet::encryption::external
