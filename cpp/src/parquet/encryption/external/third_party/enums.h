//TODO: figure out the licensing.
//https://github.com/protegrity/arrow/issues/110

#pragma once

// TODO: this file was copied from
// https://github.com/protegrity/DataBatchProtectionService
// we need to find a better way to share it between repos.
// https://github.com/protegrity/arrow/issues/110

#pragma once

namespace dbps::external {

// Captures the data type of the data batch elements.
// Intentionally similar to parquet::Type to ease mapping and for compatibility with a known enum.
// Originally defined in Arrow codebase: arrow/blob/main/cpp/src/parquet/types.h
struct Type {
    enum type {
        BOOLEAN = 0,
        INT32 = 1,
        INT64 = 2,
        INT96 = 3,
        FLOAT = 4,
        DOUBLE = 5,
        BYTE_ARRAY = 6,
        FIXED_LEN_BYTE_ARRAY = 7,
        UNDEFINED = 8
    };
};

// Intentionally similar to arrow::CompressionCodec
// Originally defined in Arrow codebase: //arrow/blob/main/cpp/src/arrow/util/type_fwd.h
struct CompressionCodec {
    enum type {
        UNCOMPRESSED = 0,
        SNAPPY = 1,
        GZIP = 2,
        BROTLI = 3,
        ZSTD = 4,
        LZ4 = 5,
        LZ4_FRAME = 6,
        LZO = 7,
        BZ2 = 8,
        LZ4_HADOOP = 9
    };
};

// Format for data values
// Intentionally similar to parquet::Encoding to ease mapping and for compatibility with a known enum.
// Originally defined in Arrow codebase: arrow/blob/main/cpp/src/parquet/types.h
// TODO: Rename to Encoding to match parquet::Encoding (as a further cleanup)
struct Format {
    enum type {
        PLAIN = 0,
        PLAIN_DICTIONARY = 2,
        RLE = 3,
        BIT_PACKED = 4,
        DELTA_BINARY_PACKED = 5,
        DELTA_LENGTH_BYTE_ARRAY = 6,
        DELTA_BYTE_ARRAY = 7,
        RLE_DICTIONARY = 8,
        BYTE_STREAM_SPLIT = 9,
        UNDEFINED = 10,
        UNKNOWN = 11
    };
};

}
