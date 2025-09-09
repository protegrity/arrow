//TODO: figure out the licensing.
//https://github.com/protegrity/arrow/issues/110

#pragma once

// TODO: this file was copied from
// https://github.com/protegrity/DataBatchProtectionService
// we need to find a better way to share it between repos.
// https://github.com/protegrity/arrow/issues/110

namespace dbps::external {

// Captures the data type of the data batch elements.
// Intentionally similar to parquet::Type to ease mapping and for compatibility with a known enum.
struct Type {
    enum type {
        BOOLEAN = 0,
        INT32 = 1,
        INT64 = 2,
        INT96 = 3,
        FLOAT = 4,
        DOUBLE = 5,
        BYTE_ARRAY = 6,
        FIXED_LEN_BYTE_ARRAY = 7
    };
};

// Intentionally similar to arrow::CompressionCodec
struct CompressionCodec {
    enum type {
        UNCOMPRESSED = 0,
        SNAPPY = 1,
        GZIP = 2,
        LZO = 3,
        BROTLI = 4,
        LZ4 = 5,
        ZSTD = 6,
        LZ4_RAW = 7
    };
};

// Format for data values
struct Format {
    enum type {
        PLAIN = 0,
        RAW_BYTES = 1
    };
};

}
