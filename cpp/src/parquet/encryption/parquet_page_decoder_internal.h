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

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "parquet/encryption/parquet_crypto_provider.h"
#include "parquet/encryption/typed_column_values.h"
#include "parquet/platform.h"

namespace parquet::encryption {
class EncodingProperties;
}  // namespace parquet::encryption

namespace parquet {

/// Arrow-internal. Decompresses and decodes a Parquet data/dictionary page into a
/// CryptoValueBuffer for the ParquetCryptoProvider cell path, and reverses the
/// transform to reassemble a page after the provider mutates the values in place.
/// Reuses Arrow's existing Decoder<DType>/Encoder<DType> machinery (decoder.cc/
/// encoder.cc) and arrow::Compression::MakeCodec() — no independent codec logic.
class PARQUET_EXPORT ParquetPageDecoder {
 public:
  /// Splits and decompresses `compressed_page` (DataPageV2 + PLAIN only; DataPageV1
  /// is not yet supported), decodes its rep/def levels, and decodes PLAIN-encoded
  /// values for fixed-width numeric physical types (INT32/INT64/INT96/FLOAT/DOUBLE)
  /// into the returned TypedColumnValues. BOOLEAN/FIXED_LEN_BYTE_ARRAY/BYTE_ARRAY
  /// value decoding and non-PLAIN value encodings are not yet implemented and throw.
  static TypedColumnValues Decompress(std::span<const uint8_t> compressed_page,
                                      const encryption::EncodingProperties& props);

  /// Not yet implemented; always throws.
  static std::vector<uint8_t> Recompress(const TypedColumnValues& values,
                                         const encryption::EncodingProperties& props);

  /// Returns one buffer holding a DataPageV2's rep/def level bytes followed by its
  /// decompressed values, split via the caller-supplied level-length fields. Level
  /// bytes are decoded but not routed through ParquetCryptoProvider.
  static std::vector<uint8_t> SplitAndDecompressDataPageV2(
      std::span<const uint8_t> page, const encryption::EncodingProperties& props);
};

}  // namespace parquet
