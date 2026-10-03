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

#include "parquet/encryption/parquet_page_decoder_internal.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <variant>

#include "arrow/util/bit_util.h"
#include "arrow/util/compression.h"
#include "arrow/util/int_util_overflow.h"
#include "parquet/column_reader.h"
#include "parquet/column_writer.h"
#include "parquet/encoding.h"
#include "parquet/encryption/encoding_properties.h"
#include "parquet/exception.h"

namespace parquet {

namespace {

// Number of leaf values PLAIN encoding actually stores in the values portion of a
// page: nulls contribute a definition level below the max but no bytes at all, so
// only entries at max_definition_level are "present" and need decoding.
int64_t CountNonNullValues(const std::vector<int16_t>& definition_levels,
                           int16_t max_definition_level) {
  if (max_definition_level == 0) {
    return static_cast<int64_t>(definition_levels.size());
  }
  return std::count(definition_levels.begin(), definition_levels.end(),
                    max_definition_level);
}

// Decodes `num_non_null` PLAIN-encoded values of DType from `values_bytes` into a
// freshly allocated, tightly-sized vector.
template <typename DType>
std::vector<typename DType::c_type> DecodePlainValues(
    std::span<const uint8_t> values_bytes, int64_t num_non_null) {
  if (num_non_null < 0 || num_non_null > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid non-null value count");
  }
  if (values_bytes.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw ParquetException("ParquetPageDecoder: values buffer too large to decode");
  }
  auto decoder = MakeTypedDecoder<DType>(Encoding::PLAIN);
  decoder->SetData(static_cast<int>(num_non_null), values_bytes.data(),
                   static_cast<int>(values_bytes.size()));
  std::vector<typename DType::c_type> values(static_cast<size_t>(num_non_null));
  int decoded = decoder->Decode(values.data(), static_cast<int>(num_non_null));
  if (decoded != static_cast<int>(num_non_null)) {
    throw ParquetException("ParquetPageDecoder: failed to decode all values");
  }
  return values;
}

// Decodes `num_non_null` PLAIN-encoded BOOLEAN values into a bit-packed buffer,
// matching Parquet's on-disk PLAIN BOOLEAN layout exactly (LSB-first) -- no
// unpacking to one-bool-per-byte, since CryptoValueBuffer's BOOLEAN alternative
// is the packed span<uint8_t> itself (see parquet_crypto_provider.h).
std::vector<uint8_t> DecodePlainBooleanValues(std::span<const uint8_t> values_bytes,
                                              int64_t num_non_null) {
  if (num_non_null < 0 || num_non_null > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid non-null value count");
  }
  if (values_bytes.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw ParquetException("ParquetPageDecoder: values buffer too large to decode");
  }
  auto decoder = MakeTypedDecoder<BooleanType>(Encoding::PLAIN);
  decoder->SetData(static_cast<int>(num_non_null), values_bytes.data(),
                   static_cast<int>(values_bytes.size()));
  std::vector<uint8_t> packed(
      static_cast<size_t>(::arrow::bit_util::BytesForBits(num_non_null)));
  int decoded = decoder->Decode(packed.data(), static_cast<int>(num_non_null));
  if (decoded != static_cast<int>(num_non_null)) {
    throw ParquetException("ParquetPageDecoder: failed to decode all values");
  }
  return packed;
}

// Copies `num_non_null * type_length` raw bytes out of `values_bytes` for a
// FIXED_LEN_BYTE_ARRAY column. PLAIN FIXED_LEN_BYTE_ARRAY has no per-value framing
// at all (schema-fixed width, no length prefix), so this is a straight copy rather
// than a decoder call -- deliberately avoids FLBADecoder/DecodePlain<FixedLenByteArray>,
// which return FixedLenByteArray structs whose `ptr` aliases the original page buffer
// (see decoder.cc); that buffer is a local variable in Decompress() and would leave
// CryptoValueBuffer's span dangling once this function returns.
std::vector<uint8_t> DecodePlainFixedLenByteArrayValues(
    std::span<const uint8_t> values_bytes, int64_t num_non_null, int64_t type_length) {
  if (num_non_null < 0 || type_length < 0) {
    throw ParquetException("ParquetPageDecoder: invalid FIXED_LEN_BYTE_ARRAY parameters");
  }
  int64_t total_bytes = 0;
  if (::arrow::internal::MultiplyWithOverflow(num_non_null, type_length, &total_bytes) ||
      total_bytes > static_cast<int64_t>(values_bytes.size())) {
    throw ParquetException(
        "ParquetPageDecoder: FIXED_LEN_BYTE_ARRAY values exceed the page buffer");
  }
  return std::vector<uint8_t>(values_bytes.begin(),
                              values_bytes.begin() + static_cast<size_t>(total_bytes));
}

// Decodes `num_non_null` PLAIN-encoded BYTE_ARRAY values (4-byte length prefix +
// data, per value) into owned strings. Each decoded ByteArray's `ptr` aliases
// `values_bytes` (see decoder.cc's ReadByteArray()); copied into std::string
// immediately, since values_bytes points into Decompress()'s local page buffer
// and would otherwise leave CryptoValueBuffer's owning vector<string> holding
// dangling pointers once this function returns.
std::vector<std::string> DecodePlainByteArrayValues(std::span<const uint8_t> values_bytes,
                                                    int64_t num_non_null) {
  if (num_non_null < 0 || num_non_null > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid non-null value count");
  }
  if (values_bytes.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    throw ParquetException("ParquetPageDecoder: values buffer too large to decode");
  }
  auto decoder = MakeTypedDecoder<ByteArrayType>(Encoding::PLAIN);
  decoder->SetData(static_cast<int>(num_non_null), values_bytes.data(),
                   static_cast<int>(values_bytes.size()));
  std::vector<ByteArray> raw(static_cast<size_t>(num_non_null));
  int decoded = decoder->Decode(raw.data(), static_cast<int>(num_non_null));
  if (decoded != static_cast<int>(num_non_null)) {
    throw ParquetException("ParquetPageDecoder: failed to decode all values");
  }
  std::vector<std::string> values;
  values.reserve(raw.size());
  for (const ByteArray& byte_array : raw) {
    values.emplace_back(reinterpret_cast<const char*>(byte_array.ptr), byte_array.len);
  }
  return values;
}

// Decodes `num_non_null` PLAIN-encoded values of `result->physical_type()` from
// `values_bytes` into `result`. Shared by DataPageV2's and DictionaryPage's
// Decompress() branches, which differ only in framing (levels present or not,
// see the two callers) -- never in how the values portion itself is decoded.
// `props.GetFixedLengthBytes()` is only read lazily, inside the FIXED_LEN_BYTE_ARRAY
// case, since it's only ever set for that physical type.
void DecodeValuesPortion(std::span<const uint8_t> values_bytes, int64_t num_non_null,
                         const encryption::EncodingProperties& props,
                         TypedColumnValues* result) {
  switch (result->physical_type()) {
    case Type::INT32:
      result->SetFixedWidthValues(
          DecodePlainValues<Int32Type>(values_bytes, num_non_null));
      break;
    case Type::INT64:
      result->SetFixedWidthValues(
          DecodePlainValues<Int64Type>(values_bytes, num_non_null));
      break;
    case Type::INT96:
      result->SetFixedWidthValues(
          DecodePlainValues<Int96Type>(values_bytes, num_non_null));
      break;
    case Type::FLOAT:
      result->SetFixedWidthValues(
          DecodePlainValues<FloatType>(values_bytes, num_non_null));
      break;
    case Type::DOUBLE:
      result->SetFixedWidthValues(
          DecodePlainValues<DoubleType>(values_bytes, num_non_null));
      break;
    case Type::BOOLEAN:
      result->SetFixedWidthValues(DecodePlainBooleanValues(values_bytes, num_non_null));
      break;
    case Type::FIXED_LEN_BYTE_ARRAY:
      result->SetFixedWidthValues(DecodePlainFixedLenByteArrayValues(
          values_bytes, num_non_null, props.GetFixedLengthBytes()));
      break;
    case Type::BYTE_ARRAY:
      result->SetByteArrayValues(DecodePlainByteArrayValues(values_bytes, num_non_null));
      break;
    case Type::UNDEFINED:
    default:
      throw ParquetException("ParquetPageDecoder: unsupported physical type");
  }
}

// RLE-encodes `levels` the same way column_writer.cc's LevelEncoder does for
// DataPageV2 -- mirrors the test suite's EncodeLevelsRLE() helper, reused here
// since Recompress() needs genuine on-wire level bytes, not a hand-rolled stand-in.
std::vector<uint8_t> EncodeLevelsRLE(const std::vector<int16_t>& levels,
                                     int16_t max_level) {
  std::vector<uint8_t> buffer(LevelEncoder::MaxBufferSize(
      Encoding::RLE, max_level, static_cast<int>(levels.size())));
  LevelEncoder encoder;
  encoder.Init(Encoding::RLE, max_level, static_cast<int>(levels.size()), buffer.data(),
               static_cast<int>(buffer.size()));
  int num_encoded = encoder.Encode(static_cast<int>(levels.size()), levels.data());
  if (num_encoded != static_cast<int>(levels.size())) {
    throw ParquetException("ParquetPageDecoder: failed to encode all levels");
  }
  buffer.resize(static_cast<size_t>(encoder.len()));
  return buffer;
}

// Mirrors EncodeLevelsRLE(), but for DataPageV1: unlike DataPageV2 (whose page
// header already carries explicit *_levels_byte_length fields), a V1 page embeds
// each level section's own 4-byte length prefix inline -- matches
// column_writer.cc's RleEncodeLevels(..., include_length_prefix=true), which this
// mirrors on the encode side, and LevelDecoder::SetData()'s RLE case, which this
// mirrors on the decode side (see the DATA_PAGE branch in Decompress() below).
std::vector<uint8_t> EncodeLevelsRLEWithLengthPrefix(const std::vector<int16_t>& levels,
                                                     int16_t max_level) {
  constexpr size_t kPrefixSize = sizeof(int32_t);
  std::vector<uint8_t> buffer(
      kPrefixSize + static_cast<size_t>(LevelEncoder::MaxBufferSize(
                        Encoding::RLE, max_level, static_cast<int>(levels.size()))));
  LevelEncoder encoder;
  encoder.Init(Encoding::RLE, max_level, static_cast<int>(levels.size()),
               buffer.data() + kPrefixSize,
               static_cast<int>(buffer.size() - kPrefixSize));
  int num_encoded = encoder.Encode(static_cast<int>(levels.size()), levels.data());
  if (num_encoded != static_cast<int>(levels.size())) {
    throw ParquetException("ParquetPageDecoder: failed to encode all levels");
  }
  reinterpret_cast<int32_t*>(buffer.data())[0] = encoder.len();
  buffer.resize(kPrefixSize + static_cast<size_t>(encoder.len()));
  return buffer;
}

// Mirrors DecodePlainValues<DType>(): PLAIN-encodes fixed-width values via Arrow's
// own Encoder<DType> machinery -- no independent codec logic, matching the class's
// documented design.
template <typename DType>
std::vector<uint8_t> EncodePlainValues(std::span<const typename DType::c_type> values) {
  auto encoder = MakeTypedEncoder<DType>(Encoding::PLAIN);
  encoder->Put(values.data(), static_cast<int>(values.size()));
  std::shared_ptr<::arrow::Buffer> buffer = encoder->FlushValues();
  return std::vector<uint8_t>(buffer->data(), buffer->data() + buffer->size());
}

// Mirrors DecodePlainByteArrayValues(): re-derives and writes each value's 4-byte
// length prefix via Arrow's own Encoder<ByteArrayType>, from whatever length the
// string ended up at after EncryptCells()/DecryptCells() ran.
std::vector<uint8_t> EncodePlainByteArrayValues(const std::vector<std::string>& values) {
  const std::vector<ByteArray> byte_arrays(values.begin(), values.end());
  auto encoder = MakeTypedEncoder<ByteArrayType>(Encoding::PLAIN);
  encoder->Put(byte_arrays.data(), static_cast<int>(byte_arrays.size()));
  std::shared_ptr<::arrow::Buffer> buffer = encoder->FlushValues();
  return std::vector<uint8_t>(buffer->data(), buffer->data() + buffer->size());
}

// Mirrors Decompress()'s switch, in the opposite direction: PLAIN-encodes `values`
// back into bytes. BOOLEAN/FIXED_LEN_BYTE_ARRAY are a straight copy rather than a
// round trip through an encoder -- CryptoValueBuffer already stores their bytes in
// exactly the on-disk PLAIN layout (packed bits for BOOLEAN, raw fixed-width bytes
// for FIXED_LEN_BYTE_ARRAY; see parquet_crypto_provider.h), and TypedEncoder<
// BooleanType> has no packed-bits-in overload to reuse (only bool*/vector<bool>).
std::vector<uint8_t> EncodeValuesPortion(const TypedColumnValues& values) {
  switch (values.physical_type()) {
    case Type::INT32:
      return EncodePlainValues<Int32Type>(std::get<std::span<int32_t>>(values.values()));
    case Type::INT64:
      return EncodePlainValues<Int64Type>(std::get<std::span<int64_t>>(values.values()));
    case Type::INT96:
      return EncodePlainValues<Int96Type>(std::get<std::span<Int96>>(values.values()));
    case Type::FLOAT:
      return EncodePlainValues<FloatType>(std::get<std::span<float>>(values.values()));
    case Type::DOUBLE:
      return EncodePlainValues<DoubleType>(std::get<std::span<double>>(values.values()));
    case Type::BOOLEAN:
    case Type::FIXED_LEN_BYTE_ARRAY: {
      std::span<uint8_t> packed = std::get<std::span<uint8_t>>(values.values());
      return std::vector<uint8_t>(packed.begin(), packed.end());
    }
    case Type::BYTE_ARRAY:
      return EncodePlainByteArrayValues(
          std::get<std::vector<std::string>>(values.values()));
    case Type::UNDEFINED:
    default:
      throw ParquetException("ParquetPageDecoder: unsupported physical type");
  }
}

// Decompresses `data` with `codec_type` in one shot into a tightly-sized buffer of
// exactly `uncompressed_len` bytes. Arrow's Codec class exposes only the raw
// MaxCompressedLen()/Compress()/Decompress() primitives (no owned-buffer
// convenience wrapper), so this resize/call/verify sequence is written once here
// and shared by DataPageV2's and DictionaryPage's decompress paths below, which
// otherwise differ only in how they arrive at `uncompressed_len`. `codec`, when
// non-null, is reused instead of constructing a fresh one -- lets a long-lived
// caller (e.g. an adapter that persists for a whole column chunk) amortize codec
// construction across every page, mirroring column_reader.cc's cached
// `decompressor_`.
std::vector<uint8_t> DecompressBuffer(std::span<const uint8_t> data,
                                      int64_t uncompressed_len,
                                      ::arrow::Compression::type codec_type,
                                      ::arrow::util::Codec* codec = nullptr) {
  std::vector<uint8_t> decompressed(static_cast<size_t>(uncompressed_len));
  if (uncompressed_len > 0) {
    // A page/dictionary may be empty (GH-31992); some codecs reject a
    // zero-length compressed input, so skip the call entirely in that case.
    std::unique_ptr<::arrow::util::Codec> owned_codec;
    ::arrow::util::Codec* codec_ptr = codec;
    if (codec_ptr == nullptr) {
      PARQUET_ASSIGN_OR_THROW(owned_codec, ::arrow::util::Codec::Create(codec_type));
      codec_ptr = owned_codec.get();
    }
    PARQUET_ASSIGN_OR_THROW(
        int64_t actual_len,
        codec_ptr->Decompress(static_cast<int64_t>(data.size()), data.data(),
                              uncompressed_len, decompressed.data()));
    if (actual_len != uncompressed_len) {
      throw ParquetException(
          "ParquetPageDecoder: values did not decompress to the expected size");
    }
  }
  return decompressed;
}

// Mirrors DecompressBuffer() in reverse; see its comment (including the `codec`
// reuse parameter).
std::vector<uint8_t> CompressBuffer(std::span<const uint8_t> data,
                                    ::arrow::Compression::type codec_type,
                                    ::arrow::util::Codec* codec = nullptr) {
  std::unique_ptr<::arrow::util::Codec> owned_codec;
  ::arrow::util::Codec* codec_ptr = codec;
  if (codec_ptr == nullptr) {
    PARQUET_ASSIGN_OR_THROW(owned_codec, ::arrow::util::Codec::Create(codec_type));
    codec_ptr = owned_codec.get();
  }
  const int64_t max_compressed_len =
      codec_ptr->MaxCompressedLen(static_cast<int64_t>(data.size()), data.data());
  std::vector<uint8_t> output(static_cast<size_t>(max_compressed_len));
  PARQUET_ASSIGN_OR_THROW(
      int64_t actual_len,
      codec_ptr->Compress(static_cast<int64_t>(data.size()), data.data(),
                          max_compressed_len, output.data()));
  output.resize(static_cast<size_t>(actual_len));
  return output;
}

// Decompresses a DictionaryPage's buffer in one shot. Unlike DataPageV2, a
// DictionaryPage has no levels to split out and no per-page is-compressed flag --
// compression is decided solely by whether the column has a compression codec at
// all, mirroring column_writer.cc's WriteDictionaryPage() (has_compressor()) and
// column_reader.cc's DecompressIfNeeded() (decompressor_ == nullptr), both of
// which compress/decompress a DictionaryPage unconditionally whenever the column
// has a codec, with no per-page opt-out.
std::vector<uint8_t> DecompressDictionaryPageBuffer(
    std::span<const uint8_t> page, const encryption::EncodingProperties& props,
    ::arrow::util::Codec* codec = nullptr) {
  if (props.GetCompressionCodec() == ::arrow::Compression::UNCOMPRESSED) {
    return std::vector<uint8_t>(page.begin(), page.end());
  }
  const int64_t uncompressed_len = props.GetUncompressedPageSize();
  if (uncompressed_len < 0) {
    throw ParquetException(
        "ParquetPageDecoder: invalid DictionaryPage uncompressed size");
  }
  return DecompressBuffer(page, uncompressed_len, props.GetCompressionCodec(), codec);
}

// Mirrors DecompressDictionaryPageBuffer() in reverse -- same unconditional
// (no per-page opt-out) compression rule.
std::vector<uint8_t> CompressDictionaryPageBuffer(
    std::span<const uint8_t> values_bytes, const encryption::EncodingProperties& props,
    ::arrow::util::Codec* codec = nullptr) {
  if (props.GetCompressionCodec() == ::arrow::Compression::UNCOMPRESSED ||
      values_bytes.empty()) {
    return std::vector<uint8_t>(values_bytes.begin(), values_bytes.end());
  }
  return CompressBuffer(values_bytes, props.GetCompressionCodec(), codec);
}

// Decompresses a DataPageV1's buffer in one shot. Unlike DataPageV2 (whose levels
// are never compressed and whose page header carries explicit *_levels_byte_length
// fields), a V1 page compresses its levels and values together as a single blob --
// same unconditional (no per-page opt-out) compression rule as
// DecompressDictionaryPageBuffer() above, mirrored here rather than reused directly
// since the two page types populate uncompressed_page_size_ from different Thrift
// fields (see encoding_properties.cc's MakeFromMetadata()).
std::vector<uint8_t> DecompressDataPageV1Buffer(
    std::span<const uint8_t> page, const encryption::EncodingProperties& props,
    ::arrow::util::Codec* codec = nullptr) {
  if (props.GetCompressionCodec() == ::arrow::Compression::UNCOMPRESSED) {
    return std::vector<uint8_t>(page.begin(), page.end());
  }
  const int64_t uncompressed_len = props.GetUncompressedPageSize();
  if (uncompressed_len < 0) {
    throw ParquetException("ParquetPageDecoder: invalid DataPageV1 uncompressed size");
  }
  return DecompressBuffer(page, uncompressed_len, props.GetCompressionCodec(), codec);
}

// Mirrors DecompressDataPageV1Buffer() in reverse -- same unconditional
// (no per-page opt-out) compression rule.
std::vector<uint8_t> CompressDataPageV1Buffer(std::span<const uint8_t> page_bytes,
                                              const encryption::EncodingProperties& props,
                                              ::arrow::util::Codec* codec = nullptr) {
  if (props.GetCompressionCodec() == ::arrow::Compression::UNCOMPRESSED ||
      page_bytes.empty()) {
    return std::vector<uint8_t>(page_bytes.begin(), page_bytes.end());
  }
  return CompressBuffer(page_bytes, props.GetCompressionCodec(), codec);
}

}  // namespace

std::vector<uint8_t> ParquetPageDecoder::SplitAndDecompressDataPageV2(
    std::span<const uint8_t> page, const encryption::EncodingProperties& props,
    ::arrow::util::Codec* codec) {
  if (props.GetPageType() != PageType::DATA_PAGE_V2) {
    throw ParquetException(
        "ParquetPageDecoder::SplitAndDecompressDataPageV2 only supports DataPageV2 "
        "pages");
  }

  // Matches column_reader.cc's SerializedPageReader::NextPage() level-length
  // addition: an overflow-checked int32 add (level lengths are int32_t on the
  // wire), widened to int64_t only for the buffer-size comparison below.
  int32_t levels_len = 0;
  if (::arrow::internal::AddWithOverflow(props.GetPageV2DefinitionLevelsByteLength(),
                                         props.GetPageV2RepetitionLevelsByteLength(),
                                         &levels_len) ||
      levels_len < 0 ||
      static_cast<int64_t>(levels_len) > static_cast<int64_t>(page.size())) {
    throw ParquetException(
        "ParquetPageDecoder: DataPageV2 level byte lengths exceed the page buffer");
  }

  std::span<const uint8_t> levels = page.subspan(0, static_cast<size_t>(levels_len));
  std::span<const uint8_t> values_portion = page.subspan(static_cast<size_t>(levels_len));

  std::vector<uint8_t> decompressed_values;
  if (!props.GetPageV2IsCompressed()) {
    decompressed_values.assign(values_portion.begin(), values_portion.end());
  } else {
    // UncompressedPageSize is the whole page (levels + values); subtract the
    // level bytes to get the values' one-shot decompression output size. A known
    // output size lets this use Codec::Decompress() directly instead of a
    // streaming Decompressor, which not every codec implements (e.g. Snappy).
    const int64_t uncompressed_values_len =
        props.GetUncompressedPageSize() - static_cast<int64_t>(levels_len);
    if (uncompressed_values_len < 0) {
      throw ParquetException(
          "ParquetPageDecoder: DataPageV2 uncompressed page size is smaller than "
          "its level byte lengths");
    }
    decompressed_values = DecompressBuffer(values_portion, uncompressed_values_len,
                                           props.GetCompressionCodec(), codec);
  }

  // One contiguous buffer, levels then values -- mirrors DataPageV2's own
  // single-buffer-plus-offset convention instead of returning a span/vector pair.
  std::vector<uint8_t> result;
  result.reserve(levels.size() + decompressed_values.size());
  result.insert(result.end(), levels.begin(), levels.end());
  result.insert(result.end(), decompressed_values.begin(), decompressed_values.end());
  return result;
}

// Decompress() decodes rep/def levels (DataPageV1 and DataPageV2) and, for every
// PLAIN-encoded physical type, the values themselves. A DictionaryPage has no
// levels at all -- see the branch below for why it's routed differently instead
// of reusing DataPageV2's framing. Recompress() (below) mirrors this in reverse.
TypedColumnValues ParquetPageDecoder::Decompress(
    std::span<const uint8_t> compressed_page, const encryption::EncodingProperties& props,
    ::arrow::util::Codec* codec) {
  if (props.GetPageEncoding() != Encoding::PLAIN) {
    throw ParquetException(
        "ParquetPageDecoder::Decompress: only PLAIN value encoding is currently "
        "supported");
  }

  if (props.GetPageType() == PageType::DICTIONARY_PAGE) {
    // A DictionaryPage is a flat, non-nullable list of distinct values -- no
    // rep/def levels, no logical-null concept (mirrors Arrow's own DictionaryPage/
    // ConfigureDictionary(), which decode exactly num_values() entries with no
    // level or null handling at all). max_definition_level/max_repetition_level
    // are 0 and both level vectors stay empty; num_values() derives its count
    // directly from values() instead (see TypedColumnValues::num_values()).
    TypedColumnValues result(props.GetPhysicalType(), /*max_definition_level=*/0,
                             /*max_repetition_level=*/0);
    std::vector<uint8_t> values_bytes =
        DecompressDictionaryPageBuffer(compressed_page, props, codec);
    DecodeValuesPortion(values_bytes, props.GetDictPageNumValues(), props, &result);
    return result;
  }

  if (props.GetPageType() == PageType::DATA_PAGE) {
    // DataPageV1 Layout: Repetition Levels - Definition Levels - encoded values,
    // the whole blob compressed together (unlike DataPageV2, which compresses only
    // the values). Each level section is self-delimiting (RLE: an embedded 4-byte
    // length prefix; BIT_PACKED: a byte count derived purely from num_values and
    // max_level) -- parsed via the same LevelDecoder::SetData() column_reader.cc's
    // InitializeLevelDecoders() uses, which already handles both encodings, so no
    // separate branch is needed here for which one the file actually used.
    std::vector<uint8_t> page = DecompressDataPageV1Buffer(compressed_page, props, codec);

    TypedColumnValues result(props.GetPhysicalType(),
                             props.GetDataPageMaxDefinitionLevel(),
                             props.GetDataPageMaxRepetitionLevel());

    const int64_t num_values = props.GetDataPageNumValues();
    if (num_values < 0 || num_values > std::numeric_limits<int>::max()) {
      throw ParquetException("ParquetPageDecoder: invalid DataPageV1 num_values");
    }
    if (page.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
      throw ParquetException("ParquetPageDecoder: DataPageV1 page too large");
    }

    const uint8_t* buffer = page.data();
    int32_t remaining = static_cast<int32_t>(page.size());

    // Unlike DataPageV2's ARROW-17453 unconditional advance, a V1 page omits
    // repetition-level bytes entirely when max_repetition_level()==0 -- mirrors
    // column_reader.cc's InitializeLevelDecoders(), which only touches the
    // repetition-level decoder/buffer inside this same condition.
    if (result.max_repetition_level() > 0) {
      LevelDecoder rep_decoder(result.max_repetition_level());
      int32_t rep_bytes = rep_decoder.SetData(
          props.GetPageV1RepetitionLevelEncoding(), result.max_repetition_level(),
          static_cast<int>(num_values), buffer, remaining);
      result.repetition_levels().resize(static_cast<size_t>(num_values));
      int decoded = rep_decoder.Decode(static_cast<int>(num_values),
                                       result.repetition_levels().data());
      if (decoded != static_cast<int>(num_values)) {
        throw ParquetException(
            "ParquetPageDecoder: failed to decode all repetition levels");
      }
      buffer += rep_bytes;
      remaining -= rep_bytes;
    }

    // definition_levels() is always fully populated, even for a required (no-null)
    // column -- TypedColumnValues::num_values() relies on its size.
    result.definition_levels().resize(static_cast<size_t>(num_values));
    if (result.max_definition_level() > 0) {
      LevelDecoder def_decoder(result.max_definition_level());
      int32_t def_bytes = def_decoder.SetData(
          props.GetPageV1DefinitionLevelEncoding(), result.max_definition_level(),
          static_cast<int>(num_values), buffer, remaining);
      int decoded = def_decoder.Decode(static_cast<int>(num_values),
                                       result.definition_levels().data());
      if (decoded != static_cast<int>(num_values)) {
        throw ParquetException(
            "ParquetPageDecoder: failed to decode all definition levels");
      }
      buffer += def_bytes;
      remaining -= def_bytes;
    } else {
      std::fill(result.definition_levels().begin(), result.definition_levels().end(), 0);
    }

    if (remaining < 0) {
      throw ParquetException("ParquetPageDecoder: level bytes exceed the page buffer");
    }

    const int64_t num_non_null =
        CountNonNullValues(result.definition_levels(), result.max_definition_level());
    std::span<const uint8_t> values_bytes(buffer, static_cast<size_t>(remaining));
    DecodeValuesPortion(values_bytes, num_non_null, props, &result);
    return result;
  }

  std::vector<uint8_t> page = SplitAndDecompressDataPageV2(compressed_page, props, codec);

  TypedColumnValues result(props.GetPhysicalType(), props.GetDataPageMaxDefinitionLevel(),
                           props.GetDataPageMaxRepetitionLevel());

  const int32_t rep_len = props.GetPageV2RepetitionLevelsByteLength();
  const int32_t def_len = props.GetPageV2DefinitionLevelsByteLength();
  const int64_t num_values = props.GetDataPageNumValues();
  if (num_values < 0 || num_values > std::numeric_limits<int>::max()) {
    throw ParquetException("ParquetPageDecoder: invalid DataPageV2 num_values");
  }

  const uint8_t* buffer = page.data();

  // Matches TypedColumnValues's documented contract: repetition_levels() stays
  // empty for non-repeated (non-list) columns, unlike definition_levels() (below),
  // which is always fully populated.
  if (result.max_repetition_level() > 0) {
    LevelDecoder rep_decoder(result.max_repetition_level());
    rep_decoder.SetDataV2(rep_len, result.max_repetition_level(),
                          static_cast<int>(num_values), buffer);
    result.repetition_levels().resize(static_cast<size_t>(num_values));
    int decoded = rep_decoder.Decode(static_cast<int>(num_values),
                                     result.repetition_levels().data());
    if (decoded != static_cast<int>(num_values)) {
      throw ParquetException(
          "ParquetPageDecoder: failed to decode all repetition levels");
    }
  }
  // Unconditional: some writers emit repetition-level bytes even when
  // max_repetition_level()==0 (mirrors column_reader.cc's ARROW-17453 fix).
  buffer += rep_len;

  // definition_levels() is always fully populated, even for a required (no-null)
  // column -- TypedColumnValues::num_values() relies on its size to report the
  // page's total logical value count.
  result.definition_levels().resize(static_cast<size_t>(num_values));
  if (result.max_definition_level() > 0) {
    LevelDecoder def_decoder(result.max_definition_level());
    def_decoder.SetDataV2(def_len, result.max_definition_level(),
                          static_cast<int>(num_values), buffer);
    int decoded = def_decoder.Decode(static_cast<int>(num_values),
                                     result.definition_levels().data());
    if (decoded != static_cast<int>(num_values)) {
      throw ParquetException(
          "ParquetPageDecoder: failed to decode all definition levels");
    }
  } else {
    // Required column: every value is present, definition level 0 for all.
    std::fill(result.definition_levels().begin(), result.definition_levels().end(), 0);
  }
  // Unconditional for the same reason as the repetition-level advance above --
  // buffer must reach the values portion regardless of whether def_len was 0.
  buffer += def_len;

  // Defensive: SplitAndDecompressDataPageV2() already guarantees rep_len+def_len
  // fits within page.size(), but that invariant is established in a different
  // function -- re-check here rather than rely on it silently holding, since a
  // violation would otherwise underflow the size passed to values_bytes below.
  if (buffer > page.data() + page.size()) {
    throw ParquetException("ParquetPageDecoder: level bytes exceed the page buffer");
  }

  const int64_t num_non_null =
      CountNonNullValues(result.definition_levels(), result.max_definition_level());
  std::span<const uint8_t> values_bytes(
      buffer, static_cast<size_t>(page.data() + page.size() - buffer));

  DecodeValuesPortion(values_bytes, num_non_null, props, &result);

  return result;
}

std::vector<uint8_t> ParquetPageDecoder::Recompress(
    const TypedColumnValues& values, const encryption::EncodingProperties& props,
    int64_t* new_uncompressed_size, ::arrow::util::Codec* codec) {
  if (props.GetPageEncoding() != Encoding::PLAIN) {
    throw ParquetException(
        "ParquetPageDecoder::Recompress: only PLAIN value encoding is currently "
        "supported");
  }

  if (props.GetPageType() == PageType::DICTIONARY_PAGE) {
    // No levels for a DictionaryPage -- mirrors Decompress()'s DICTIONARY_PAGE
    // branch above.
    std::vector<uint8_t> values_bytes = EncodeValuesPortion(values);
    if (new_uncompressed_size != nullptr) {
      *new_uncompressed_size = static_cast<int64_t>(values_bytes.size());
    }
    return CompressDictionaryPageBuffer(values_bytes, props, codec);
  }

  if (props.GetPageType() == PageType::DATA_PAGE) {
    // Mirrors the DICTIONARY_PAGE branch's reasoning: repetition/definition levels
    // are never mutated by EncryptCells()/DecryptCells(), so re-encoding them
    // always reproduces byte-identical output to props's frozen originals -- only
    // values_bytes's size can legitimately change. Only RLE-encoded levels can be
    // re-emitted (the only encoding Arrow's own writer ever produces for V1); a
    // file written by another implementation with BIT_PACKED levels decodes fine
    // (see Decompress()) but cannot round-trip through the cell path.
    if ((values.max_repetition_level() > 0 &&
         props.GetPageV1RepetitionLevelEncoding() != Encoding::RLE) ||
        (values.max_definition_level() > 0 &&
         props.GetPageV1DefinitionLevelEncoding() != Encoding::RLE)) {
      throw ParquetException(
          "ParquetPageDecoder::Recompress: only RLE-encoded DataPageV1 levels can "
          "be re-encoded");
    }

    std::vector<uint8_t> rep_bytes;
    if (values.max_repetition_level() > 0) {
      rep_bytes = EncodeLevelsRLEWithLengthPrefix(values.repetition_levels(),
                                                  values.max_repetition_level());
    }
    std::vector<uint8_t> def_bytes;
    if (values.max_definition_level() > 0) {
      def_bytes = EncodeLevelsRLEWithLengthPrefix(values.definition_levels(),
                                                  values.max_definition_level());
    }
    std::vector<uint8_t> values_bytes = EncodeValuesPortion(values);

    if (new_uncompressed_size != nullptr) {
      *new_uncompressed_size =
          static_cast<int64_t>(rep_bytes.size() + def_bytes.size() + values_bytes.size());
    }

    // Unlike DataPageV2, a V1 page's levels and values are compressed together as
    // one blob -- concatenate first, then compress the whole thing.
    std::vector<uint8_t> page_bytes;
    page_bytes.reserve(rep_bytes.size() + def_bytes.size() + values_bytes.size());
    page_bytes.insert(page_bytes.end(), rep_bytes.begin(), rep_bytes.end());
    page_bytes.insert(page_bytes.end(), def_bytes.begin(), def_bytes.end());
    page_bytes.insert(page_bytes.end(), values_bytes.begin(), values_bytes.end());
    return CompressDataPageV1Buffer(page_bytes, props, codec);
  }

  if (props.GetPageType() != PageType::DATA_PAGE_V2) {
    throw ParquetException(
        "ParquetPageDecoder::Recompress only supports DataPageV1, DataPageV2, and "
        "DictionaryPage pages");
  }

  // Repetition/definition levels are never mutated by ParquetCryptoProvider::
  // EncryptCells()/DecryptCells() -- only values() is -- so re-encoding them always
  // reproduces byte-identical output to props's frozen originals; only the values
  // portion's size can legitimately change (e.g. a BYTE_ARRAY value's length
  // changing).
  std::vector<uint8_t> rep_bytes;
  if (values.max_repetition_level() > 0) {
    rep_bytes =
        EncodeLevelsRLE(values.repetition_levels(), values.max_repetition_level());
  }
  std::vector<uint8_t> def_bytes;
  if (values.max_definition_level() > 0) {
    def_bytes =
        EncodeLevelsRLE(values.definition_levels(), values.max_definition_level());
  }

  std::vector<uint8_t> values_bytes = EncodeValuesPortion(values);

  const int64_t uncompressed_size =
      static_cast<int64_t>(rep_bytes.size() + def_bytes.size() + values_bytes.size());

  std::vector<uint8_t> output_values;
  if (!props.GetPageV2IsCompressed()) {
    output_values = std::move(values_bytes);
  } else if (!values_bytes.empty()) {
    // Mirrors SplitAndDecompressDataPageV2()'s inverse: only the values portion is
    // ever compressed in a DataPageV2 -- levels never are.
    output_values = CompressBuffer(values_bytes, props.GetCompressionCodec(), codec);
  }
  // else: a page may have zero values when every row is null (GH-31992); some
  // codecs reject a zero-length compressed input, so skip the call entirely,
  // mirroring SplitAndDecompressDataPageV2()'s same skip on the decode side.

  if (new_uncompressed_size != nullptr) {
    *new_uncompressed_size = uncompressed_size;
  }
  std::vector<uint8_t> page_bytes;
  page_bytes.reserve(rep_bytes.size() + def_bytes.size() + output_values.size());
  page_bytes.insert(page_bytes.end(), rep_bytes.begin(), rep_bytes.end());
  page_bytes.insert(page_bytes.end(), def_bytes.begin(), def_bytes.end());
  page_bytes.insert(page_bytes.end(), output_values.begin(), output_values.end());
  return page_bytes;
}

}  // namespace parquet
