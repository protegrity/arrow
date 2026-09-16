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
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "arrow/result.h"
#include "arrow/status.h"
#include "parquet/platform.h"
#include "parquet/types.h"

namespace parquet {

/// Describes the Parquet module a single ParquetCryptoProvider call applies to.
///
/// Populated by Arrow from the file's crypto metadata. `key_metadata` is an opaque,
/// implementation-defined string read verbatim from the file (or supplied by the
/// application on write); Arrow never parses it or derives key material from it.
struct PARQUET_EXPORT ParquetCryptoContext {
  /// Opaque key or policy identifier, interpreted only by the ParquetCryptoProvider
  /// implementation. Same value for every module belonging to one column (or the
  /// footer).
  std::string key_metadata;
  /// Dot-separated Parquet column path (e.g. "address.zip"); empty for the
  /// file-level footer modules.
  std::string column_path;
  /// Physical type of the column; meaningless for footer modules.
  Type::type data_type = Type::BYTE_ARRAY;
  /// Byte width for FIXED_LEN_BYTE_ARRAY columns; nullopt for all other types.
  std::optional<int> datatype_length;
  /// Application-supplied JSON context for access-control decisions, forwarded
  /// verbatim from FileEncryptionProperties/FileDecryptionProperties. Same value
  /// for every module in the file; empty if the application did not set one.
  std::string app_context;
};

/// Type-erased, per-page buffer of decoded column values, used by the cell path.
///
/// One discriminant covers the whole page (resolved once via `std::get`), not one
/// per value — a Parquet page is single-typed by construction, so boxing
/// each value in its own tagged union wastes memory and forces a redundant type
/// check on every element. Fixed-width physical types are non-owning, mutable spans
/// into caller-owned storage (zero-copy). Only BYTE_ARRAY uses an owning
/// `vector<string>`, since its per-value length is not schema-fixed and
/// tokenization/FPE may change it.
///
/// BOOLEAN and FIXED_LEN_BYTE_ARRAY share the `span<uint8_t>` alternative: both are
/// packed, fixed-stride byte data (stride 1 for BOOLEAN, `ctx.datatype_length` for
/// FIXED_LEN_BYTE_ARRAY — the width Parquet's schema guarantees for every value in
/// that column, so a zero-copy view is always valid). BOOLEAN specifically matches
/// `BooleanDecoder::Decode(uint8_t*, ...)` — `vector<bool>` is bit-packed and cannot
/// be viewed as a span.
using CryptoValueBuffer =
    std::variant<std::span<uint8_t>,         // BOOLEAN (stride 1) or FIXED_LEN_BYTE_ARRAY
                 std::span<int32_t>,         // INT32
                 std::span<int64_t>,         // INT64
                 std::span<Int96>,           // INT96 (deprecated)
                 std::span<float>,           // FLOAT
                 std::span<double>,          // DOUBLE
                 std::vector<std::string>>;  // BYTE_ARRAY

/// Pure-virtual interface for an external Parquet crypto provider.
///
/// Implement this interface to protect Parquet file modules (footer, column
/// metadata, data pages, dictionary pages, and related structures) with a
/// third-party key-management, HSM, or tokenization backend instead of Arrow's
/// built-in AES-GCM/CTR encryptor. `ParquetCryptoContext::key_metadata` is an
/// opaque string only the implementation interprets; `dek` (below) carries the
/// actual key bytes Arrow generated for the column or footer.
///
/// Arrow calls exactly one of the two paths below for a given provider
/// instance, decided once via SupportsTypedValues():
/// - false (block path): only EncryptBlock()/DecryptBlock() are called.
/// - true (cell path): only EncryptCells()/DecryptCells() are called.
/// The inactive path's methods must still be overridden but are never invoked;
/// implementations may return Status::OK()/an empty buffer for them.
///
/// Thread safety: implementations must be thread-safe. Arrow may call these
/// methods concurrently for different columns during parallel row-group reads
/// and writes.
class PARQUET_EXPORT ParquetCryptoProvider {
 public:
  virtual ~ParquetCryptoProvider() = default;

  /// Encrypt a raw module block (compressed page, footer, or serialized
  /// column metadata).
  ///
  /// \param plaintext The raw bytes to encrypt.
  /// \param ctx Identifies the column (or footer) and module this call applies to.
  /// \param module_aad Arrow-computed positional binding (file AAD, module
  ///     type, row group, column, and page ordinals). AES-GCM implementations
  ///     should pass it as additional authenticated data; ciphers without an
  ///     AEAD tag may ignore it.
  /// \param dek The column's or footer's data-encryption key, forwarded
  ///     unconditionally by Arrow. A block cipher always requires it; empty
  ///     only when Arrow could not resolve a key for this module.
  virtual ::arrow::Result<std::vector<uint8_t>> EncryptBlock(
      std::span<const uint8_t> plaintext, const ParquetCryptoContext& ctx,
      std::span<const uint8_t> module_aad, std::span<const uint8_t> dek = {}) = 0;

  /// Decrypt a raw module block. See EncryptBlock() for `module_aad`/`dek` semantics.
  ///
  /// \param ciphertext The raw bytes to decrypt.
  /// \param ctx Identifies the column (or footer) and module this call applies to.
  /// \param module_aad Same value EncryptBlock() received for this module.
  /// \param dek Same value EncryptBlock() received for this module.
  virtual ::arrow::Result<std::vector<uint8_t>> DecryptBlock(
      std::span<const uint8_t> ciphertext, const ParquetCryptoContext& ctx,
      std::span<const uint8_t> module_aad, std::span<const uint8_t> dek = {}) = 0;

  /// Selects the routing path Arrow uses for this provider.
  ///
  /// false: Arrow calls EncryptBlock()/DecryptBlock() with raw module bytes.
  /// true: Arrow decodes the page into typed values first and calls
  /// EncryptCells()/DecryptCells() instead.
  [[nodiscard]] virtual bool SupportsTypedValues() const = 0;

  /// Transform decoded column values in place (e.g. tokenize, FPE,
  /// pseudonymize). Called only when SupportsTypedValues() returns true.
  ///
  /// \param values The page's decoded values, transformed in place.
  /// \param ctx Identifies the column this call applies to.
  /// \param dek Same key as EncryptBlock()'s `dek`. The cell path may use it
  ///     (e.g. keyed FPE) or ignore it (pure tokenization).
  virtual ::arrow::Status EncryptCells(CryptoValueBuffer& values,
                                       const ParquetCryptoContext& ctx,
                                       std::span<const uint8_t> dek = {}) = 0;

  /// Reverse the transform applied by EncryptCells(). Called only when
  /// SupportsTypedValues() returns true.
  ///
  /// \param values The page's decoded values, transformed in place.
  /// \param ctx Identifies the column this call applies to.
  /// \param dek Same value EncryptCells() received for this column.
  virtual ::arrow::Status DecryptCells(CryptoValueBuffer& values,
                                       const ParquetCryptoContext& ctx,
                                       std::span<const uint8_t> dek = {}) = 0;
};

}  // namespace parquet
