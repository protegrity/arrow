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

#include <memory>
#include <optional>
#include <string>

#include "arrow/util/type_fwd.h"
#include "parquet/platform.h"
#include "parquet/types.h"

namespace parquet::encryption {
class EncryptorInterface;
}  // namespace parquet::encryption

namespace parquet {

/// Parameters identifying a single column for external encryption or decryption.
struct PARQUET_EXPORT ColumnEncryptionParams {
  /// Opaque key identifier set via ColumnEncryptionProperties::Builder::key_metadata().
  /// Not raw key bytes and not KMS-wrapped key material.
  std::string key_metadata;
  /// Dot-separated Parquet column path (e.g. "address.zip").
  std::string column_path;
  /// Physical type of the column.
  parquet::Type::type data_type = parquet::Type::BYTE_ARRAY;
  /// Compression codec applied to the page before encryption (or after decryption).
  ::arrow::Compression::type compression_type = ::arrow::Compression::UNCOMPRESSED;
  /// Byte width for FIXED_LEN_BYTE_ARRAY columns; nullopt for all other types.
  std::optional<int> datatype_length;
  /// Column-level key/value metadata from the file footer. Null on the write path.
  std::shared_ptr<const ::arrow::KeyValueMetadata> key_value_metadata;
  /// ABI version — increment when new fields are appended to this struct.
  uint32_t abi_version = 1;
};

/// Pure-virtual factory interface for external column encryption.
///
/// Implement this interface to replace the built-in AES encryptor with a
/// third-party key-management or HSM-backed encryptor.
///
/// Thread safety: GetColumnEncryptor() must be thread-safe. Parquet may call it
/// concurrently for different columns during parallel row-group writes.
class PARQUET_EXPORT ExternalEncryptorProvider {
 public:
  virtual ~ExternalEncryptorProvider() = default;

  /// Return an encryptor for the given column.
  ///
  /// Called once per column per row-group write. The returned object is used for
  /// all pages of the column in that row group.
  ///
  /// \param params Column path, key identifier, and schema metadata.
  /// \return Caller-owned encryptor for this column.
  virtual std::unique_ptr<encryption::EncryptorInterface> GetColumnEncryptor(
      const ColumnEncryptionParams& params) = 0;
};

}  // namespace parquet
