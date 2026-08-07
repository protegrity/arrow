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
#include <string>

#include "parquet/platform.h"

namespace parquet {

/// Parameters passed to an external encryptor for a single column.
/// key_metadata is an opaque key identifier (not key material) used by the
/// provider's key management system to look up the actual encryption key.
struct PARQUET_EXPORT ColumnEncryptionParams {
  /// Opaque key identifier set via ColumnEncryptionProperties::Builder::key_metadata().
  /// The provider uses this to look up the actual encryption key — it is NOT
  /// KMS-wrapped key material and NOT raw key bytes.
  std::string key_metadata;
  /// Dot-separated Parquet column path (e.g. "address.zip").
  std::string column_path;
};

/// Pure-virtual interface for plugging an external encryption provider into
/// Parquet column encryption. Implement this interface to replace the built-in
/// AES encryptor with a third-party key-management or HSM-backed encryptor.
///
/// Thread safety: implementations must be thread-safe. Arrow may call Encrypt()
/// concurrently for different columns during parallel row-group writes.
class PARQUET_EXPORT ExternalEncryptorProvider {
 public:
  virtual ~ExternalEncryptorProvider() = default;

  /// Encrypt \p plaintext using the key identified by \p params.key_metadata.
  /// \p ciphertext must be at least CiphertextLength(plaintext.size()) bytes.
  /// Returns the number of bytes written to \p ciphertext.
  virtual int32_t Encrypt(const ColumnEncryptionParams& params,
                          std::span<const uint8_t> plaintext,
                          std::span<uint8_t> ciphertext) = 0;

  /// Returns the maximum ciphertext size in bytes for the given plaintext length.
  virtual int32_t CiphertextLength(int64_t plaintext_length) const = 0;
};

}  // namespace parquet
