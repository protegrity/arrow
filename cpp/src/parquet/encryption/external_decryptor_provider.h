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

#include "parquet/encryption/external_encryptor_provider.h"
#include "parquet/platform.h"

namespace parquet::encryption {
class DecryptorInterface;
}  // namespace parquet::encryption

namespace parquet {

/// Pure-virtual factory interface for external column decryption.
///
/// Implement this interface to replace the built-in AES decryptor with a
/// third-party key-management or HSM-backed decryptor.
///
/// Thread safety: GetColumnDecryptor() must be thread-safe. Parquet may call it
/// concurrently for different columns during parallel row-group reads.
class PARQUET_EXPORT ExternalDecryptorProvider {
 public:
  virtual ~ExternalDecryptorProvider() = default;

  /// Return a decryptor for the given column.
  ///
  /// Called once per column per read sequence. The returned object is used for
  /// all pages of the column in that read.
  ///
  /// \param params Column path, key identifier, and footer metadata.
  /// \return Caller-owned decryptor for this column.
  virtual std::unique_ptr<encryption::DecryptorInterface> GetColumnDecryptor(
      const ColumnEncryptionParams& params) = 0;
};

}  // namespace parquet
