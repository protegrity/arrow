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

#include "parquet/encryption/external_encryptor_provider.h"
#include "parquet/platform.h"

namespace parquet {

/// Pure-virtual interface for plugging an external decryption provider into
/// Parquet column decryption. Implement this interface to replace the built-in
/// AES decryptor with a third-party key-management or HSM-backed decryptor.
///
/// Thread safety: implementations must be thread-safe. Arrow may call Decrypt()
/// concurrently for different columns during parallel row-group reads.
class PARQUET_EXPORT ExternalDecryptorProvider {
 public:
  virtual ~ExternalDecryptorProvider() = default;

  /// Decrypt \p ciphertext using the key identified by \p params.key_metadata.
  /// \p plaintext must be at least PlaintextLength(ciphertext.size()) bytes.
  /// Returns the number of bytes written to \p plaintext.
  virtual int32_t Decrypt(const ColumnEncryptionParams& params,
                          std::span<const uint8_t> ciphertext,
                          std::span<uint8_t> plaintext) = 0;

  /// Returns the maximum plaintext size in bytes for the given ciphertext length.
  virtual int32_t PlaintextLength(int32_t ciphertext_length) const = 0;
};

}  // namespace parquet
