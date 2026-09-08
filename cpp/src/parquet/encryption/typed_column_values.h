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
#include <vector>

#include "parquet/encryption/parquet_crypto_provider.h"
#include "parquet/platform.h"
#include "parquet/types.h"

namespace parquet {

/// Per-page container of decoded column values plus the definition/repetition
/// level bookkeeping needed to re-encode the page.
///
/// Produced and consumed by the page decoder that implements the cell path
/// (decompress + decode a page into `values()`, hand it to
/// ParquetCryptoProvider::EncryptCells()/DecryptCells(), then re-encode from
/// the transformed values). `values()` holds one CryptoValueBuffer for the
/// whole page's non-null entries, in row order; definition_levels()/
/// repetition_levels() cover every logical value in the page, nulls included,
/// and are unchanged by the vendor.
class PARQUET_EXPORT TypedColumnValues {
 public:
  TypedColumnValues(Type::type physical_type, int16_t max_definition_level,
                    int16_t max_repetition_level)
      : physical_type_(physical_type),
        max_definition_level_(max_definition_level),
        max_repetition_level_(max_repetition_level) {}

  /// Non-null decoded values for this page, in row order. Providers operate
  /// on this in place via ParquetCryptoProvider::EncryptCells()/DecryptCells().
  CryptoValueBuffer& values() { return values_; }
  [[nodiscard]] const CryptoValueBuffer& values() const { return values_; }

  /// Physical type shared by every element of values().
  [[nodiscard]] Type::type physical_type() const { return physical_type_; }

  /// Definition levels for every logical value in the page, nulls included.
  std::vector<int16_t>& definition_levels() { return definition_levels_; }
  [[nodiscard]] const std::vector<int16_t>& definition_levels() const {
    return definition_levels_;
  }

  /// Repetition levels for every logical value in the page; empty for
  /// non-repeated (non-list) columns.
  std::vector<int16_t>& repetition_levels() { return repetition_levels_; }
  [[nodiscard]] const std::vector<int16_t>& repetition_levels() const {
    return repetition_levels_;
  }

  [[nodiscard]] int16_t max_definition_level() const { return max_definition_level_; }
  [[nodiscard]] int16_t max_repetition_level() const { return max_repetition_level_; }

  /// Total logical value count for the page, including nulls.
  [[nodiscard]] int64_t num_values() const {
    return static_cast<int64_t>(definition_levels_.size());
  }

 private:
  Type::type physical_type_;
  int16_t max_definition_level_;
  int16_t max_repetition_level_;
  CryptoValueBuffer values_;
  std::vector<int16_t> definition_levels_;
  std::vector<int16_t> repetition_levels_;
};

}  // namespace parquet
