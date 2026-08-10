&lt;!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Parquet Modular Encryption

Parquet Modular Encryption (PME) encrypts individual columns and the file footer
independently using AES-GCM or AES-CTR. Each column can use a different key.

The encryption layer is pluggable: you can replace the built-in AES path with
any external key-management system, HSM, or encryption service by implementing
`ExternalEncryptorProvider` and `ExternalDecryptorProvider`.

---

## When to use the external provider

Use the built-in AES path (`FileEncryptionProperties::Builder` with `.key()`) when:
- You can supply raw AES-128/192/256 keys at write time
- You want standard Parquet format compatibility (AES_GCM_V1, AES_GCM_CTR_V1)

Use `ExternalEncryptorProvider` when:
- The encryption implementation is provided as a **shared library** that Arrow
  loads at link time — the library internally handles key retrieval from a secure
  appliance, HSM, or key server; Arrow never sees the key material
- Your encryptor produces **variable-length ciphertext** (e.g. adds an IV prefix or
  authentication tag with non-standard overhead)
- You need **key-management lifecycle control** — key rotation, access auditing,
  or policy enforcement — performed by the vendor crypto library per column page

For KMS-style encryption where Arrow can hold a wrapped DEK in memory, the existing
`CryptoFactory` + `KmsClient` path (standard AES) is simpler and fully interoperable
with other PME readers.

---

## Built-in AES encryption

The standard path uses raw AES keys provided at write time:

```cpp
#include "parquet/encryption/encryption.h"
#include "parquet/file_writer.h"

// 16-, 24-, or 32-byte AES keys
arrow::util::SecureString footer_key("0123456789012345");
arrow::util::SecureString col_key("1234567890123456");

parquet::ColumnPathToEncryptionPropertiesMap cols;
cols["my_column"] = parquet::ColumnEncryptionProperties::Builder("my_column")
    .key(col_key)
    ->build();

auto enc_props = parquet::FileEncryptionProperties::Builder(footer_key)
    .encrypted_columns(cols)
    ->build();

auto writer_props = parquet::WriterProperties::Builder()
    .encryption(std::move(enc_props))
    ->build();

auto writer = parquet::ParquetFileWriter::Open(sink, schema, writer_props);
```

For decryption, supply the matching keys via `FileDecryptionProperties`.

---

## External encryption provider

To use an HSM, KMS, or any other external encryptor, implement
`ExternalEncryptorProvider` and `ExternalDecryptorProvider` and inject them
into the properties builders. Arrow calls the provider once per column per page;
the AES path is unaffected for columns that do not use `EXTERNAL_DBPA_V1`.

### Interface

```cpp
// parquet/encryption/external_encryptor_provider.h

struct PARQUET_EXPORT ColumnEncryptionParams {
  std::string key_metadata;    // opaque key identifier (not raw key bytes)
  std::string column_path;     // dot-separated column path, e.g. "address.zip"
  parquet::Type::type data_type = parquet::Type::BYTE_ARRAY;  // physical type
  arrow::Compression::type compression_type =
      arrow::Compression::UNCOMPRESSED;    // codec applied before encryption
  std::optional<int> datatype_length;      // byte width for FIXED_LEN_BYTE_ARRAY
  std::shared_ptr<const arrow::KeyValueMetadata> key_value_metadata;  // read path only
  uint32_t abi_version = 1;                // forward-compat guard
};

class PARQUET_EXPORT ExternalEncryptorProvider {
 public:
  virtual ~ExternalEncryptorProvider() = default;

  /// Return an encryptor for the given column.
  ///
  /// Called once per column per row-group write. The returned object is used
  /// for all pages of that column in the row group and must be thread-safe
  /// for concurrent calls across different columns.
  virtual std::unique_ptr<encryption::EncryptorInterface> GetColumnEncryptor(
      const ColumnEncryptionParams& params) = 0;
};
```

```cpp
// parquet/encryption/external_decryptor_provider.h

class PARQUET_EXPORT ExternalDecryptorProvider {
 public:
  virtual ~ExternalDecryptorProvider() = default;

  /// Return a decryptor for the given column.
  ///
  /// Called once per column per row-group read. The returned object handles
  /// all pages of that column in the row group.
  virtual std::unique_ptr<encryption::DecryptorInterface> GetColumnDecryptor(
      const ColumnEncryptionParams& params) = 0;
};
```

The returned `EncryptorInterface` / `DecryptorInterface` objects implement:

```cpp
// parquet/encryption/encryptor_interface.h
class PARQUET_EXPORT EncryptorInterface {
 public:
  /// If true, Arrow pre-allocates CiphertextLength() bytes and calls Encrypt().
  /// If false, Arrow calls EncryptWithManagedBuffer() with a ResizableBuffer
  /// and passes EncodingProperties containing page_type, physical_type, codec.
  [[nodiscard]] virtual bool CanCalculateCiphertextLength() const = 0;
  [[nodiscard]] virtual int32_t CiphertextLength(int64_t plaintext_len) const = 0;
  virtual int32_t Encrypt(std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> key,
                          std::span<const uint8_t> aad,
                          std::span<uint8_t> ciphertext,
                          std::unique_ptr<EncodingProperties>) = 0;
  virtual int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t> plaintext,
      arrow::ResizableBuffer* ciphertext,
      std::unique_ptr<EncodingProperties>) = 0;
};
```

### Writing with an external provider

```cpp
#include "parquet/encryption/encryption.h"
#include "parquet/encryption/external_encryptor_provider.h"
#include "parquet/encryption/encryptor_interface.h"

// Per-column encryptor: holds key context, performs actual encryption.
class MyColumnEncryptor : public parquet::encryption::EncryptorInterface {
 public:
  explicit MyColumnEncryptor(const parquet::ColumnEncryptionParams& params)
      : key_metadata_(params.key_metadata) {}

  bool CanCalculateCiphertextLength() const override { return true; }
  int32_t CiphertextLength(int64_t n) const override {
    return static_cast<int32_t>(n) + kms_.OverheadBytes();
  }
  int32_t Encrypt(std::span<const uint8_t> plaintext,
                  std::span<const uint8_t> /*key*/,
                  std::span<const uint8_t> /*aad*/,
                  std::span<uint8_t> ciphertext,
                  std::unique_ptr<parquet::encryption::EncodingProperties>) override {
    // External providers use their own key material; ignore key and aad.
    auto key = kms_.FetchKey(key_metadata_);
    return kms_.Encrypt(key, plaintext, ciphertext);
  }
  int32_t EncryptWithManagedBuffer(
      std::span<const uint8_t>, arrow::ResizableBuffer*,
      std::unique_ptr<parquet::encryption::EncodingProperties>) override {
    throw parquet::ParquetException("variable-length output not supported");
  }
  int32_t SignedFooterEncrypt(std::span<const uint8_t>, std::span<const uint8_t>,
                               std::span<const uint8_t>, std::span<const uint8_t>,
                               std::span<uint8_t>) override {
    throw parquet::ParquetException("footer signing not supported");
  }

 private:
  std::string key_metadata_;
  MyKmsClient kms_;
};

// Provider factory: GetColumnEncryptor() is called once per column.
class MyEncryptorProvider : public parquet::ExternalEncryptorProvider {
 public:
  std::unique_ptr<parquet::encryption::EncryptorInterface> GetColumnEncryptor(
      const parquet::ColumnEncryptionParams& params) override {
    return std::make_unique<MyColumnEncryptor>(params);
  }
};

// Wire into Arrow:
parquet::ColumnPathToEncryptionPropertiesMap cols;
cols["ssn"] = parquet::ColumnEncryptionProperties::Builder("ssn")
    .key(col_aes_key)           // AES key for column metadata (statistics, min/max)
    .key_metadata("my-key-id")  // forwarded to GetColumnEncryptor() as params.key_metadata
    ->parquet_cipher(parquet::ParquetCipher::EXTERNAL_DBPA_V1)
    ->build();

auto enc_props = parquet::FileEncryptionProperties::Builder(footer_key)
    .external_encryptor_provider(std::make_shared<MyEncryptorProvider>())
    ->encrypted_columns(cols)
    ->build();
```

> **Note:** `key()` sets the AES key used for column *metadata* (statistics,
> min/max values). Column *data pages* go through the `EncryptorInterface`
> returned by `GetColumnEncryptor()`. Both are required when using `EXTERNAL_DBPA_V1`.

### Reading with an external provider

```cpp
#include "parquet/encryption/external_decryptor_provider.h"
#include "parquet/encryption/decryptor_interface.h"

class MyColumnDecryptor : public parquet::encryption::DecryptorInterface {
 public:
  explicit MyColumnDecryptor(const parquet::ColumnEncryptionParams& params)
      : key_metadata_(params.key_metadata) {}

  bool CanCalculateLengths() const override { return true; }
  int32_t PlaintextLength(int32_t n) const override {
    return n - kms_.OverheadBytes();
  }
  int32_t CiphertextLength(int32_t n) const override {
    return n + kms_.OverheadBytes();
  }
  int32_t Decrypt(std::span<const uint8_t> ciphertext,
                  std::span<const uint8_t> /*key*/,
                  std::span<const uint8_t> /*aad*/,
                  std::span<uint8_t> plaintext,
                  std::unique_ptr<parquet::encryption::EncodingProperties>) override {
    auto key = kms_.FetchKey(key_metadata_);
    return kms_.Decrypt(key, ciphertext, plaintext);
  }
  int32_t DecryptWithManagedBuffer(
      std::span<const uint8_t>, arrow::ResizableBuffer*,
      std::unique_ptr<parquet::encryption::EncodingProperties>) override {
    throw parquet::ParquetException("variable-length output not supported");
  }

 private:
  std::string key_metadata_;
  MyKmsClient kms_;
};

class MyDecryptorProvider : public parquet::ExternalDecryptorProvider {
 public:
  std::unique_ptr<parquet::encryption::DecryptorInterface> GetColumnDecryptor(
      const parquet::ColumnEncryptionParams& params) override {
    return std::make_unique<MyColumnDecryptor>(params);
  }
};

// Wire into Arrow:
parquet::ColumnPathToDecryptionPropertiesMap dec_cols;
dec_cols["ssn"] = parquet::ColumnDecryptionProperties::Builder("ssn")
    .key(col_aes_key)
    ->build();

auto dec_props = parquet::FileDecryptionProperties::Builder()
    .footer_key(footer_key)
    ->column_keys(dec_cols)
    ->external_decryptor_provider(std::make_shared<MyDecryptorProvider>())
    ->build();
```

### Fallback behaviour

If no external provider is set (`nullptr`, the default), Arrow uses the
built-in AES path unchanged. Columns configured with `AES_GCM_V1` or
`AES_GCM_CTR_V1` never go through the external provider even if one is set.

### AAD (Additional Authenticated Data) behaviour

Arrow maintains a file-level `aad_prefix` that is incorporated into the
authentication tag used for footer and column metadata (statistics, min/max).
This prefix is verified on the read path and is independent of the external
provider — it continues to work correctly when a provider is set.

Per-page AAD (`module_aad` — encodes row-group index and page type) is used
by the built-in AES path for replay protection but is **not forwarded to
`ExternalEncryptorProvider::Encrypt()`**. External provider implementations
that require per-page authentication must derive equivalent context from
`params.column_path` and manage their own authentication tag.

---

## Thread safety

`GetColumnEncryptor()` and `GetColumnDecryptor()` must be safe for concurrent
calls with **different `params.column_path` values**. Arrow may call them
simultaneously for column C1 and column C2 from separate encoding threads
within the same file.

The returned `EncryptorInterface` / `DecryptorInterface` instances are
col’umn-private — Arrow never shares one instance across threads, so per-column
state in those objects requires no additional synchronisation.

Provider lifetime is managed via `shared_ptr`, whose reference count is updated
atomically. No explicit lock is required for lifetime management.

---

## Building with encryption

```bash
cmake -GNinja \
      -DARROW_PARQUET=ON \
      -DPARQUET_REQUIRE_ENCRYPTION=ON \
      -DARROW_BUILD_TESTS=ON \
      -DARROW_TESTING=ON \
      ..
ninja parquet
```

To build *without* OpenSSL (encryption API present but AES path stubbed):

```bash
cmake -GNinja \
      -DARROW_PARQUET=ON \
      -DPARQUET_REQUIRE_ENCRYPTION=OFF \
      ..
ninja parquet
```

---

## Running the tests

```bash
# All Parquet tests
ctest --test-dir build -L parquet --output-on-failure

# External provider tests only (33 tests)
ctest --test-dir build -R parquet-external-provider-test --output-on-failure
```

The `parquet-external-provider-test` binary uses in-tree XOR mock providers
(`MockEncryptorProvider`, `MockDecryptorProvider`) and covers:

- Provider factory call (`GetColumnEncryptor` / `GetColumnDecryptor`) and round-trip correctness
- Null provider fallback to AES
- Provider lifetime (`shared_ptr` ownership safety)
- Multi-column and mixed AES + external in the same file
- All `ColumnEncryptionParams` fields: `key_metadata`, `column_path`, `data_type`,
  `compression_type`, `datatype_length`, `key_value_metadata`
- `EncryptWithManagedBuffer` path (`CanCalculateCiphertextLength() = false`)
- Ciphertext overhead (`CiphertextLength` non-zero)
- Compression + external encryption ordering (Snappy, LZ4)
- AAD prefix with external providers
- `FIXED_LEN_BYTE_ARRAY`, dictionary-encoded, and DataPage V2 columns
- Concurrent writes with a shared provider instance
- Provider exception propagation
