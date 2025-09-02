//TODO: figure out the licensing.

#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include "span.hpp"
#include "enums.h"

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

// TODO: this file was copied from
// https://github.com/protegrity/DataBatchProtectionService
// we need to find a better way to share it between repos.
// https://github.com/protegrity/arrow/issues/110

namespace dbps::external {

template <typename T>
using span = tcb::span<T>;

/*
 * DataBatchProtectionAgentInterface, EncryptionResult and DecryptionResult implementation contracts:
 * - While handle to EncryptionResult/DecryptionResult exists, ciphertext()/plaintext() is guaranteed to return valid data
 * - Read operations are not destructive. Multiple calls return the same data
 * - Destructor must dispose of internal memory (either by delegation or cleanup)
 * - No throwing exceptions. Errors reported via success() flag and error methods.
 * - Library users must check size() to ensure the actual size of the returned payload.
 */

class DBPS_EXPORT EncryptionResult {
public:
    virtual span<const uint8_t> ciphertext() const = 0;

    // Allows a larger backing buffer than the exact ciphertext size.
    // Library users must check size() to ensure the actual size of the returned payload.
    virtual std::size_t size() const = 0;

    // Success flag; false indicates an error.
    virtual bool success() const = 0;

    // Error details (valid when success() == false).
    virtual const std::string& error_message() const = 0;
    virtual const std::map<std::string, std::string>& error_fields() const = 0;

    virtual ~EncryptionResult() = default;
};

class DBPS_EXPORT DecryptionResult {
public:
    virtual span<const uint8_t> plaintext() const = 0;

    // Allows a larger backing buffer than the exact plaintext size.
    // Library users must check size() to ensure the actual size of the returned payload.
    virtual std::size_t size() const = 0;

    // Success flag; false indicates an error.
    virtual bool success() const = 0;

    // Error details (valid when success() == false).
    virtual const std::string& error_message() const = 0;
    virtual const std::map<std::string, std::string>& error_fields() const = 0;

    virtual ~DecryptionResult() = default;
};

class DBPS_EXPORT DataBatchProtectionAgentInterface {
public:
    DataBatchProtectionAgentInterface() = default;

    // user_id is not stored as a member; it is expected to be embedded into app_context
    // (e.g., as a serialized map/JSON field).
    virtual void init(
        std::string column_name,
        std::map<std::string, std::string> connection_config,
        std::string app_context,
        std::string column_key_id,
        Type::type data_type,
        CompressionCodec::type compression_type)
    {
        column_name_ = std::move(column_name);
        connection_config_ = std::move(connection_config);
        app_context_ = std::move(app_context);
        column_key_id_ = std::move(column_key_id);
        data_type_ = data_type;
        compression_type_ = compression_type;
    }

    virtual std::unique_ptr<EncryptionResult> Encrypt(
        span<const uint8_t> plaintext) = 0;

    virtual std::unique_ptr<DecryptionResult> Decrypt(
        span<const uint8_t> ciphertext) = 0;

    virtual ~DataBatchProtectionAgentInterface() = default;

private:
    std::string column_name_;
    std::map<std::string, std::string> connection_config_;
    std::string app_context_;  // includes user_id

    std::string column_key_id_;
    Type::type data_type_;
    CompressionCodec::type compression_type_;
};
}
