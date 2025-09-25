//TODO: figure out the licensing.

#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <stdexcept>
#include "span.hpp"
#include "enums.h"

template <typename T>
using span = tcb::span<T>;

// TODO: this file was copied from
// https://github.com/protegrity/DataBatchProtectionService
// we need to find a better way to share it between repos.
// https://github.com/protegrity/arrow/issues/110

#ifndef DBPS_EXPORT
#define DBPS_EXPORT
#endif

class DBPS_EXPORT DBPSException : public std::runtime_error {
public:
    explicit DBPSException(const std::string& message) : std::runtime_error(message) {}
};

namespace dbps::external {

/*
 * DataBatchProtectionAgentInterface, EncryptionResult and DecryptionResult implementation contracts:
 * - While handle to EncryptionResult/DecryptionResult exists, ciphertext()/plaintext() is guaranteed to return valid data
 * - Read operations are not destructive. Multiple calls return the same data
 * - Destructor must dispose of internal memory (either by delegation or cleanup)
 * - Library users must check size() to ensure the actual size of the returned payload.
 * - Exceptions on init(): init() may throw DBPSException for initialization errors (e.g., invalid parameters, server connection failures)
 * - Exceptions on Encrypt() and Decrypt(): Encrypt/Decrypt do not throw exceptions. Errors reported via success() flag and error methods.
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
        Type::type datatype,
        std::optional<int> datatype_length,
        CompressionCodec::type compression_type)
    {
        column_name_ = std::move(column_name);
        connection_config_ = std::move(connection_config);
        app_context_ = std::move(app_context);
        column_key_id_ = std::move(column_key_id);
        datatype_ = datatype;
        datatype_length_ = datatype_length;
        compression_type_ = compression_type;
    }

    /*
    * Encrypts the provided plaintext data using the configured encryption parameters.
    *
    * @param plaintext Binary data to be encrypted, provided as a span of bytes
    * @param encoding_attributes A map of string key-values. The plaintext is encoded with a type defined in enums.h Format::type.
    *   Each encoding type requires additional attributes to be properly decoded. These attributes are specified in the map so an
    *   implementation can properly interpret and process the input text.
    *
    * @return A unique pointer to an EncryptionResult containing the encrypted data and operation status
    */
    virtual std::unique_ptr<EncryptionResult> Encrypt(
        span<const uint8_t> plaintext,
        std::map<std::string, std::string> encoding_attributes) = 0;

    virtual std::unique_ptr<DecryptionResult> Decrypt(
        span<const uint8_t> ciphertext,
        std::map<std::string, std::string> encoding_attributes) = 0;

    virtual ~DataBatchProtectionAgentInterface() = default;

protected:
    std::string column_name_;
    std::map<std::string, std::string> connection_config_;
    std::string app_context_;  // includes user_id

    std::string column_key_id_;
    Type::type datatype_;
    std::optional<int> datatype_length_;
    CompressionCodec::type compression_type_;
};
}
