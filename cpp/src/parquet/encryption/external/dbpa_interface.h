//TODO: figure out the licensing.

#pragma once

#include <memory>
#include "parquet/platform.h"
#include "arrow/util/span.h"

using ::arrow::util::span;

namespace parquet::encryption::external {

    //TODO: this will change once we have a solid defition of interfaces 

    class EncryptionResult {
    };

    class DecryptionResult {
    };

    class PARQUET_EXPORT DataBatchProtectionAgentInterface {
        public:
         virtual std::unique_ptr<EncryptionResult> Encrypt(
            span<const uint8_t> plaintext, 
            span<uint8_t> ciphertext) = 0;

        virtual std::unique_ptr<DecryptionResult> Decrypt(
            span<const uint8_t> ciphertext) = 0;

        virtual ~DataBatchProtectionAgentInterface() = default;
    };
}
