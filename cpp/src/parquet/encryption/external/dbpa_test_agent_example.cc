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

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "parquet/encryption/external/dbpa_test_agent.h"
#include "arrow/util/span.h"

using ::arrow::util::span;

int main() {
  std::cout << "DBPATestAgent Example" << std::endl;
  std::cout << "=====================" << std::endl;

  try {
    // Create an instance of DBPATestAgent
    auto agent = std::make_unique<parquet::encryption::external::DBPATestAgent>();
    std::cout << "Created DBPATestAgent instance" << std::endl;

    // Initialize the agent
    agent->init("example_agent", "test_configuration", true);
    std::cout << "Initialized DBPATestAgent" << std::endl;

    // Prepare test data
    std::string plaintext = "Hello, World! This is a test message.";
    std::vector<uint8_t> plaintext_data(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertext(plaintext_data.size());

    std::cout << "Original text: " << plaintext << std::endl;
    std::cout << "Data size: " << plaintext_data.size() << " bytes" << std::endl;

    // Create spans for the data
    span<const uint8_t> plaintext_span(plaintext_data.data(), plaintext_data.size());
    span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());

    // Encrypt the data
    std::cout << "Encrypting data..." << std::endl;
    auto encrypt_result = agent->Encrypt(plaintext_span, ciphertext_span);
    std::cout << "Encryption completed successfully" << std::endl;

    // Display encrypted data (first few bytes)
    std::cout << "Encrypted data (first 10 bytes): ";
    for (size_t i = 0; i < std::min(size_t(10), ciphertext.size()); ++i) {
      printf("%02X ", ciphertext[i]);
    }
    std::cout << std::endl;

    // Decrypt the data
    std::cout << "Decrypting data..." << std::endl;
    span<const uint8_t> ciphertext_span_const(ciphertext.data(), ciphertext.size());
    auto decrypt_result = agent->Decrypt(ciphertext_span_const);
    std::cout << "Decryption completed successfully" << std::endl;

    // Verify the encryption worked (XOR with 0xAA should change the data)
    bool data_changed = false;
    for (size_t i = 0; i < plaintext_data.size(); ++i) {
      if (ciphertext[i] != plaintext_data[i]) {
        data_changed = true;
        break;
      }
    }

    if (data_changed) {
      std::cout << "✓ Encryption verification: Data was successfully encrypted" << std::endl;
    } else {
      std::cout << "✗ Encryption verification: Data was not encrypted" << std::endl;
    }

    std::cout << "Example completed successfully!" << std::endl;

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
} 