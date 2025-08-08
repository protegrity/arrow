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
#include <functional>

#include "gtest/gtest.h"
#include "parquet/encryption/external/dbpa_interface.h"
#include "parquet/encryption/external/dbpa_library_wrapper.h"
#include "arrow/util/span.h"
#include "parquet/test_util.h"

using ::arrow::util::span;

namespace parquet::encryption::external::test {

// Companion object to track the order of destruction events
class DestructionOrderTracker {
 public:
  DestructionOrderTracker() : sequence_counter_(0) {}
  
  // Record an event with a sequence number
  void RecordEvent(const std::string& event_name) {
    events_.emplace_back(event_name, ++sequence_counter_);
  }
  
  // Get the sequence number for a specific event
  int GetEventSequence(const std::string& event_name) const {
    for (const auto& event : events_) {
      if (event.first == event_name) {
        return event.second;
      }
    }
    return -1; // Event not found
  }
  
  // Verify that first_event occurred before second_event
  bool VerifyOrder(const std::string& first_event, const std::string& second_event) const {
    int first_seq = GetEventSequence(first_event);
    int second_seq = GetEventSequence(second_event);
    
    if (first_seq == -1 || second_seq == -1) {
      return false; // One or both events not recorded
    }
    
    return first_seq < second_seq;
  }
  
  // Get all recorded events in order
  const std::vector<std::pair<std::string, int>>& GetEvents() const {
    return events_;
  }
  
  // Clear all recorded events
  void Clear() {
    events_.clear();
    sequence_counter_ = 0;
  }
  
  // Check if an event was recorded
  bool WasEventRecorded(const std::string& event_name) const {
    return GetEventSequence(event_name) != -1;
  }

 private:
  std::vector<std::pair<std::string, int>> events_;
  int sequence_counter_;
}; //DestructionOrderTracker

// Companion object to hold mock state that persists after mock instance destruction
class MockCompanionDBPA {
 public:
  MockCompanionDBPA(std::shared_ptr<DestructionOrderTracker> order_tracker = nullptr) 
      : encrypt_called_(false), 
        decrypt_called_(false),
        destructor_called_(false),
        encrypt_count_(0),
        decrypt_count_(0),
        order_tracker_(order_tracker ? order_tracker : std::make_shared<DestructionOrderTracker>()) {}
  
  // Test helper methods
  bool WasEncryptCalled() const { return encrypt_called_; }
  bool WasDecryptCalled() const { return decrypt_called_; }
  bool WasDestructorCalled() const { return destructor_called_; }
  int GetEncryptCount() const { return encrypt_count_; }
  int GetDecryptCount() const { return decrypt_count_; }
  const std::vector<uint8_t>& GetEncryptPlaintext() const { return encrypt_plaintext_; }
  const std::vector<uint8_t>& GetDecryptCiphertext() const { return decrypt_ciphertext_; }
  size_t GetEncryptCiphertextSize() const { return encrypt_ciphertext_size_; }
  std::shared_ptr<DestructionOrderTracker> GetOrderTracker() const { return order_tracker_; }

  // State update methods (called by the mock instance)
  void SetEncryptCalled(bool called) { encrypt_called_ = called; }
  void SetDecryptCalled(bool called) { decrypt_called_ = called; }
  void SetDestructorCalled(bool called) { 
    destructor_called_ = called; 
    if (called) {
      order_tracker_->RecordEvent("agent_destructor");
    }
  }
  void IncrementEncryptCount() { encrypt_count_++; }
  void IncrementDecryptCount() { decrypt_count_++; }
  void SetEncryptPlaintext(const std::vector<uint8_t>& plaintext) { encrypt_plaintext_ = plaintext; }
  void SetDecryptCiphertext(const std::vector<uint8_t>& ciphertext) { decrypt_ciphertext_ = ciphertext; }
  void SetEncryptCiphertextSize(size_t size) { encrypt_ciphertext_size_ = size; }

 private:
  bool encrypt_called_;
  bool decrypt_called_;
  bool destructor_called_;
  int encrypt_count_;
  int decrypt_count_;
  std::vector<uint8_t> encrypt_plaintext_;
  std::vector<uint8_t> decrypt_ciphertext_;
  size_t encrypt_ciphertext_size_;
  std::shared_ptr<DestructionOrderTracker> order_tracker_;
}; //MockCompanionDBPA

// Companion object to track shared library handle management operations
class SharedLibHandleManagementCompanion {
 public:
  SharedLibHandleManagementCompanion(std::shared_ptr<DestructionOrderTracker> order_tracker = nullptr) 
      : handle_close_called_(false), 
        handle_close_count_(0),
        last_closed_handle_(nullptr),
        order_tracker_(order_tracker ? order_tracker : std::make_shared<DestructionOrderTracker>()) {}
  
  // Test helper methods
  bool WasHandleCloseCalled() const { return handle_close_called_; }
  int GetHandleCloseCount() const { return handle_close_count_; }
  void* GetLastClosedHandle() const { return last_closed_handle_; }
  std::shared_ptr<DestructionOrderTracker> GetOrderTracker() const { return order_tracker_; }
  
  // State update methods
  void SetHandleCloseCalled(bool called) { handle_close_called_ = called; }
  void IncrementHandleCloseCount() { handle_close_count_++; }
  void SetLastClosedHandle(void* handle) { last_closed_handle_ = handle; }
  
  // Create a closure that captures this companion object
  // and returns a function that can be used to close the shared library handle
  std::function<void(void*)> CreateHandleClosingFunction() {
    return [this](void* library_handle) {
      this->SetHandleCloseCalled(true);
      this->IncrementHandleCloseCount();
      this->SetLastClosedHandle(library_handle);
      this->order_tracker_->RecordEvent("handle_close");
    };
  }

 private:
  bool handle_close_called_;
  int handle_close_count_;
  void* last_closed_handle_;
  std::shared_ptr<DestructionOrderTracker> order_tracker_;
}; //SharedLibHandleManagementCompanion

// Mock implementation of DataBatchProtectionAgentInterface for testing delegation
class MockDataBatchProtectionAgent : public DataBatchProtectionAgentInterface {
 public:
  explicit MockDataBatchProtectionAgent(std::shared_ptr<MockCompanionDBPA> companion = nullptr) 
      : companion_(companion ? companion : std::make_shared<MockCompanionDBPA>()) {}
  
  ~MockDataBatchProtectionAgent() override {
    companion_->SetDestructorCalled(true);
  }
  
  std::unique_ptr<EncryptionResult> Encrypt(
      span<const uint8_t> plaintext, 
      span<uint8_t> ciphertext) override {
    companion_->SetEncryptCalled(true);
    companion_->IncrementEncryptCount();
    companion_->SetEncryptPlaintext(std::vector<uint8_t>(plaintext.begin(), plaintext.end()));
    companion_->SetEncryptCiphertextSize(ciphertext.size());
    
    // Simple mock encryption: just copy plaintext to ciphertext
    if (ciphertext.size() >= plaintext.size()) {
      std::copy(plaintext.begin(), plaintext.end(), ciphertext.begin());
    }
    
    return std::make_unique<EncryptionResult>();
  }

  std::unique_ptr<DecryptionResult> Decrypt(
      span<const uint8_t> ciphertext) override {
    companion_->SetDecryptCalled(true);
    companion_->IncrementDecryptCount();
    companion_->SetDecryptCiphertext(std::vector<uint8_t>(ciphertext.begin(), ciphertext.end()));
    
    return std::make_unique<DecryptionResult>();
  }

  // Getter for the companion object
  std::shared_ptr<MockCompanionDBPA> GetCompanion() const { return companion_; }

 private:
  std::shared_ptr<MockCompanionDBPA> companion_;
};

// Test fixture for DBPALibraryWrapper tests
class DBPALibraryWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create test data
    test_plaintext_ = "Hello, World!";
    test_ciphertext_.resize(test_plaintext_.size());
    
    // Create shared destruction order tracker
    destruction_order_tracker_ = std::make_shared<DestructionOrderTracker>();
    
    // Create companion objects with shared order tracker
    mock_companion_ = std::make_shared<MockCompanionDBPA>(destruction_order_tracker_);
    handle_companion_ = std::make_shared<SharedLibHandleManagementCompanion>(destruction_order_tracker_);
    
    // Create mock agent
    mock_agent_ = std::make_unique<MockDataBatchProtectionAgent>(mock_companion_);
    mock_agent_ptr_ = mock_agent_.get();
  }

  void TearDown() override {
    // mock_companion_ and handle_companion_ remain valid for assertions even after mock_agent_ is destroyed
    mock_agent_.reset();
  }

  // Helper method to create a wrapper with mock agent and handle management tracking
  std::unique_ptr<DBPALibraryWrapper> CreateWrapper() {
    return CreateWrapperWithAgent(std::move(mock_agent_));
  }

  // Helper method to create a wrapper with custom agent and handle management tracking
  std::unique_ptr<DBPALibraryWrapper> CreateWrapperWithAgent(
      std::unique_ptr<MockDataBatchProtectionAgent> agent) {
    void* dummy_handle = reinterpret_cast<void*>(0x12345678);
    
    // Use the existing handle companion from the test fixture
    return std::make_unique<DBPALibraryWrapper>(
        std::move(agent), dummy_handle, handle_companion_->CreateHandleClosingFunction());
  }

  // Helper method to create wrapper with custom handle closing function
  std::unique_ptr<DBPALibraryWrapper> CreateWrapperWithCustomClosing(
      std::function<void(void*)> handle_closing_fn) {
    void* dummy_handle = reinterpret_cast<void*>(0x12345678);
    
    return std::make_unique<DBPALibraryWrapper>(
        std::move(mock_agent_), dummy_handle, handle_closing_fn);
  }

  std::string test_plaintext_;
  std::vector<uint8_t> test_ciphertext_;
  std::shared_ptr<DestructionOrderTracker> destruction_order_tracker_;
  std::shared_ptr<MockCompanionDBPA> mock_companion_;
  std::shared_ptr<SharedLibHandleManagementCompanion> handle_companion_;
  std::unique_ptr<MockDataBatchProtectionAgent> mock_agent_;
  MockDataBatchProtectionAgent* mock_agent_ptr_;
};

// ============================================================================
// CONSTRUCTOR TESTS
// ============================================================================

TEST_F(DBPALibraryWrapperTest, ConstructorValidParameters) {
  auto mock_agent = std::make_unique<MockDataBatchProtectionAgent>();
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  EXPECT_NO_THROW({
    DBPALibraryWrapper wrapper(std::move(mock_agent), dummy_handle, handle_companion_->CreateHandleClosingFunction());
  });
}

TEST_F(DBPALibraryWrapperTest, ConstructorValidParametersWithDefaultClosing) {
  auto mock_agent = std::make_unique<MockDataBatchProtectionAgent>();
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  EXPECT_NO_THROW({
    DBPALibraryWrapper wrapper(std::move(mock_agent), dummy_handle, handle_companion_->CreateHandleClosingFunction());
  });
}

TEST_F(DBPALibraryWrapperTest, ConstructorNullAgent) {
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  // Test with custom function
  EXPECT_THROW({
    DBPALibraryWrapper wrapper(nullptr, dummy_handle, handle_companion_->CreateHandleClosingFunction());
  }, std::invalid_argument);
} 

TEST_F(DBPALibraryWrapperTest, ConstructorNullLibraryHandle) {
  auto mock_agent = std::make_unique<MockDataBatchProtectionAgent>();
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);

  // Test with custom function
  EXPECT_THROW({
    DBPALibraryWrapper wrapper(std::move(mock_agent), dummy_handle, nullptr);
  }, std::invalid_argument);
}

// ============================================================================
// HANDLE CLOSING FUNCTION TESTS
// ============================================================================

TEST_F(DBPALibraryWrapperTest, HandleClosingFunctionCalled) {
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  // Create wrapper in a scope to trigger destructor
  {
    auto wrapper = CreateWrapper();
    
    // Verify handle closing hasn't been called yet
    EXPECT_FALSE(handle_companion_->WasHandleCloseCalled());
    EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 0);
  }
  
  // After wrapper destruction, handle closing should have been called
  EXPECT_TRUE(handle_companion_->WasHandleCloseCalled());
  EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 1);
  EXPECT_EQ(handle_companion_->GetLastClosedHandle(), dummy_handle);
}

TEST_F(DBPALibraryWrapperTest, CustomHandleClosingFunction) {
  bool custom_function_called = false;
  void* custom_last_handle = nullptr;
  
  auto custom_closing_fn = [&custom_function_called, &custom_last_handle](void* handle) {
    custom_function_called = true;
    custom_last_handle = handle;
  };
  
  void* dummy_handle = reinterpret_cast<void*>(0x87654321);
  
  // Create wrapper with custom closing function
  {
    auto mock_agent = std::make_unique<MockDataBatchProtectionAgent>();
    DBPALibraryWrapper wrapper(std::move(mock_agent), dummy_handle, custom_closing_fn);
  }
  
  // Verify custom function was called
  EXPECT_TRUE(custom_function_called);
  EXPECT_EQ(custom_last_handle, dummy_handle);
  
  // Verify our handle companion wasn't called
  EXPECT_FALSE(handle_companion_->WasHandleCloseCalled());
  EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 0);
}

// ============================================================================
// DELEGATION FUNCTIONALITY TESTS
// ============================================================================

TEST_F(DBPALibraryWrapperTest, EncryptDelegation) {
  auto wrapper = CreateWrapper();
  
  // Convert test data to spans
  span<const uint8_t> plaintext_span(
      reinterpret_cast<const uint8_t*>(test_plaintext_.data()),
      test_plaintext_.size());
  span<uint8_t> ciphertext_span(test_ciphertext_.data(), test_ciphertext_.size());
  
  // Call encrypt through wrapper
  auto result = wrapper->Encrypt(plaintext_span, ciphertext_span);
  
  // Verify the mock agent was called
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  EXPECT_EQ(mock_companion_->GetEncryptCount(), 1);
  
  // Verify the correct plaintext was passed to the mock
  auto mock_plaintext = mock_companion_->GetEncryptPlaintext();
  std::string mock_plaintext_str(mock_plaintext.begin(), mock_plaintext.end());
  EXPECT_EQ(mock_plaintext_str, test_plaintext_);
  
  // Verify the correct ciphertext size was passed
  EXPECT_EQ(mock_companion_->GetEncryptCiphertextSize(), test_ciphertext_.size());
  
  // Verify result is not null
  EXPECT_NE(result, nullptr);
}

TEST_F(DBPALibraryWrapperTest, DecryptDelegation) {
  auto wrapper = CreateWrapper();
  
  // Convert test data to spans
  span<const uint8_t> ciphertext_span(
      reinterpret_cast<const uint8_t*>(test_plaintext_.data()),
      test_plaintext_.size());
  
  // Call decrypt through wrapper
  auto result = wrapper->Decrypt(ciphertext_span);
  
  // Verify the mock agent was called
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
  EXPECT_EQ(mock_companion_->GetDecryptCount(), 1);
  
  // Verify the correct ciphertext was passed to the mock
  auto mock_ciphertext = mock_companion_->GetDecryptCiphertext();
  std::string mock_ciphertext_str(mock_ciphertext.begin(), mock_ciphertext.end());
  EXPECT_EQ(mock_ciphertext_str, test_plaintext_);
  
  // Verify result is not null
  EXPECT_NE(result, nullptr);
}

TEST_F(DBPALibraryWrapperTest, MultipleEncryptDelegations) {
  auto wrapper = CreateWrapper();
  
  // Perform multiple encrypt operations
  for (int i = 0; i < 5; ++i) {
    std::string plaintext = "Test " + std::to_string(i);
    std::vector<uint8_t> ciphertext(plaintext.size());
    
    span<const uint8_t> plaintext_span(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size());
    span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());
    
    auto result = wrapper->Encrypt(plaintext_span, ciphertext_span);
    EXPECT_NE(result, nullptr);
  }
  
  // Verify the mock agent was called the correct number of times
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  EXPECT_EQ(mock_companion_->GetEncryptCount(), 5);
}

TEST_F(DBPALibraryWrapperTest, MultipleDecryptDelegations) {
  auto wrapper = CreateWrapper();
  
  // Perform multiple decrypt operations
  for (int i = 0; i < 3; ++i) {
    std::string ciphertext = "Test " + std::to_string(i);
    
    span<const uint8_t> ciphertext_span(
        reinterpret_cast<const uint8_t*>(ciphertext.data()),
        ciphertext.size());
    
    auto result = wrapper->Decrypt(ciphertext_span);
    EXPECT_NE(result, nullptr);
  }
  
  // Verify the mock agent was called the correct number of times
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
  EXPECT_EQ(mock_companion_->GetDecryptCount(), 3);
}

TEST_F(DBPALibraryWrapperTest, MixedOperationsDelegation) {
  auto wrapper = CreateWrapper();
  
  // Perform mixed encrypt and decrypt operations
  std::vector<std::string> test_data = {"Hello", "World", "Test", "Data"};
  int call_count = test_data.size();
  
  for (const auto& data : test_data) {
    // Encrypt
    std::vector<uint8_t> ciphertext(data.size());
    span<const uint8_t> plaintext_span(
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size());
    span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());
    
    auto encrypt_result = wrapper->Encrypt(plaintext_span, ciphertext_span);
    EXPECT_NE(encrypt_result, nullptr);
    
    // Decrypt
    span<const uint8_t> decrypt_span(ciphertext.data(), ciphertext.size());
    auto decrypt_result = wrapper->Decrypt(decrypt_span);
    EXPECT_NE(decrypt_result, nullptr);
  }
  
  // Verify both operations were called
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
  EXPECT_EQ(mock_companion_->GetEncryptCount(), call_count);
  EXPECT_EQ(mock_companion_->GetDecryptCount(), call_count);
}

TEST_F(DBPALibraryWrapperTest, DelegationWithEmptyData) {
  auto wrapper = CreateWrapper();
  
  // Test encryption with empty data
  std::vector<uint8_t> empty_plaintext;
  std::vector<uint8_t> empty_ciphertext;
  
  span<const uint8_t> plaintext_span(empty_plaintext);
  span<uint8_t> ciphertext_span(empty_ciphertext);
  
  auto encrypt_result = wrapper->Encrypt(plaintext_span, ciphertext_span);
  EXPECT_NE(encrypt_result, nullptr);
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  
  // Test decryption with empty data
  span<const uint8_t> empty_ciphertext_span(empty_ciphertext);
  auto decrypt_result = wrapper->Decrypt(empty_ciphertext_span);
  EXPECT_NE(decrypt_result, nullptr);
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
}

//TODO: we need to revisit this once we have a solid defition of interfaces 
// and behavior whenever we have null data.
TEST_F(DBPALibraryWrapperTest, DelegationWithNullData) {
  auto wrapper = CreateWrapper();
  
  // Test encryption with null data pointers but valid spans
  // This tests that the wrapper properly delegates even with null data
  span<const uint8_t> null_plaintext_span(nullptr, size_t{0});
  span<uint8_t> null_ciphertext_span(nullptr, size_t{0});
  
  auto encrypt_result = wrapper->Encrypt(null_plaintext_span, null_ciphertext_span);
  EXPECT_NE(encrypt_result, nullptr);
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  
  // Test decryption with null data pointer but valid span
  span<const uint8_t> null_decrypt_span(nullptr, size_t{0});
  auto decrypt_result = wrapper->Decrypt(null_decrypt_span);
  EXPECT_NE(decrypt_result, nullptr);
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
  
  // Verify the mock agent received the correct data (empty vectors)
  auto mock_plaintext = mock_companion_->GetEncryptPlaintext();
  auto mock_ciphertext = mock_companion_->GetDecryptCiphertext();
  EXPECT_EQ(mock_plaintext.size(), 0);
  EXPECT_EQ(mock_ciphertext.size(), 0);
}

// ============================================================================
// DESTRUCTOR FUNCTIONALITY TESTS
// ============================================================================

TEST_F(DBPALibraryWrapperTest, DestructorBasicBehavior) {
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  // Create wrapper in a scope to test destructor
  {
    auto wrapper = CreateWrapper();
    
    // Perform some operations to ensure the wrapper is used
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    std::vector<uint8_t> ciphertext(plaintext.size());
    
    span<const uint8_t> plaintext_span(plaintext.data(), plaintext.size());
    span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());
    
    auto result = wrapper->Encrypt(plaintext_span, ciphertext_span);
    EXPECT_NE(result, nullptr);
    
    // Verify handle closing hasn't been called yet
    EXPECT_FALSE(handle_companion_->WasHandleCloseCalled());
    EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 0);
  }
  
  // At this point, the wrapper should have been destroyed and handle closed
  EXPECT_TRUE(handle_companion_->WasHandleCloseCalled());
  EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 1);
  EXPECT_EQ(handle_companion_->GetLastClosedHandle(), dummy_handle);
}

TEST_F(DBPALibraryWrapperTest, DestructorWithMultipleOperations) {
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  // Create wrapper in a scope to test destructor
  {
    auto wrapper = CreateWrapper();
    
    // Perform multiple operations
    for (int i = 0; i < 10; ++i) {
      std::string plaintext = "Test " + std::to_string(i);
      std::vector<uint8_t> ciphertext(plaintext.size());
      
      span<const uint8_t> plaintext_span(
          reinterpret_cast<const uint8_t*>(plaintext.data()),
          plaintext.size());
      span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());
      
      auto encrypt_result = wrapper->Encrypt(plaintext_span, ciphertext_span);
      EXPECT_NE(encrypt_result, nullptr);
      
      span<const uint8_t> ciphertext_span_const(ciphertext.data(), ciphertext.size());
      auto decrypt_result = wrapper->Decrypt(ciphertext_span_const);
      EXPECT_NE(decrypt_result, nullptr);
    }
    
    // Verify operations completed but handle not closed yet
    EXPECT_FALSE(handle_companion_->WasHandleCloseCalled());
  }

  // Verify the wrapper was destroyed properly and handle was closed
  EXPECT_TRUE(handle_companion_->WasHandleCloseCalled());
  EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 1);
  EXPECT_EQ(handle_companion_->GetLastClosedHandle(), dummy_handle);
}

TEST_F(DBPALibraryWrapperTest, DestructorOrderVerification) {
  // Clear any previous events from the shared order tracker
  destruction_order_tracker_->Clear();
  
  // Create a custom mock agent that tracks destruction order
      auto custom_companion = std::make_shared<MockCompanionDBPA>(destruction_order_tracker_);
  auto custom_agent = std::make_unique<MockDataBatchProtectionAgent>(custom_companion);
  
  void* dummy_handle = reinterpret_cast<void*>(0x12345678);
  
  // Create wrapper in a scope
  {
    auto wrapper = CreateWrapperWithAgent(std::move(custom_agent));
    
    // Perform some operations
    std::vector<uint8_t> plaintext = {1, 2, 3};
    std::vector<uint8_t> ciphertext(plaintext.size());
    
    span<const uint8_t> plaintext_span(plaintext.data(), plaintext.size());
    span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());
    
    auto result = wrapper->Encrypt(plaintext_span, ciphertext_span);
    EXPECT_NE(result, nullptr);
    
    // Verify neither destructor nor handle closing has been called yet
    EXPECT_FALSE(custom_companion->WasDestructorCalled());
    EXPECT_FALSE(handle_companion_->WasHandleCloseCalled());
    EXPECT_FALSE(destruction_order_tracker_->WasEventRecorded("handle_close"));
    EXPECT_FALSE(destruction_order_tracker_->WasEventRecorded("agent_destructor"));
  }
  
  // Verify both the custom agent was destroyed and handle was closed
  EXPECT_TRUE(custom_companion->WasDestructorCalled());
  EXPECT_TRUE(handle_companion_->WasHandleCloseCalled());
  EXPECT_EQ(handle_companion_->GetHandleCloseCount(), 1);
  EXPECT_EQ(handle_companion_->GetLastClosedHandle(), dummy_handle);
  
  // Verify the order of destruction: handle_close should be called BEFORE agent_destructor
  EXPECT_TRUE(destruction_order_tracker_->WasEventRecorded("agent_destructor"));
  EXPECT_TRUE(destruction_order_tracker_->WasEventRecorded("handle_close"));
  EXPECT_TRUE(destruction_order_tracker_->VerifyOrder("agent_destructor", "handle_close"));  
}

TEST_F(DBPALibraryWrapperTest, DestructionOrderTrackerFunctionality) {
  // Test the destruction order tracker functionality independently
  auto tracker = std::make_shared<DestructionOrderTracker>();
  
  // Record events in a specific order
  tracker->RecordEvent("first");
  tracker->RecordEvent("second");
  tracker->RecordEvent("third");
  
  // Verify order tracking
  EXPECT_TRUE(tracker->VerifyOrder("first", "second"));
  EXPECT_TRUE(tracker->VerifyOrder("second", "third"));
  EXPECT_TRUE(tracker->VerifyOrder("first", "third"));
  
  // Verify reverse order is false
  EXPECT_FALSE(tracker->VerifyOrder("second", "first"));
  EXPECT_FALSE(tracker->VerifyOrder("third", "second"));
  EXPECT_FALSE(tracker->VerifyOrder("third", "first"));
  
  // Verify sequence numbers
  EXPECT_EQ(tracker->GetEventSequence("first"), 1);
  EXPECT_EQ(tracker->GetEventSequence("second"), 2);
  EXPECT_EQ(tracker->GetEventSequence("third"), 3);
  
  // Verify event recording
  EXPECT_TRUE(tracker->WasEventRecorded("first"));
  EXPECT_TRUE(tracker->WasEventRecorded("second"));
  EXPECT_TRUE(tracker->WasEventRecorded("third"));
  EXPECT_FALSE(tracker->WasEventRecorded("nonexistent"));
}

// ============================================================================
// INTERFACE COMPLIANCE TESTS
// ============================================================================

TEST_F(DBPALibraryWrapperTest, InterfaceCompliancePolymorphic) {
  auto wrapper = CreateWrapper();
  
  // Verify the wrapper can be used polymorphically
  DataBatchProtectionAgentInterface* interface_ptr = wrapper.get();
  EXPECT_NE(interface_ptr, nullptr);
  
  // Test polymorphic calls
  std::vector<uint8_t> plaintext = {1, 2, 3};
  std::vector<uint8_t> ciphertext(plaintext.size());
  
  span<const uint8_t> plaintext_span(plaintext.data(), plaintext.size());
  span<uint8_t> ciphertext_span(ciphertext.data(), ciphertext.size());
  
  auto encrypt_result = interface_ptr->Encrypt(plaintext_span, ciphertext_span);
  EXPECT_NE(encrypt_result, nullptr);
  
  span<const uint8_t> ciphertext_span_const(ciphertext.data(), ciphertext.size());
  auto decrypt_result = interface_ptr->Decrypt(ciphertext_span_const);
  EXPECT_NE(decrypt_result, nullptr);
  
  // Verify the mock agent was called through the interface
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

TEST_F(DBPALibraryWrapperTest, EdgeCaseZeroSizeSpans) {
  auto wrapper = CreateWrapper();
  
  // Test with zero-size spans
  std::vector<uint8_t> empty_data;
  
  span<const uint8_t> empty_plaintext_span(empty_data);
  span<uint8_t> empty_ciphertext_span(empty_data);
  
  auto encrypt_result = wrapper->Encrypt(empty_plaintext_span, empty_ciphertext_span);
  EXPECT_NE(encrypt_result, nullptr);
  
  span<const uint8_t> empty_decrypt_span(empty_data);
  auto decrypt_result = wrapper->Decrypt(empty_decrypt_span);
  EXPECT_NE(decrypt_result, nullptr);
  
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
}

TEST_F(DBPALibraryWrapperTest, EdgeCaseSingleByteData) {
  auto wrapper = CreateWrapper();
  
  // Test with single byte data
  std::vector<uint8_t> single_byte = {0x42};
  std::vector<uint8_t> single_byte_ciphertext(1);
  
  span<const uint8_t> plaintext_span(single_byte.data(), single_byte.size());
  span<uint8_t> ciphertext_span(single_byte_ciphertext.data(), single_byte_ciphertext.size());
  
  auto encrypt_result = wrapper->Encrypt(plaintext_span, ciphertext_span);
  EXPECT_NE(encrypt_result, nullptr);
  
  span<const uint8_t> ciphertext_span_const(single_byte_ciphertext.data(), single_byte_ciphertext.size());
  auto decrypt_result = wrapper->Decrypt(ciphertext_span_const);
  EXPECT_NE(decrypt_result, nullptr);
  
  EXPECT_TRUE(mock_companion_->WasEncryptCalled());
  EXPECT_TRUE(mock_companion_->WasDecryptCalled());
}

}  // namespace parquet::encryption::external::test 