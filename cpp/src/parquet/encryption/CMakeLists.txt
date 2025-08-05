# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Headers: public api
arrow_install_all_headers("parquet/encryption")

add_library(DLLEncryptor SHARED
   encryption_internal.cc
   openssl_internal.cc
   external/dll_encryptor.cc
)

add_library(DBPATestAgent SHARED
   external/dbpa_test_agent.cc
)

# target_include_directories(DLLEncryptor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#TODO marguedas: this needs review.
target_link_libraries(DLLEncryptor PUBLIC
  ${ARROW_OPENSSL_LIBS}
  arrow_shared
)

set_target_properties(DLLEncryptor PROPERTIES OUTPUT_NAME "DLLEncryptor")

# DBPATestAgent configuration
target_link_libraries(DBPATestAgent PUBLIC
  arrow_shared
)

set_target_properties(DBPATestAgent PROPERTIES OUTPUT_NAME "DBPATestAgent")

# Install the DLLEncryptor library
# install(TARGETS DLLEncryptor
#         EXPORT DLLEncryptor_targets
#         ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
#         LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#         RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#         INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
