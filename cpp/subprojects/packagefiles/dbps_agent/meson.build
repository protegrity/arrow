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

project('dbps_agent', 'cpp')

# Expose the DBPS interface headers (dbpa_interface.h, enums.h, etc.).
# This subproject is intentionally header-only: Arrow's Meson build must not
# build DBPS agents or shared libraries.
dbps_interface_dep = declare_dependency(
    include_directories: include_directories('src/common'),
)

# Optional: allow `dependency('dbps_interface')` elsewhere if needed.
meson.override_dependency('dbps_interface', dbps_interface_dep)

