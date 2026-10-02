#!/usr/bin/env bash
#
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
#
# Clones the Protegrity-internal nested repos (documents/, vendor/protegrity/)
# into a freshly checked-out Arrow working tree and excludes them locally so
# `git status`/`git add -A` in this repo never sees them.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

clone_nested_repo() {
  local path="$1" url="$2"
  if [[ -d "$path/.git" ]]; then
    echo "skip: $path already exists"
  else
    echo "cloning $url -> $path"
    git clone "$url" "$path"
  fi
  if ! grep -qxF "$path/" .git/info/exclude 2>/dev/null; then
    echo "$path/" >> .git/info/exclude
  fi
}

clone_nested_repo "documents" "https://source.protegrity.com/akil.raza/protegrity-docs.git"
clone_nested_repo "vendor/protegrity" "https://source.protegrity.com/arrow_vendor_code/vendor_crypto_provider.git"

echo "done"
