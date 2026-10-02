#!/usr/bin/env bash
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
