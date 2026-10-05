#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Replay against the repository's pinned Wasefire revision without resetting files.
set -euo pipefail
cd "$(dirname "$0")/.."
PATCH="$PWD/tools/patches/wasefire-cc310.patch"
WASEFIRE=third_party/wasefire
BASE=6d8f4fc9714004af9d86b4218da0ce6d52db84f4
if [[ "$(git -C "$WASEFIRE" rev-parse HEAD)" != "$BASE" ]]; then
  echo "Error: CC310 patch requires Wasefire revision $BASE" >&2
  exit 1
fi
if git -C "$WASEFIRE" apply --reverse --check "$PATCH" 2>/dev/null; then
  echo "CC310 patch is already applied"
  exit 0
fi
git -C "$WASEFIRE" apply --check "$PATCH"
git -C "$WASEFIRE" apply "$PATCH"
echo "CC310 patch applied"
