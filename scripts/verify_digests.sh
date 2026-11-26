#!/bin/sh
# Verify SHA-256 digests of every shipped file against SHA256SUMS.
# Usage: sh scripts/verify_digests.sh   (from the pack root)
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS
