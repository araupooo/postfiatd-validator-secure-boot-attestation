#!/bin/sh
# Run the full lab harness and preserve unedited outputs.
# Lab-only: pure Python 3 standard library, no network, no hardware,
# no package manager, no clone of any other repository.
# Usage: sh scripts/run_all.sh   (from the pack root)
set -eu
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
mkdir -p outputs
LOG="outputs/run_all.log"
: > "$LOG"
echo "validator secure-boot and attestation assessment harness" | tee -a "$LOG"
echo "run started (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$LOG"
echo "python: $(python3 --version 2>&1)" | tee -a "$LOG"
echo "pack root: $(pwd)" | tee -a "$LOG"
for script in inventory_check.py pcr_model.py quote_verify.py seal_model.py manifest_model.py coverage.py; do
  echo "=== $script ===" | tee -a "$LOG"
  python3 "scripts/harness/$script" 2>&1 | tee -a "$LOG"
done
echo "=== output digests (full SHA-256) ===" | tee -a "$LOG"
sha256sum outputs/*.json | tee -a "$LOG"
echo "=== harness complete ===" | tee -a "$LOG"
echo "run finished (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$LOG"
