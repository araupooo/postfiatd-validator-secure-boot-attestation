#!/bin/sh
# Fresh-clone reproduction check.
#
# Reproduces the pack from a fresh copy of the PACK REPOSITORY ALONE:
#   * copies this pack to a fresh temporary directory (excluding the
#     generated outputs/ and local-only files),
#   * re-runs the harness there with scripts/run_all.sh,
#   * verifies the regenerated outputs against the committed SHA256SUMS,
#   * compares every regenerated outputs/*.json byte-for-byte against the
#     committed outputs/*.json, and
#   * writes outputs/reproduction/COMPARISON.md with full SHA-256 values.
#
# It does NOT clone postfiatd, does NOT run Conan, and does NOT call any
# package manager. The pinned-source evidence it re-checks is vendored in
# evidence/ (verified against the pinned tree at build time). The only
# tools used are cp, sh, python3 (standard library only), sha256sum and
# diff. It needs no network access.
#
# Usage: sh scripts/clean_reproduce.sh   (from the pack root)
set -eu
PACK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "clean_reproduce: pack dir: $PACK_DIR"
echo "clean_reproduce: fresh copy at: $WORK/pack"

# Fresh copy: everything except generated outputs and local-only files.
cp -a "$PACK_DIR" "$WORK/pack"
rm -rf "$WORK/pack/outputs" "$WORK/pack/PROGRESS.md" "$WORK/pack/PACK-READY.md"

cd "$WORK/pack"
echo "clean_reproduce: re-running harness in fresh copy..."
sh scripts/run_all.sh > /tmp/clean_reproduce_run.log 2>&1 || {
  echo "clean_reproduce: run_all.sh FAILED in fresh copy; see /tmp/clean_reproduce_run.log"
  cat /tmp/clean_reproduce_run.log
  exit 1
}
echo "clean_reproduce: harness re-ran to completion in fresh copy."

echo "clean_reproduce: verifying digests of regenerated outputs..."
VERIFY_RESULT="PASS"
if sh scripts/verify_digests.sh > /tmp/clean_reproduce_verify.log 2>&1; then
  echo "clean_reproduce: verify_digests.sh PASS in fresh copy."
else
  VERIFY_RESULT="FAIL"
  echo "clean_reproduce: verify_digests.sh FAILED in fresh copy."
  cat /tmp/clean_reproduce_verify.log
fi

# Byte-for-byte comparison of every regenerated outputs/*.json.
mkdir -p "$PACK_DIR/outputs/reproduction"
COMP="$PACK_DIR/outputs/reproduction/COMPARISON.md"
{
  echo "# Fresh-clone reproduction comparison"
  echo ""
  echo "Reproduced from a fresh copy of the pack repository alone: the harness"
  echo "was re-run in a temporary directory with no access to the original"
  echo "outputs, no clone of any other repository, no Conan, and no package"
  echo "manager. Pinned-source evidence is vendored in evidence/."
  echo ""
  echo "- Python: $(python3 --version 2>&1)"
  echo "- System: $(uname -srm)"
  echo "- Fresh copy: temporary directory (removed after the run)"
  echo "- Digest verification in fresh copy: $VERIFY_RESULT"
  echo ""
  echo "| Output file | Committed SHA-256 | Reproduced SHA-256 | Result |"
  echo "|---|---|---|---|"
  MISMATCH=0
  for f in "$PACK_DIR"/outputs/*.json; do
    name="$(basename "$f")"
    committed="$(sha256sum "$f" | cut -d' ' -f1)"
    reproduced="$(sha256sum "$WORK/pack/outputs/$name" | cut -d' ' -f1)"
    if [ "$committed" = "$reproduced" ]; then
      result="MATCH"
    else
      result="MISMATCH"
      MISMATCH=1
    fi
    echo "| $name | $committed | $reproduced | $result |"
  done
  echo ""
  if [ "$MISMATCH" -eq 0 ] && [ "$VERIFY_RESULT" = "PASS" ]; then
    echo "Result: REPRODUCED. Every regenerated output is byte-identical to the committed output, and digest verification passes in the fresh copy."
  else
    echo "Result: NOT REPRODUCED. See the MISMATCH rows above and/or the digest verification failure."
  fi
} > "$COMP"
cat "$COMP"
if [ "$MISMATCH" -eq 1 ] || [ "$VERIFY_RESULT" != "PASS" ]; then
  exit 1
fi
echo "clean_reproduce: done. Comparison written to outputs/reproduction/COMPARISON.md"
