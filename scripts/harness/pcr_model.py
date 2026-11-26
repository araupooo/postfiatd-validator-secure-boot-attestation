#!/usr/bin/env python3
"""SIMULATED measured-boot model for a PostFiat validator host.

Implements the TPM 2.0 PCR extend rule (TCG TPM 2.0 Library Part 1:
other than reset, the only way to change a PCR value is to Extend it):
    PCR_new = H_bank(PCR_old || digest)
and replays a boot event log for the validator boot chain, with PCR
assignments per the TCG PC Client Platform Firmware Profile v1.06 rev 52
(PCR 0 firmware code, PCR 1 platform config, PCR 2/3 pluggable code,
PCR 4 boot manager code, PCR 5 boot config/GPT, PCR 7 Secure Boot policy,
PCR 8-15 static OS).

No TPM hardware is present on this machine and no hardware measurement is
claimed: every value below is computed in software from fixed test vectors
and labelled SIMULATED. The model shows what a measured-boot chain WOULD
prove, and which failure modes it WOULD catch, if it existed on the
validator hosts — the pinned postfiatd tree contains no such mechanism
(see inventory_check.py, check ATT-01).

Deterministic: fixed test vectors, sorted keys, no timestamps.
"""

import hashlib
import json
import os
import sys

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "pcr_model.json")

ZERO32 = b"\x00" * 32


def extend(pcr_old, digest):
    return hashlib.sha256(pcr_old + digest).digest()


def event_digest(label):
    """Deterministic test-vector digest for a boot event."""
    return hashlib.sha256(("validator-boot-event:" + label).encode()).digest()


# Boot chain, stage -> (PCR index, event label). PCR assignment follows the
# TCG PC Client Platform Firmware Profile v1.06 rev 52.
BOOT_CHAIN = [
    ("firmware-crtm", 0, "CRTM core firmware image v1.0.9-build"),
    ("firmware-config", 1, "firmware configuration (Secure Boot enabled)"),
    ("option-rom", 2, "NIC option ROM"),
    ("boot-manager", 4, "shim + GRUB boot manager"),
    ("boot-config", 5, "GPT + boot configuration"),
    ("secure-boot-policy", 7, "db/dbx/KEK enrollment state"),
    ("kernel", 9, "Linux kernel 6.8 image"),
    ("initrd", 9, "initramfs image"),
    ("container-image", 10, "postfiatd container image digest"),
    ("postfiatd-binary", 10, "postfiatd binary 1.0.9"),
    ("validator-config", 10, "postfiatd.cfg + validators.txt"),
]


def replay(events):
    """Replay an ordered event list; return {pcr_index: value_hex}."""
    pcrs = {}
    for _stage, pcr, label in events:
        pcrs.setdefault(pcr, ZERO32)
        pcrs[pcr] = extend(pcrs[pcr], event_digest(label))
    return {i: v.hex() for i, v in sorted(pcrs.items())}


def main():
    golden = replay(BOOT_CHAIN)

    cases = []

    # Control: replaying the same log reproduces the golden PCRs exactly.
    replayed = replay(BOOT_CHAIN)
    cases.append({
        "id": "PCR-CONTROL",
        "description": "Replaying the identical boot event log reproduces the golden PCR values.",
        "expected": "match",
        "actual": "match" if replayed == golden else "MISMATCH",
        "passed": replayed == golden,
    })

    # Failure mode 1: one tampered event (modified firmware image).
    tampered = [
        (s, p, l + " [TAMPERED]" if s == "firmware-crtm" else l)
        for (s, p, l) in BOOT_CHAIN
    ]
    t = replay(tampered)
    cases.append({
        "id": "PCR-FM1",
        "description": "Tampered firmware image changes PCR 0; verifier comparing against golden values rejects the boot.",
        "expected": "PCR 0 differs from golden",
        "actual": "PCR 0 differs" if t[0] != golden[0] else "PCR 0 UNCHANGED (model failure)",
        "passed": t[0] != golden[0],
        "golden_pcr0": golden[0],
        "tampered_pcr0": t[0],
    })

    # Failure mode 2: two events in the SAME PCR swapped (kernel and
    # initrd, both PCR 9). A PCR value depends on the order of extends
    # within that PCR, so swapping them must change PCR 9 while other
    # PCRs stay identical. (Swapping events across different PCRs is a
    # no-op per PCR and is not a valid test of ordering.)
    reordered = list(BOOT_CHAIN)
    reordered[6], reordered[7] = reordered[7], reordered[6]
    r = replay(reordered)
    cases.append({
        "id": "PCR-FM2",
        "description": "Reordered boot events within one PCR change that PCR even when the same components are present; other PCRs are unaffected.",
        "expected": "PCR 9 differs from golden; PCR 0/4/7 unchanged",
        "actual": "PCR 9 differs=%s PCR 0 differs=%s PCR 4 differs=%s PCR 7 differs=%s" % (
            r[9] != golden[9], r[0] != golden[0], r[4] != golden[4], r[7] != golden[7]),
        "passed": r[9] != golden[9] and r[0] == golden[0] and r[4] == golden[4] and r[7] == golden[7],
    })

    # Failure mode 3: truncated log (last event missing — e.g. validator
    # config never measured).
    truncated = BOOT_CHAIN[:-1]
    tr = replay(truncated)
    cases.append({
        "id": "PCR-FM3",
        "description": "Truncated event log (validator config unmeasured) leaves PCR 10 different from golden.",
        "expected": "PCR 10 differs from golden",
        "actual": "PCR 10 differs" if tr[10] != golden[10] else "PCR 10 UNCHANGED (model failure)",
        "passed": tr[10] != golden[10],
    })

    # Failure mode 4: wrong hash bank (SHA-1 bank vs SHA-256 bank).
    def extend_sha1(pcr_old, digest):
        return hashlib.sha1(pcr_old + digest).digest()

    pcr_sha1 = ZERO32
    for _s, _p, l in [e for e in BOOT_CHAIN if e[1] == 0]:
        pcr_sha1 = extend_sha1(pcr_sha1, event_digest(l))
    cases.append({
        "id": "PCR-FM4",
        "description": "Verifying a SHA-256 golden value against a SHA-1 bank never matches (bank selection must agree).",
        "expected": "SHA-1 PCR 0 (20 bytes) != SHA-256 golden PCR 0 (32 bytes)",
        "actual": "lengths %d vs %d, equal=%s" % (len(pcr_sha1), len(bytes.fromhex(golden[0])), pcr_sha1.hex() == golden[0]),
        "passed": pcr_sha1.hex() != golden[0],
    })

    # Failure mode 5: legitimate firmware update changes PCR 0 (brittleness).
    updated = [
        (s, p, l.replace("v1.0.9-build", "v1.0.10-build") if s == "firmware-crtm" else l)
        for (s, p, l) in BOOT_CHAIN
    ]
    u = replay(updated)
    cases.append({
        "id": "PCR-FM5",
        "description": "A legitimate firmware update changes PCR 0 exactly like tampering does — golden values must be re-enrolled, or sealing breaks.",
        "expected": "PCR 0 differs from golden after update",
        "actual": "PCR 0 differs" if u[0] != golden[0] else "PCR 0 UNCHANGED (model failure)",
        "passed": u[0] != golden[0],
        "updated_pcr0": u[0],
    })

    passed = sum(1 for c in cases if c["passed"])
    out = {
        "label": "SIMULATED",
        "model": "TPM 2.0 PCR extend, TCG TPM 2.0 Library Part 1; PCR assignment per TCG PC Client Platform Firmware Profile v1.06 rev 52",
        "note": "No TPM hardware on this machine. All values are software-computed from fixed test vectors; no hardware measurement is claimed.",
        "boot_chain_stages": len(BOOT_CHAIN),
        "golden_pcrs_sha256": golden,
        "cases": cases,
        "cases_run": len(cases),
        "cases_passed": passed,
        "cases_failed": [c["id"] for c in cases if not c["passed"]],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("pcr_model: %d/%d cases passed" % (passed, len(cases)))
    print("golden PCR 0: %s" % golden[0])
    print("golden PCR 4: %s" % golden[4])
    print("golden PCR 7: %s" % golden[7])
    print("golden PCR 10: %s" % golden[10])
    if passed != len(cases):
        sys.exit(1)


if __name__ == "__main__":
    main()
