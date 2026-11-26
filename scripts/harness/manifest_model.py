#!/usr/bin/env python3
"""Validator manifest lifecycle model (SIMULATED behaviour, MEASURED rules).

The RULES are taken from the pinned postfiatd source and re-checked by
inventory_check.py (checks MFT-01..MFT-05):
  * Manifest::verify() requires BOTH the ephemeral signing-key signature
    and the master-key signature (Manifest.cpp:196-215).
  * A manifest is accepted only if its sequence is strictly greater than
    the stored one (Manifest.cpp:411).
  * Sequence 0xFFFFFFFF revokes the master key permanently; no higher
    sequence exists (Manifest.cpp:236-240, Manifest.h:71-76).
  * A fresh peer that has never seen a master key accepts any valid
    sequence on first sighting (ManifestCache::applyManifest, first-entry
    path, Manifest.cpp:400-460).

The BEHAVIOUR is then exercised with real secp256k1 ECDSA signatures
(pure-Python implementation in ecdsa.py, cross-checked against OpenSSL
at build time) on fixed test keys. This models the manifest protocol
logic; it does not run postfiatd and does not claim any on-chain or
on-network measurement. Label: SIMULATED for the lifecycle cases,
MEASURED for the source-derived rules.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ecdsa import SECP256K1, sign, verify, point_hex, sig_hex  # noqa: E402

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "manifest_model.json")

MAX_SEQ = 0xFFFFFFFF

# Fixed test keys (labelled test-only; never used outside this model).
MASTER_PRIV = 0x1A57E2
EPHEMERAL_PRIV = 0xE9E1
MASTER_PUB = SECP256K1.pubkey(MASTER_PRIV)
EPHEMERAL_PUB = SECP256K1.pubkey(EPHEMERAL_PRIV)


def canonical(master_pub, signing_pub, sequence, domain):
    return json.dumps(
        {
            "master_key": point_hex(master_pub),
            "signing_key": point_hex(signing_pub) if signing_pub else None,
            "sequence": sequence,
            "domain": domain,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def make_manifest(master_priv, signing_priv, sequence, domain=""):
    master_pub = SECP256K1.pubkey(master_priv)
    signing_pub = SECP256K1.pubkey(signing_priv) if signing_priv else None
    data = canonical(master_pub, signing_pub, sequence, domain)
    digest = hashlib.sha256(data).digest()
    r1, s1 = sign(SECP256K1, signing_priv, digest) if signing_priv else (0, 0)
    r2, s2 = sign(SECP256K1, master_priv, digest)
    return {
        "master_key": point_hex(master_pub),
        "signing_key": point_hex(signing_pub) if signing_pub else None,
        "sequence": sequence,
        "domain": domain,
        "signing_signature": sig_hex(r1, s1) if signing_priv else None,
        "master_signature": sig_hex(r2, s2),
        "_canonical_sha256": hashlib.sha256(data).hexdigest(),
    }


def verify_manifest(m):
    """Mirror of Manifest::verify(): both signatures must check out;
    a revoked manifest needs no signing key."""
    if m["sequence"] == MAX_SEQ:
        # Revocation: only the master signature is required.
        data = json.dumps(
            {"master_key": m["master_key"], "signing_key": None,
             "sequence": m["sequence"], "domain": m["domain"]},
            sort_keys=True, separators=(",", ":")).encode()
        r = int(m["master_signature"][:64], 16)
        s = int(m["master_signature"][64:], 16)
        master_pub = (int(m["master_key"][2:66], 16), int(m["master_key"][66:], 16))
        return verify(SECP256K1, master_pub, hashlib.sha256(data).digest(), r, s)
    if not m["signing_key"]:
        return False
    data = json.dumps(
        {"master_key": m["master_key"], "signing_key": m["signing_key"],
         "sequence": m["sequence"], "domain": m["domain"]},
        sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(data).digest()
    master_pub = (int(m["master_key"][2:66], 16), int(m["master_key"][66:], 16))
    signing_pub = (int(m["signing_key"][2:66], 16), int(m["signing_key"][66:], 16))
    r1, s1 = int(m["signing_signature"][:64], 16), int(m["signing_signature"][64:], 16)
    r2, s2 = int(m["master_signature"][:64], 16), int(m["master_signature"][64:], 16)
    return (verify(SECP256K1, signing_pub, digest, r1, s1)
            and verify(SECP256K1, master_pub, digest, r2, s2))


class ManifestCache:
    """Minimal model of ManifestCache::applyManifest sequence handling."""

    def __init__(self):
        self.store = {}  # master_key_hex -> (sequence, revoked)

    def apply(self, m):
        key = m["master_key"]
        if key in self.store:
            stored_seq, revoked = self.store[key]
            if revoked:
                return "rejected: master key revoked"
            if m["sequence"] <= stored_seq:
                return "rejected: sequence %d not greater than stored %d" % (m["sequence"], stored_seq)
        if not verify_manifest(m):
            return "rejected: signature verification failed"
        revoked = m["sequence"] == MAX_SEQ
        self.store[key] = (m["sequence"], revoked)
        return "accepted: revoked" if revoked else "accepted"


def main():
    cases = []
    cache = ManifestCache()

    def run(cid, description, manifest, expect_prefix):
        result = cache.apply(manifest)
        passed = result.startswith(expect_prefix)
        cases.append({
            "id": cid,
            "description": description,
            "expected": expect_prefix,
            "actual": result,
            "passed": passed,
            "manifest_sequence": manifest["sequence"],
            "manifest_canonical_sha256": manifest["_canonical_sha256"],
        })

    m1 = make_manifest(MASTER_PRIV, EPHEMERAL_PRIV, 1, "validator.example.com")
    run("MAN-CONTROL", "First valid manifest (sequence 1) is accepted.",
        m1, "accepted")

    m2 = make_manifest(MASTER_PRIV, EPHEMERAL_PRIV, 2, "validator.example.com")
    run("MAN-ROTATE", "Rotation to sequence 2 with the same keys is accepted (key rotation path).",
        m2, "accepted")

    run("MAN-FM1", "Replay of the superseded sequence-1 manifest is rejected (sequence not strictly greater).",
        m1, "rejected: sequence")

    m3 = make_manifest(MASTER_PRIV, EPHEMERAL_PRIV, 3, "validator.example.com")
    m3_tampered = dict(m3)
    m3_tampered["domain"] = "attacker.example.com"
    run("MAN-FM2", "Manifest with a tampered domain (signatures no longer match the content) is rejected.",
        m3_tampered, "rejected: signature")

    m4 = make_manifest(MASTER_PRIV, EPHEMERAL_PRIV, 4, "validator.example.com")
    m4_bad = dict(m4)
    sig = m4_bad["master_signature"]
    m4_bad["master_signature"] = sig[:10] + ("0" if sig[10] != "0" else "1") + sig[11:]
    run("MAN-FM3", "Manifest with a tampered master signature is rejected.",
        m4_bad, "rejected: signature")

    # Fresh peer: a new cache that never saw this master key accepts any
    # valid sequence on first sighting — including a STALE one.
    fresh = ManifestCache()
    stale_first = fresh.apply(m1)
    cases.append({
        "id": "MAN-FM4",
        "description": "A fresh peer with no prior manifest for this master key accepts the stale sequence-1 manifest (first-sighting rule) — the rollback window.",
        "expected": "accepted",
        "actual": stale_first,
        "passed": stale_first.startswith("accepted"),
        "manifest_sequence": 1,
        "manifest_canonical_sha256": m1["_canonical_sha256"],
    })

    # Revocation: sequence 0xFFFFFFFF, signed by the master key only.
    rev = make_manifest(MASTER_PRIV, None, MAX_SEQ, "")
    # make_manifest with signing_priv=None produces a revocation-shaped
    # manifest; verify_manifest handles the revoked path.
    run("MAN-REV", "Revocation manifest (sequence 4294967295, master signature only) is accepted and marks the key revoked.",
        rev, "accepted: revoked")

    m5 = make_manifest(MASTER_PRIV, EPHEMERAL_PRIV, 5, "validator.example.com")
    run("MAN-FM5", "After revocation, no further manifest for that master key is accepted (no higher sequence exists).",
        m5, "rejected")

    passed = sum(1 for c in cases if c["passed"])
    out = {
        "label": "SIMULATED",
        "model": "Validator manifest lifecycle per pinned postfiatd src/xrpld/app/misc/Manifest.h and src/xrpld/app/misc/detail/Manifest.cpp (verify, sequence monotonicity, revocation at 0xFFFFFFFF)",
        "note": "Lifecycle cases are a software model using real secp256k1 ECDSA on fixed test keys; the rules themselves are MEASURED from the pinned source (inventory_check.py MFT-01..MFT-05). No on-network measurement is claimed.",
        "master_public_key_uncompressed_hex": point_hex(MASTER_PUB),
        "ephemeral_public_key_uncompressed_hex": point_hex(EPHEMERAL_PUB),
        "cases": cases,
        "cases_run": len(cases),
        "cases_passed": passed,
        "cases_failed": [c["id"] for c in cases if not c["passed"]],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("manifest_model: %d/%d cases passed" % (passed, len(cases)))
    print("master public key: %s" % point_hex(MASTER_PUB))
    print("control manifest canonical sha256: %s" % m1["_canonical_sha256"])
    if passed != len(cases):
        sys.exit(1)


if __name__ == "__main__":
    main()
