#!/usr/bin/env python3
"""SIMULATED PCR-policy sealing model for a validator signing secret.

Models TPM2 sealing (TCG TPM 2.0 Library Part 3, TPM2_Create with an
authPolicy derived from a PCR policy, TPM2_PolicyPCR, TPM2_Unseal):
a secret is sealed so it can only be released when the platform PCRs
match the policy. This is a SOFTWARE model of the policy logic only:
the "seal" is an HMAC-based construction over the policy digest, not a
real TPM object. It shows which states release the secret and which do
not. Label: SIMULATED. No TPM hardware on this machine; no hardware
measurement is claimed.

Policy digest: SHA-256 over the ordered (pcr_index, pcr_value) pairs
plus a policy version string — the model equivalent of a TPM2_PolicyPCR
digest. A signed-policy variant models TPM2_PolicyAuthorize: an
authority key signs a new policy digest, letting a legitimate update
re-authorize unsealing without re-sealing.
"""

import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ecdsa import P256, sign, verify, point_hex  # noqa: E402
from pcr_model import BOOT_CHAIN, replay  # noqa: E402

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "seal_model.json")

SECRET = b"validator-ephemeral-signing-secret (TEST VECTOR ONLY)"
AUTH_PRIV = 0xA070
AUTH_PUB = P256.pubkey(AUTH_PRIV)


def policy_digest(pcr_values, version="policy-v1"):
    h = hashlib.sha256()
    h.update(version.encode())
    for idx in sorted(pcr_values):
        h.update(b"%d:" % idx)
        h.update(bytes.fromhex(pcr_values[idx]))
    return h.hexdigest()


def seal(secret, digest):
    """Model seal: the blob is masked with a FIXED seal key (standing in
    for the TPM's internal protection of the sealed object). The policy
    digest is stored alongside as the release condition only — it is NOT
    the decryption key. That matches real TPM semantics: PolicyAuthorize
    can authorize a NEW policy digest without re-sealing the object."""
    mask = hmac.new(b"seal-key (TEST VECTOR ONLY)", b"seal-mask", hashlib.sha256).digest()
    blob = bytes(a ^ b for a, b in zip(secret, (mask * ((len(secret) // 32) + 1))[:len(secret)]))
    return {"policy_digest": digest, "blob_hex": blob.hex()}


def _unmask(blob):
    mask = hmac.new(b"seal-key (TEST VECTOR ONLY)", b"seal-mask", hashlib.sha256).digest()
    raw = bytes.fromhex(blob["blob_hex"])
    return bytes(a ^ b for a, b in zip(raw, (mask * ((len(raw) // 32) + 1))[:len(raw)]))


def unseal(blob, current_pcr_values, version="policy-v1", auth_sig=None):
    """Model unseal. Release requires EITHER the current PCRs to
    reproduce the sealed policy digest, OR (PolicyAuthorize model) a
    valid authority signature over the current policy digest. Returns
    (secret_or_None, current_policy_digest)."""
    digest = policy_digest(current_pcr_values, version)
    if digest == blob["policy_digest"]:
        return _unmask(blob), digest
    if auth_sig is not None:
        r, s = auth_sig
        if verify(P256, AUTH_PUB, hashlib.sha256(digest.encode()).digest(), r, s):
            return _unmask(blob), digest
    return None, digest


def main():
    golden = replay(BOOT_CHAIN)
    blob = seal(SECRET, policy_digest(golden))
    cases = []

    def run(cid, description, pcr_values, version, expect_ok, signed_auth=None):
        secret, digest = unseal(blob, pcr_values, version, auth_sig=signed_auth)
        ok = secret == SECRET
        cases.append({"id": cid, "description": description,
                      "expected": "release" if expect_ok else "refuse",
                      "actual": ("release" if ok else "refuse"),
                      "passed": ok == expect_ok,
                      "current_policy_digest": digest})

    run("SEAL-CONTROL", "Unseal on the exact golden boot state releases the secret.",
        golden, "policy-v1", True)

    tampered = dict(golden)
    tampered[4] = hashlib.sha256(b"tampered boot manager").hexdigest()
    run("SEAL-FM1", "Tampered boot manager (PCR 4 changed) refuses unseal.",
        tampered, "policy-v1", False)

    updated = dict(golden)
    updated[0] = hashlib.sha256(b"firmware v1.0.10").hexdigest()
    run("SEAL-FM2", "Legitimate firmware update (PCR 0 changed) refuses unseal — sealing is brittle without a signed-policy path.",
        updated, "policy-v1", False)

    # Signed-policy (PolicyAuthorize) path: authority signs the updated
    # policy digest; unseal succeeds on the updated firmware.
    new_digest = policy_digest(updated, "policy-v1")
    r, s = sign(P256, AUTH_PRIV, hashlib.sha256(new_digest.encode()).digest())
    run("SEAL-FM3", "Same firmware update, but with an authority-signed policy digest (PolicyAuthorize model), releases the secret.",
        updated, "policy-v1", True, signed_auth=(r, s))

    # Forged authorization: same update, but the signature is from a
    # different (non-authority) key.
    WRONG_AUTH_PRIV = 0xBADC0DE
    r_bad, s_bad = sign(P256, WRONG_AUTH_PRIV, hashlib.sha256(new_digest.encode()).digest())
    run("SEAL-FM6", "Same firmware update with an authority signature from a non-authority key refuses unseal.",
        updated, "policy-v1", False, signed_auth=(r_bad, s_bad))

    # Attacker who copies the sealed blob but boots a different platform.
    attacker_pcrs = {i: hashlib.sha256(("attacker-platform-%d" % i).encode()).hexdigest() for i in golden}
    run("SEAL-FM4", "Sealed blob copied to a different platform refuses unseal (PCRs do not match).",
        attacker_pcrs, "policy-v1", False)

    # Wrong policy version string.
    run("SEAL-FM5", "Unseal attempted under a different policy version refuses (policy digest includes the version).",
        golden, "policy-v2", False)

    passed = sum(1 for c in cases if c["passed"])
    out = {
        "label": "SIMULATED",
        "model": "TPM2 PCR-policy sealing, TCG TPM 2.0 Library Part 3 (TPM2_Create / TPM2_PolicyPCR / TPM2_Unseal / TPM2_PolicyAuthorize)",
        "note": "Software model of policy logic only. The seal construction is HMAC-based, not a TPM object; no TPM hardware on this machine; no hardware measurement is claimed.",
        "sealed_policy_digest_sha256": blob["policy_digest"],
        "sealed_blob_sha256": hashlib.sha256(bytes.fromhex(blob["blob_hex"])).hexdigest(),
        "authority_public_key_uncompressed_hex": point_hex(AUTH_PUB),
        "cases": cases,
        "cases_run": len(cases),
        "cases_passed": passed,
        "cases_failed": [c["id"] for c in cases if not c["passed"]],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("seal_model: %d/%d cases passed" % (passed, len(cases)))
    print("sealed policy digest: %s" % blob["policy_digest"])
    print("sealed blob sha256: %s" % out["sealed_blob_sha256"])
    if passed != len(cases):
        sys.exit(1)


if __name__ == "__main__":
    main()
