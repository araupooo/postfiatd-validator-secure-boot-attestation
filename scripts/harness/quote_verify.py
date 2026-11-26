#!/usr/bin/env python3
"""SIMULATED TPM2_Quote verification model.

Models the TPM2_Quote flow (TCG TPM 2.0 Library Part 3, TPM2_Quote):
an Attestation Key (AK) inside the TPM signs a TPMS_ATTEST structure
committing to selected PCR values and to verifier-supplied qualifying
data (a nonce). The verifier checks the signature, the nonce, the PCR
selection, and the PCR digest, and compares the PCR values against
reference (golden) values.

Implementation: pure-Python ECDSA over NIST P-256 (see ecdsa.py; the
implementation was cross-checked against OpenSSL at build time).
Fixed test keys and nonces — deterministic, no hardware, no TPM.
Label: SIMULATED. No hardware measurement is claimed.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ecdsa import P256, sign, verify, point_hex, sig_hex  # noqa: E402
from pcr_model import BOOT_CHAIN, replay  # noqa: E402

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "quote_verify.json")

# Fixed test keys (labelled test-only; never used outside this model).
AK_PRIV = 0xA11CE5
OTHER_PRIV = 0xBADACC
AK_PUB = P256.pubkey(AK_PRIV)
OTHER_PUB = P256.pubkey(OTHER_PRIV)

# Golden PCR values: recomputed here from the SAME boot chain and extend
# rule as pcr_model.py, so the two models agree exactly.
GOLDEN_PCRS = {0: replay(BOOT_CHAIN)[0]}
NONCE = bytes.fromhex("5eedf00d5eedf00d5eedf00d5eedf00d5eedf00d5eedf00d5eedf00d5eedf00d")
STALE_NONCE = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
SELECTION = "sha256:0,1,2,4,7"


def pcr_digest(pcr_values):
    """TPMS_QUOTE_INFO pcrDigest: hash of the concatenation of the selected
    PCR values, in index order."""
    h = hashlib.sha256()
    for idx in sorted(pcr_values):
        h.update(bytes.fromhex(pcr_values[idx]))
    return h.hexdigest()


def attest_bytes(nonce, selection, digest):
    """Canonical bytes of the attestation structure that the AK signs."""
    return json.dumps(
        {
            "magic": "TPMS_ATTEST",
            "type": "TPM_ST_ATTEST_QUOTE",
            "qualified_signer": point_hex(AK_PUB),
            "extra_data_nonce": nonce.hex(),
            "pcr_selection": selection,
            "pcr_digest": digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def make_quote(priv, nonce, selection, pcr_values):
    digest = pcr_digest(pcr_values)
    data = attest_bytes(nonce, selection, digest)
    r, s = sign(P256, priv, hashlib.sha256(data).digest())
    return {
        "attest": json.loads(data.decode()),
        "signature_hex": sig_hex(r, s),
        "pcr_values": pcr_values,
    }


def verify_quote(quote, expected_nonce, expected_selection, enrolled_pub, golden_digest):
    """Return (ok, reasons). Mirrors the checks a RATS verifier performs
    (RFC 9334 roles: Attester produces Evidence, Verifier appraises it)."""
    reasons = []
    attest = quote["attest"]
    if attest["extra_data_nonce"] != expected_nonce.hex():
        reasons.append("nonce mismatch (stale or replayed quote)")
    if attest["pcr_selection"] != expected_selection:
        reasons.append("PCR selection differs from policy")
    digest = pcr_digest(quote["pcr_values"])
    if attest["pcr_digest"] != digest:
        reasons.append("quoted PCR digest does not match supplied PCR values")
    if digest != golden_digest:
        reasons.append("PCR values differ from golden reference values")
    r = int(quote["signature_hex"][:64], 16)
    s = int(quote["signature_hex"][64:], 16)
    data = json.dumps(attest, sort_keys=True, separators=(",", ":")).encode()
    if not verify(P256, enrolled_pub, hashlib.sha256(data).digest(), r, s):
        reasons.append("signature invalid under enrolled AK")
    return (len(reasons) == 0, reasons)


def main():
    # Golden PCR set for the model (PCR 0 only, to keep the vectors short;
    # the full set is exercised in pcr_model.py).
    golden_pcrs = {0: GOLDEN_PCRS[0]}
    golden_digest = pcr_digest(golden_pcrs)

    cases = []

    def run(cid, description, quote, nonce, selection, pub, digest, expect_ok):
        ok, reasons = verify_quote(quote, nonce, selection, pub, digest)
        passed = ok == expect_ok
        cases.append({
            "id": cid,
            "description": description,
            "expected": "accept" if expect_ok else "reject",
            "actual": "accept" if ok else "reject: " + "; ".join(reasons),
            "passed": passed,
            "signature_hex": quote["signature_hex"],
        })

    good = make_quote(AK_PRIV, NONCE, SELECTION, golden_pcrs)
    run("Q-CONTROL", "Valid quote from the enrolled AK, fresh nonce, golden PCRs is accepted.",
        good, NONCE, SELECTION, AK_PUB, golden_digest, True)

    # FM1: tampered signature (flip one hex digit of s).
    bad_sig = dict(good)
    bad_sig["signature_hex"] = good["signature_hex"][:100] + ("0" if good["signature_hex"][100] != "0" else "1") + good["signature_hex"][101:]
    run("Q-FM1", "Tampered signature is rejected.",
        bad_sig, NONCE, SELECTION, AK_PUB, golden_digest, False)

    # FM2: replay — a quote made for an old nonce presented for a new challenge.
    replayed = make_quote(AK_PRIV, STALE_NONCE, SELECTION, golden_pcrs)
    run("Q-FM2", "Replayed quote (stale nonce) is rejected even though the signature is valid.",
        replayed, NONCE, SELECTION, AK_PUB, golden_digest, False)

    # FM3: PCR values changed after the quote was signed (tampered boot).
    tampered_pcrs = {0: hashlib.sha256(b"tampered firmware").hexdigest()}
    tampered = make_quote(AK_PRIV, NONCE, SELECTION, golden_pcrs)
    tampered["pcr_values"] = tampered_pcrs
    run("Q-FM3", "Quote whose PCR values no longer match the signed digest is rejected.",
        tampered, NONCE, SELECTION, AK_PUB, golden_digest, False)

    # FM4: quote signed by a different AK (attacker key, not enrolled).
    wrong_ak = make_quote(OTHER_PRIV, NONCE, SELECTION, golden_pcrs)
    run("Q-FM4", "Quote signed by a non-enrolled AK is rejected.",
        wrong_ak, NONCE, SELECTION, AK_PUB, golden_digest, False)

    # FM5: PCR selection narrowed (PCR 7 Secure Boot policy dropped).
    narrow = make_quote(AK_PRIV, NONCE, "sha256:0,1,2,4", golden_pcrs)
    run("Q-FM5", "Quote omitting a policy-required PCR (PCR 7, Secure Boot policy) is rejected.",
        narrow, NONCE, SELECTION, AK_PUB, golden_digest, False)

    # FM6: golden values changed by a legitimate firmware update, quote is
    # genuine but the reference values are stale — verifier must re-enroll.
    new_golden = {0: hashlib.sha256(b"firmware v1.0.10").hexdigest()}
    updated_quote = make_quote(AK_PRIV, NONCE, SELECTION, new_golden)
    run("Q-FM6", "Genuine quote after a firmware update is rejected until golden reference values are re-enrolled.",
        updated_quote, NONCE, SELECTION, AK_PUB, golden_digest, False)

    passed = sum(1 for c in cases if c["passed"])
    out = {
        "label": "SIMULATED",
        "model": "TPM2_Quote verification, TCG TPM 2.0 Library Part 3; verifier roles per RFC 9334 (RATS)",
        "note": "No TPM hardware on this machine. AK is a fixed test key; signatures are pure-Python ECDSA P-256, cross-checked against OpenSSL at build time. No hardware measurement is claimed.",
        "ak_public_key_uncompressed_hex": point_hex(AK_PUB),
        "pcr_selection_policy": SELECTION,
        "golden_pcr_digest_sha256": golden_digest,
        "cases": cases,
        "cases_run": len(cases),
        "cases_passed": passed,
        "cases_failed": [c["id"] for c in cases if not c["passed"]],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("quote_verify: %d/%d cases passed" % (passed, len(cases)))
    print("AK public key: %s" % point_hex(AK_PUB))
    print("golden PCR digest: %s" % golden_digest)
    print("control quote signature: %s" % good["signature_hex"])
    if passed != len(cases):
        sys.exit(1)


if __name__ == "__main__":
    main()
