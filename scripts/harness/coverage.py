#!/usr/bin/env python3
"""Attestation coverage matrix (MEASURED inventory + SIMULATED models).

Combines outputs/inventory_check.json and the four model outputs into
one coverage table: for each boot-chain / trust-chain stage, what
mechanism exists in the pinned postfiatd tree, what the models show, and
whether the stage is covered, partially covered, or a gap.

Deterministic: sorted keys, no timestamps. Label: MEASURED for the
in-tree facts, SIMULATED for the model-derived rows.
"""

import json
import os
import sys

PACK = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(PACK, "outputs", "coverage.json")


def load(name):
    with open(os.path.join(PACK, "outputs", name)) as f:
        return json.load(f)


def main():
    inv = load("inventory_check.json")
    pcr = load("pcr_model.json")
    quote = load("quote_verify.json")
    seal = load("seal_model.json")
    man = load("manifest_model.json")

    inv_by_id = {c["id"]: c for c in inv["checks"]}

    # stage, in-tree mechanism (MEASURED), model result (SIMULATED), status
    rows = [
        {
            "stage": "Platform firmware (CRTM / BIOS)",
            "in_tree_mechanism": "None. No firmware measurement, no Secure Boot policy, no TPM code in the pinned tree (ATT-01).",
            "model": "pcr_model PCR-FM1/FM5: a measured boot WOULD catch tampering and WOULD change on update.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Boot manager / Secure Boot policy (db/dbx/KEK)",
            "in_tree_mechanism": "None in-tree. UEFI Secure Boot is a platform property; the tree never checks it (ATT-01).",
            "model": "pcr_model PCR 7 golden value computed; quote_verify Q-FM5 rejects quotes that omit PCR 7.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Kernel / initramfs",
            "in_tree_mechanism": "None in-tree (ATT-01).",
            "model": "pcr_model PCR 9 covers kernel + initrd in the simulated chain.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Container image / postfiatd binary",
            "in_tree_mechanism": "None. Image referenced by mutable tag (SUP-05); no digest pinning or cosign (SUP-03); entrypoint performs no integrity check (SUP-08).",
            "model": "pcr_model PCR 10 covers image + binary + config in the simulated chain.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Validator config (postfiatd.cfg, validators.txt)",
            "in_tree_mechanism": "Config-file validation only (mutual-exclusion fatal error, KEY-02). No measurement or sealing of config contents.",
            "model": "pcr_model PCR-FM3: an unmeasured config leaves PCR 10 different from golden.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Validator identity (master key)",
            "in_tree_mechanism": "Plaintext validator-keys.json, deleted on container restart, copied by docker cp / scp (OPS-01, OPS-02). No sealing, no HSM binding.",
            "model": "seal_model SEAL-CONTROL/FM4: a PCR-sealed secret WOULD release only on the matching platform.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Validator signing key (ephemeral) + token",
            "in_tree_mechanism": "Two-tier manifest: master signs ephemeral key; token carries manifest + 32-byte secret (KEY-04, MFT-04). No hardware binding of the secret.",
            "model": "manifest_model MAN-ROTATE/MAN-FM1: rotation and replay rules verified; seal_model shows how the secret could be PCR-bound.",
            "status": "PARTIAL",
            "label": "MEASURED",
        },
        {
            "stage": "Manifest revocation",
            "in_tree_mechanism": "Sequence 0xFFFFFFFF revokes the master key permanently; peers enforce monotonic sequences (MFT-02, MFT-03).",
            "model": "manifest_model MAN-REV/MAN-FM5: revocation accepted and terminal in the model.",
            "status": "COVERED",
            "label": "MEASURED",
        },
        {
            "stage": "Validator list (UNL) trust anchor",
            "in_tree_mechanism": "Single publisher key + single site in mainnet file; list signature verified against publisher manifest (UNL-01, UNL-03). Publisher revocation clears lists (UNL-04).",
            "model": "No model run: list verification is code, verified by source inspection (UNL-03).",
            "status": "PARTIAL",
            "label": "MEASURED",
        },
        {
            "stage": "Domain attestation",
            "in_tree_mechanism": "Hosted file at .well-known/pft-ledger.toml (OPS-04). No binding to boot measurements or to the validator key beyond the manifest domain field.",
            "model": "quote_verify Q-FM2/Q-FM4: a hardware quote WOULD bind identity to fresh evidence; the file-based check cannot.",
            "status": "PARTIAL",
            "label": "MEASURED",
        },
        {
            "stage": "Remote attestation (TPM quote / enclave report)",
            "in_tree_mechanism": "None. No quote, no AK enrollment, no verifier, no reference values anywhere in the tree or deployment (ATT-01).",
            "model": "quote_verify Q-CONTROL + Q-FM1..Q-FM6: all six failure modes behave as a verifier should — in the model only.",
            "status": "GAP",
            "label": "MEASURED",
        },
        {
            "stage": "Post-quantum signatures (validator identity, manifests, lists)",
            "in_tree_mechanism": "secp256k1 ECDSA only (KEY-01). No ML-DSA/SLH-DSA anywhere; no hybrid path.",
            "model": "No model run: algorithm inventory is a source fact (KEY-01). Migration is specified in docs/migration-plan.md.",
            "status": "GAP",
            "label": "MEASURED",
        },
    ]

    counts = {"COVERED": 0, "PARTIAL": 0, "GAP": 0}
    for r in rows:
        counts[r["status"]] += 1

    out = {
        "label": "MEASURED",
        "pinned_commit": inv["pinned_commit"],
        "inventory_checks_passed": "%d/%d" % (inv["checks_passed"], inv["checks_run"]),
        "model_cases": {
            "pcr_model": "%d/%d" % (pcr["cases_passed"], pcr["cases_run"]),
            "quote_verify": "%d/%d" % (quote["cases_passed"], quote["cases_run"]),
            "seal_model": "%d/%d" % (seal["cases_passed"], seal["cases_run"]),
            "manifest_model": "%d/%d" % (man["cases_passed"], man["cases_run"]),
        },
        "rows": rows,
        "counts": counts,
        "stages_total": len(rows),
        "coverage_summary": "%d covered, %d partial, %d gaps out of %d stages"
        % (counts["COVERED"], counts["PARTIAL"], counts["GAP"], len(rows)),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("coverage: %s" % out["coverage_summary"])
    if inv["checks_failed"]:
        print("WARNING: inventory checks failed: %s" % ", ".join(inv["checks_failed"]))
        sys.exit(1)


if __name__ == "__main__":
    main()
