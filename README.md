# Validator secure-boot and attestation assessment

An assessment of PostFiat validator secure boot and remote attestation
at pinned postfiatd commit `0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10, 1.0.9), with a lab-only runnable harness, a severity-ranked
findings register, and a staged hardening and post-quantum migration plan.

## Headline results

- **No measured boot or remote attestation exists** anywhere in the
  pinned tree or deployment: zero TPM / Secure Boot / SGX / SEV /
  enclave / PCR / UEFI / HSM code in 1,947 tree paths (inventory check
  ATT-01). The validator's only trust anchors are manifest signatures
  and the validator list.
- **Validator signing is secp256k1-only**, with no post-quantum path;
  revocation is terminal (sequence 0xFFFFFFFF).
- **Master keys are plaintext JSON** (`validator-keys.json`), deleted on
  container restart and shuttled with `docker cp` / `scp`.
- **The mainnet validator-list file trusts one publisher** and points
  at a testnet list URL.
- **Coverage: 1 covered, 3 partial, 8 gaps out of 12 stages**
  (`outputs/coverage.json`).
- **13 findings** (1 Critical, 4 High, 5 Medium, 2 Low, 1 Informational)
  in `findings/findings-register.md`.
- **Harness: 31/31 inventory checks pass; 28/28 model cases pass**
  (PCR 6/6, quote 7/7, seal 7/7, manifest 8/8).
- **Fresh-clone reproduction: byte-identical** — see
  `outputs/reproduction/COMPARISON.md`.

## What is in this pack

| Path | Contents |
|---|---|
| `PINNED-SOURCES.md` | Pinned commit, vendored-file manifest, external dependency pin, vendor specifications |
| `inventory/boot-chain-inventory.md` | Boot-chain stages with in-tree evidence |
| `inventory/attestation-surfaces.md` | Manifest, token, seed, UNL, domain, deployment, remote-attestation surfaces |
| `findings/findings-register.md` | 13 severity-ranked findings with assets, prerequisites, impact, evidence |
| `docs/decision-memo.md` | Priorities, what is and is not proven, unresolved dependencies |
| `docs/migration-plan.md` | Stages 0–4: hygiene, measured boot + attestation, sealing, enclave evaluation, post-quantum |
| `docs/claim-evidence-index.md` | Every substantive claim with label and evidence pointer |
| `docs/methodology.md` | Pinning, static analysis, models, label discipline, limitations |
| `scripts/run_all.sh` | Runs the full harness, preserves unedited outputs |
| `scripts/verify_digests.sh` | Verifies every deterministic shipped file against `SHA256SUMS` (excludes `outputs/run_all.log` and `outputs/reproduction/COMPARISON.md` — see `docs/methodology.md`) |
| `scripts/clean_reproduce.sh` | Fresh-clone reproduction from the pack alone (no network, no other repo, no Conan, no package manager) |
| `scripts/harness/` | `inventory_check.py`, `pcr_model.py`, `quote_verify.py`, `seal_model.py`, `manifest_model.py`, `coverage.py`, `ecdsa.py` (pure-Python ECDSA, stdlib only) |
| `evidence/pinned-sources/` | Verbatim copies of the 21 cited pinned files |
| `evidence/pinned-tree-manifest.json` | Per-file blob SHA-1, size, SHA-256 for the vendored files |
| `evidence/pinned-tree-paths.txt` | Full 1,947-path listing of the pinned tree |
| `outputs/` | Unedited harness outputs (`*.json`, `run_all.log`) |
| `outputs/reproduction/COMPARISON.md` | Fresh-clone byte-comparison result |
| `SHA256SUMS` | Full SHA-256 digests of every deterministic shipped file (48 files; excludes `outputs/run_all.log` and `outputs/reproduction/COMPARISON.md`) |

## How to run

```sh
sh scripts/run_all.sh          # run the full harness; outputs land in outputs/
sh scripts/verify_digests.sh   # verify every deterministic shipped file against SHA256SUMS
sh scripts/clean_reproduce.sh  # fresh-clone reproduction; writes outputs/reproduction/COMPARISON.md
```

Requirements: Python 3 (standard library only) and `sha256sum`. No
network, no hardware, no package manager, no other repository.

## Labels

Every substantive claim is labelled: **MEASURED** (verified against
the pinned source or produced by executing the harness), **SIMULATED**
(software model of specified behaviour — no hardware involved),
**UNTESTABLE** (would need validator-host hardware or access that was
not available), **ANALYSIS** (interpretation or recommendation).

No hardware measurement is claimed anywhere in this pack. The build
machine has no TPM device and no enclave hardware; all hardware
behaviour is modelled in software and labelled SIMULATED.

## Pinned sources

- postfiatd `0085a1ff885d6a446369cf73a4430f75af22be55` (LIVE main HEAD,
  2026-10-10, 1.0.9), fetched via the GitHub API at build start.
- validator-keys-tool pinned to `05742108d4b7c0b7d9a97c073acd690d2c75a2b4`.
- Vendor specifications: TCG TPM 2.0 Library Parts 1 and 3; TCG PC
  Client Platform Firmware Profile v1.06 rev 52; UEFI 2.10 ch. 32;
  NIST SP 800-155 (draft, retired 2024-10-25) and SP 1800-34;
  RFC 9334; NIST FIPS 203/204/205.
