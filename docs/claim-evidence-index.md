# Claim-to-evidence index

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55`.
Labels: MEASURED / SIMULATED / UNTESTABLE / ANALYSIS.
Evidence paths are relative to the pack root unless they name a file
inside `evidence/pinned-sources/` (the vendored pinned tree).
Bare tree-relative paths — `src/...`, `include/...`, `cfg/...`,
`scripts/...`, `Dockerfile`, `.github/...`, and the pinned-tree documents
`docs/DomainAttestation.md`, `docs/DeploymentWorkflows.md`,
`docs/Docker.md`, `docs/ValidatorKeyUpdate.md`, `docs/build/install.md` —
refer to files in the pinned postfiatd tree and resolve under
`evidence/pinned-sources/` with the same relative path (e.g.
`docs/DomainAttestation.md` means
`evidence/pinned-sources/docs/DomainAttestation.md`). This pack's own
documents are cited with their pack-root path
(`docs/claim-evidence-index.md`, `docs/decision-memo.md`,
`docs/methodology.md`, `docs/migration-plan.md`).

## Pinned source

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-01 | Pinned commit is the LIVE main HEAD, 2026-10-10, 1.0.9 | MEASURED | `PINNED-SOURCES.md`; `evidence/pinned-tree-manifest.json`; `outputs/inventory_check.json` PIN-02 |
| C-02 | 21 vendored files are byte-identical to the pinned tree (blob SHA-1 + size) | MEASURED | `evidence/pinned-tree-manifest.json`; PIN-01; `outputs/inventory_check.json` |
| C-03 | Tree has 1,947 paths | MEASURED | `evidence/pinned-tree-paths.txt`; PIN-01 |

## Validator keys and manifests

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-10 | Validator signing keys are secp256k1 ECDSA only | MEASURED | `ValidatorKeys.cpp` lines 47, 84, 85; KEY-01 |
| C-11 | `[validation_seed]` and `[validator_token]` are mutually exclusive (fatal) | MEASURED | `ValidatorKeys.cpp` lines 31–37; `Config.cpp` lines 637–640; KEY-02 |
| C-12 | Seed path derives keys directly, sequence 0, no manifest | MEASURED | `ValidatorKeys.cpp` lines 72–91; KEY-03 |
| C-13 | Token path requires derived public key == manifest signing key | MEASURED | `ValidatorKeys.cpp` lines 43–61; KEY-04 |
| C-14 | Token is base64 JSON: `manifest` + 32-byte `validation_secret_key` | MEASURED | `Manifest.cpp` lines 264–300; MFT-04 |
| C-15 | Manifest verify requires both signing-key and master signatures | MEASURED | `Manifest.cpp` lines 196–215; MFT-01 |
| C-16 | Revocation is sequence 0xFFFFFFFF, terminal | MEASURED | `Manifest.cpp` lines 226–240; `Manifest.h` lines 71–76; MFT-02 |
| C-17 | Manifest accepted only if sequence strictly greater than stored | MEASURED | `Manifest.cpp` line 411; MFT-03 |
| C-18 | Manifest lifecycle (rotate / replay-reject / tamper-reject / first-sighting accept / terminal revoke) behaves as specified | SIMULATED | `scripts/harness/manifest_model.py`; `outputs/manifest_model.json` 8/8 |
| C-19 | No post-quantum signature anywhere in the validator path | MEASURED | KEY-01 (secp256k1 only); ATT-01 (no PQ code in tree) |

## Attestation absence

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-20 | No TPM / Secure Boot / SGX / SEV / enclave / measured-boot / PCR / UEFI / HSM code in the tree | MEASURED | 1,947-path scan; ATT-01; `outputs/inventory_check.json` |
| C-21 | Only "attestation" in-tree is cross-chain XChainAttestations + a test helper | MEASURED | ATT-02 |
| C-22 | No TPM quote, AK enrollment, verifier, or golden values in tree or deployment | MEASURED | ATT-01; inventory/attestation-surfaces.md S-7 |
| C-23 | A measured boot would catch tampering, reordering, truncation; an update changes PCRs like tampering | SIMULATED | `scripts/harness/pcr_model.py`; `outputs/pcr_model.json` 6/6 |
| C-24 | A quote verifier would reject tampered, replayed, wrong-AK, narrowed-selection, and stale-golden quotes | SIMULATED | `scripts/harness/quote_verify.py`; `outputs/quote_verify.json` 7/7 |
| C-25 | A PCR-sealed secret releases only on matching boot; an authority-signed policy authorizes updates; a forged authorization refuses | SIMULATED | `scripts/harness/seal_model.py`; `outputs/seal_model.json` 7/7 |
| C-26 | Whether real validator hosts have TPM 2.0 / Secure Boot enabled / would produce valid quotes | UNTESTABLE | docs/methodology.md (no host access, no hardware) |

## Validator list and domain

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-30 | Mainnet file trusts 1 site + 1 publisher key; threshold 0 (computed 1) | MEASURED | `cfg/validators-mainnet.txt` lines 56–59, 71–86; UNL-01 |
| C-31 | Mainnet file points at a testnet list URL (`postfiat.org/testnet_vl.json`) | MEASURED | `cfg/validators-mainnet.txt` line 56; UNL-02 |
| C-32 | Fetched lists verified against publisher manifest signing key | MEASURED | `ValidatorList.cpp` lines 1404–1407, 1166; UNL-03 |
| C-33 | Publisher revocation removes its list and clears pending lists | MEASURED | `ValidatorList.cpp` lines 1392–1397; UNL-04 |
| C-34 | List sites may be plain http as well as https | MEASURED | `ValidatorSite.cpp` lines 65–68, 520–535; UNL-05 |
| C-35 | Domain attestation is a hosted file at `.well-known/pft-ledger.toml`, unbound to boot state | MEASURED | `docs/DomainAttestation.md` lines 3, 11; OPS-04 |

## Operations and deployment

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-40 | `validator-keys.json` is deleted on container restart/recreate | MEASURED | `docs/ValidatorKeyUpdate.md` lines 16, 207–209; OPS-01 |
| C-41 | Key workflow copies the master-key file with `docker cp` / `scp` | MEASURED | `docs/ValidatorKeyUpdate.md` lines 23–24, 40–44; OPS-02 |
| C-42 | Documented rotation cadence 6–12 months; `set_domain` rotates the signing key | MEASURED | `docs/ValidatorKeyUpdate.md` lines 81, 109–116; OPS-03 |
| C-43 | Base image `ubuntu:24.04` by tag, no digest pin | MEASURED | `Dockerfile` line 17; SUP-01 |
| C-44 | Toolchain unpinned (`apt update`, `pipx install conan`, CMake tarball) | MEASURED | `Dockerfile` lines 33–48; SUP-02 |
| C-45 | No image signing / digest verification anywhere (no cosign, no `@sha256`) | MEASURED | Dockerfile + deploy.yml + DeploymentWorkflows.md; SUP-03 |
| C-46 | Deploy injects tokens from GitHub Secrets over SSH, selected by host IP | MEASURED | `.github/workflows/deploy.yml` lines 96–118, 255–269; SUP-04 |
| C-47 | Image referenced by mutable tag, rewritten with `sed` at deploy | MEASURED | `.github/workflows/deploy.yml` line 200; SUP-05 |
| C-48 | `validator-keys-tool` pinned to commit `05742108…` | MEASURED | `cmake/RippledValidatorKeys.cmake` lines 9, 15; SUP-06; verified live via API |
| C-49 | Entrypoint performs no integrity check before exec | MEASURED | `scripts/docker-entrypoint.sh`; SUP-08 |
| C-50 | Validators disable pathfinding (`PATH_SEARCH_MAX = 0`) | MEASURED | `Config.cpp` line 679; CFG-01 |

## Coverage

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-60 | 12 stages: 1 covered, 3 partial, 8 gaps | MEASURED | `scripts/harness/coverage.py`; `outputs/coverage.json` |
| C-61 | 31/31 inventory checks pass; 28/28 model cases pass (6+7+7+8) | MEASURED | `outputs/run_all.log`; `outputs/*.json` |
| C-62 | Fresh-clone reproduction is byte-identical (see comparison) | MEASURED | `outputs/reproduction/COMPARISON.md`; `scripts/clean_reproduce.sh` |

## Findings and plans

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-70 | 13 findings: 1 Critical, 4 High, 5 Medium, 2 Low, 1 Informational | ANALYSIS | `findings/findings-register.md` (severities are assessed judgement) |
| C-71 | Staged plan Stages 0–4 with exit criteria | ANALYSIS | `docs/migration-plan.md` |
| C-72 | Priorities and unresolved dependencies | ANALYSIS | `docs/decision-memo.md` |

## Specifications

| # | Claim | Label | Evidence |
|---|---|---|---|
| C-80 | UEFI 2.10 ch. 32 defines the PK/KEK/db/dbx hierarchy | MEASURED (spec) | UEFI 2.10, Chapter 32; `PINNED-SOURCES.md` |
| C-81 | PCR extend rule: PCR_new = H(PCR_old \|\| digest) | MEASURED (spec) | TCG TPM 2.0 Library Part 1, Rev 01.59 |
| C-82 | PCR assignments (0 firmware, 4 boot manager, 7 Secure Boot policy, 8–15 OS) | MEASURED (spec) | TCG PC Client Platform Firmware Profile v1.06 rev 52 |
| C-83 | SP 800-155 is a draft, retired 2024-10-25; SP 1800-34 is the live successor guidance | MEASURED (spec) | NIST CSRC publication pages; `PINNED-SOURCES.md` |
| C-84 | ML-KEM / ML-DSA / SLH-DSA are FIPS 203 / 204 / 205 (Aug 2024) | MEASURED (spec) | NIST FIPS 203/204/205 |
| C-85 | RATS roles: Attester, Verifier, Relying Party, Endorser, Reference Value Provider | MEASURED (spec) | IETF RFC 9334 |
