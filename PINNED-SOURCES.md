# Pinned sources

## Assessed repository

| Item | Value |
|---|---|
| Repository | postfiatorg/postfiatd |
| Pinned commit (LIVE main HEAD at build start) | `0085a1ff885d6a446369cf73a4430f75af22be55` |
| Commit date | 2026-10-10T16:53:26Z |
| Commit subject | Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9 — 1.0.9: backport the upstream 3.4.1 payment engine overflow fix |
| Tree size | 1,947 paths |
| Pin method | GitHub API `GET /repos/postfiatorg/postfiatd/commits/main` at build start, 2026-11-26; re-fetched live, not carried over from an earlier pin (the same commit was already HEAD) |
| Vendored evidence | `evidence/pinned-sources/` — verbatim copies of the 21 cited files; each file verified against the pinned tree by git blob SHA-1 and size (see `evidence/pinned-tree-manifest.json`); full path list in `evidence/pinned-tree-paths.txt` |

## Vendored files (all at the pinned commit)

See `evidence/pinned-tree-manifest.json` for the per-file blob SHA-1,
byte size, and SHA-256. Files: `src/xrpld/app/misc/detail/ValidatorKeys.cpp`,
`src/xrpld/app/misc/ValidatorKeys.h`, `src/xrpld/app/misc/detail/Manifest.cpp`,
`src/xrpld/app/misc/Manifest.h`, `src/xrpld/app/misc/detail/ValidatorList.cpp`,
`src/xrpld/app/misc/detail/ValidatorSite.cpp`, `src/xrpld/core/detail/Config.cpp`,
`src/libxrpl/protocol/Sign.cpp`, `include/xrpl/protocol/Seed.h`,
`include/xrpl/protocol/SecretKey.h`, `docs/ValidatorKeyUpdate.md`,
`docs/DeploymentWorkflows.md`, `docs/DomainAttestation.md`, `docs/Docker.md`,
`docs/build/install.md`, `Dockerfile`, `scripts/docker-entrypoint.sh`,
`cfg/validators-mainnet.txt`, `cfg/postfiatd-mainnet-full.cfg`,
`cmake/RippledValidatorKeys.cmake`, `.github/workflows/deploy.yml`.

## External dependency pin (in-tree)

| Item | Value |
|---|---|
| validator-keys-tool | Fetched by CMake FetchContent, pinned to commit `05742108d4b7c0b7d9a97c073acd690d2c75a2b4` (2025-09-05, "Update rippled version and remove reference to Ripple's defunct Conan recipies. (#58)") — `cmake/RippledValidatorKeys.cmake` lines 9, 15. Verified live via the GitHub API at build time. |

## Vendor specifications relied on

| Specification | Version / status | Used for |
|---|---|---|
| TCG TPM 2.0 Library, Part 1: Architecture | Level 00 Rev 01.59 (Nov 2019), errata v1.4 (Jan 2023) | PCR extend rule ("the only way to change a PCR value is to Extend it"), TPM architecture |
| TCG TPM 2.0 Library, Part 3: Commands | Level 00 Rev 01.59 | TPM2_Quote, TPM2_PCR_Extend, TPM2_PCR_Read, TPM2_Create / TPM2_PolicyPCR / TPM2_Unseal / TPM2_PolicyAuthorize |
| TCG PC Client Platform Firmware Profile for TPM 2.0 | v1.06 rev 52 (Dec 2023) | PCR assignments: 0 firmware code, 1 platform config, 2/3 pluggable code, 4 boot manager code, 5 boot config/GPT, 7 Secure Boot policy, 8–15 static OS |
| UEFI Specification | 2.10, Chapter 32 "Secure Boot and Driver Signing" | PK / KEK / db / dbx hierarchy, authenticated-variable update rules (§32.6.3, §8.2) |
| NIST SP 800-155, BIOS Integrity Measurement Guidelines | Draft, Dec 2011; RETIRED 2024-10-25 — cited as a draft, not as live guidance | Historical basis for BIOS measurement; its content was contributed to the TCG PC Client Firmware Integrity Measurement specification |
| NIST SP 1800-34, Validating the Integrity of Computing Devices | Current | Successor guidance for integrity validation (per the SP 800-155 retirement note) |
| NIST SP 800-147 / 800-147B, BIOS Protection Guidelines | Current | Authenticated BIOS update, root-of-trust update |
| IETF RFC 9334, Remote ATtestation procedureS (RATS) Architecture | Current | Attester / Verifier / Relying Party / Endorser / Reference Value Provider roles |
| NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) | Aug 2024 | Post-quantum key encapsulation (migration plan) |
| NIST FIPS 204, Module-Lattice-Based Digital Signature Algorithm (ML-DSA) | Aug 2024 | Post-quantum signatures (migration plan) |
| NIST FIPS 205, Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) | Aug 2024 | Post-quantum signatures, hash-based alternative (migration plan) |
| Intel SGX Developer Reference / Intel TDX Module Specification | Current | EREPORT-based enclave attestation; TD-Quote (evaluation only) |
| AMD SEV-SNP ABI Specification | Current | SNP_REPORT-based confidential-VM attestation (evaluation only) |

## What was NOT measured

No TPM, Secure Boot, SGX, TDX, or SEV-SNP hardware was present on the
build machine and none was used. All hardware-behaviour claims in this
pack are labelled SIMULATED (software models) or UNTESTABLE (would need
validator-host hardware). See `docs/methodology.md` and
`docs/claim-evidence-index.md`.
