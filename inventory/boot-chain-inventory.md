# Boot-chain inventory — PostFiat validator at pinned postfiatd `0085a1ff`

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
All file paths are relative to that tree; line numbers were verified
against the vendored copies in `evidence/pinned-sources/` by
`scripts/harness/inventory_check.py` (31/31 checks pass; see
`outputs/inventory_check.json`).

Labels: MEASURED = verified against the pinned source. SIMULATED = shown
by the software models in `scripts/harness/`. UNTESTABLE = would need
validator-host hardware that was not available.

## The chain as deployed

| # | Stage | What runs / what exists | In-tree evidence (MEASURED) |
|---|---|---|---|
| 0 | Platform firmware (CRTM / BIOS/UEFI) | Unknown firmware on third-party hosts (Vultr); no inventory of hosts in the tree | No firmware, UEFI, or Secure Boot code in the tree (ATT-01: 0 attestation-related paths in 1,947) |
| 1 | UEFI Secure Boot policy (PK / KEK / db / dbx) | Platform property; never checked by postfiatd or the deployment | No Secure Boot code in the tree (ATT-01). Spec: UEFI 2.10 ch. 32 |
| 2 | Boot manager / kernel / initramfs | Ubuntu 24.04 container host; kernel not specified in-tree | No measured-boot code in the tree (ATT-01) |
| 3 | Container image | `Dockerfile` builds from `ubuntu:24.04` (line 17, by tag, no `@sha256` digest pin — SUP-01); toolchain fetched unpinned (`apt update`, `pipx install conan`, CMake 3.25.1 tarball — SUP-02); image referenced by mutable tag at deploy time via `sed` (`.github/workflows/deploy.yml` line 200 — SUP-05); no cosign / digest verification anywhere (SUP-03) |
| 4 | postfiatd binary | Built with Conan + CMake (`Dockerfile` lines 61–64); `validator-keys` target built alongside (line 64) | No pre-exec integrity check in `scripts/docker-entrypoint.sh` (SUP-08): entrypoint starts cron/logrotate and execs the binary |
| 5 | postfiatd config | `cfg/postfiatd-${NETWORK}-${NODE_SIZE}.cfg` copied into the image (`Dockerfile` lines 89–90); `[validation_seed]` and `[validator_token]` documented in `cfg/postfiatd-mainnet-full.cfg` lines 700–739; both set is a fatal error (`src/xrpld/core/detail/Config.cpp` lines 637–640; `ValidatorKeys.cpp` lines 31–37) |
| 6 | Validator identity | Master key in `validator-keys.json`; ephemeral signing key + manifest in the `[validator_token]` | See attestation surfaces |
| 7 | Network trust anchor | `cfg/validators-mainnet.txt` | Single list site + single publisher key (UNL-01); see below |

## What the tree measures: nothing

A full-tree path scan (1,947 paths) finds zero files related to TPM,
Secure Boot, SGX, SEV, enclaves, measured boot, PCRs, UEFI, or HSM
(inventory check ATT-01). The only "attestation" in the tree is
cross-chain bridge attestation (`include/xrpl/protocol/XChainAttestations.h`,
`src/libxrpl/protocol/XChainAttestations.cpp`) and a unit-test helper
(`src/test/jtx/attester.h`) — both unrelated to validator boot
attestation (ATT-02). The validator therefore boots on unverified
firmware, an unverified image, and an unverified config, and its only
trust anchors are the manifest signatures and the validator list.

## What a measured boot would add (SIMULATED)

`scripts/harness/pcr_model.py` replays the validator boot chain through
the TPM 2.0 extend rule (PCR_new = H(PCR_old || digest)) with PCR
assignments per the TCG PC Client Platform Firmware Profile v1.06 rev 52
(PCR 0 firmware, 1 config, 2 option ROM, 4 boot manager, 5 boot config,
7 Secure Boot policy, 9 kernel/initrd, 10 container image/binary/config).
Golden values (SHA-256):

- PCR 0: `55e0f3e900859954256bde81aff4cac3aa7919204bfe26e1059d486bf4a1b51d`
- PCR 4: `9b423ea7f7fecd81c3e30692e0c46285942dfdd6d6a662831ce18b827d23724c`
- PCR 7: `22b7b407600d173e7d5c706553f5533d4fa764c4f2cdfcce6cfd56b5051e7c18`
- PCR 10: `1c9811caa7402d5cf597786e53227f6378bd83ea5e3e0b599b6c5e31575aec00`

Failure modes demonstrated (6/6 pass in `outputs/pcr_model.json`):
tampered firmware changes PCR 0; reordered events within one PCR change
that PCR; a truncated log leaves PCR 10 different; a SHA-1 bank never
matches a SHA-256 golden value; a legitimate firmware update changes
PCR 0 exactly like tampering does (golden values must be re-enrolled).

## Gaps by stage

| Stage | Measured? | Attested? | Sealed? |
|---|---|---|---|
| Firmware | No | No | n/a |
| Secure Boot policy | No | No | n/a |
| Boot manager / kernel | No | No | n/a |
| Container image / binary | No | No | n/a |
| Config | No | No | n/a |
| Validator master key | No | No | No |
| Validator signing secret | No | No | No |
| Manifest / token | n/a | Signed (secp256k1), not hardware-bound | No |

Full stage-by-stage coverage is in `outputs/coverage.json`:
1 covered, 3 partial, 8 gaps out of 12 stages.
