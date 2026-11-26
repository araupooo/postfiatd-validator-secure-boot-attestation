# Findings register — validator secure boot and attestation

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
Severity is assessed from exploitability and impact on the validator
trust chain; it is ANALYSIS, not a measured quantity. Evidence pointers
are MEASURED (pinned source) or SIMULATED (harness models). No finding
claims a hardware measurement that was not performed.

Counts: 1 Critical, 4 High, 5 Medium, 2 Low, 1 Informational.

## F-01 — CRITICAL — No measured boot or remote attestation anywhere in the validator stack

- Affected assets: every validator host; the boot chain (firmware →
  bootloader → kernel → container → postfiatd → config); the validator
  identity itself, which runs on unverified software.
- Prerequisites: none. The gap is architectural: there is no mechanism
  to detect a compromised boot at all.
- Impact: a firmware or bootloader compromise (including a malicious
  image pushed through the unsigned deploy path, F-06) is invisible to
  the network. A compromised validator keeps signing validations with a
  valid manifest; peers have no evidence channel that would distinguish
  it from a healthy validator. Detection depends entirely on out-of-band
  operator vigilance.
- Evidence (MEASURED): zero TPM / Secure Boot / SGX / SEV / enclave /
  measured-boot / PCR / UEFI / HSM paths in 1,947 tree paths
  (inventory check ATT-01); no quote, AK enrollment, verifier, or
  golden reference values in the tree or deployment (S-7).
- Model (SIMULATED): `outputs/pcr_model.json` 6/6 — a measured boot
  would catch tampering (PCR-FM1) and a truncated log (PCR-FM3);
  `outputs/quote_verify.json` 7/7 — a verifier would reject tampered,
  replayed, and mis-selected quotes.
- Fix: Stage 1–2 of `docs/migration-plan.md` (measured boot + quote
  verification, then PCR sealing).

## F-02 — HIGH — Validator master keys live as plaintext JSON, deleted on container restart

- Affected assets: validator master keys (`validator-keys.json`);
  every validator identity.
- Prerequisites: access to the host filesystem, the container, a backup
  copy, or the CI/host channel over which the file is copied.
- Impact: the master key is the permanent validator identity. Anyone
  who obtains it can issue manifests (including revocation) for that
  validator forever, until revocation — and revocation itself destroys
  the identity (F-03). The file's lifecycle makes loss likely as well:
  it is deleted on every container restart/recreate, so operators keep
  copies in "secure locations" and shuttle them with `docker cp` / `scp`,
  multiplying the copies and the exposure.
- Evidence (MEASURED): `docs/ValidatorKeyUpdate.md` lines 16, 207–209
  (deleted on restart/recreate); lines 23–24, 40–44 (`docker cp` /
  `scp` workflow); `docs/DomainAttestation.md` lines 34–44 (same
  shuttle for domain setup). No sealing or HSM binding exists (ATT-01).
- Model (SIMULATED): `outputs/seal_model.json` SEAL-FM4 — a sealed blob
  copied to a different platform refuses unseal; the current plaintext
  file has no such property.
- Fix: Stage 0 (offline master keys, encrypted backups, no plaintext
  copies on networked hosts) and Stage 2 (PCR-sealed ephemeral secret;
  master key never leaves an offline/air-gapped store).

## F-03 — HIGH — Validator identity is secp256k1-only; revocation is terminal, with no post-quantum path

- Affected assets: validator master keys, manifests, validations,
  validator-list publisher signatures.
- Prerequisites: a cryptographically relevant quantum computer (for the
  PQ aspect — future, not present); or a master-key compromise (present-day).
- Impact: all validator authentication rests on ECDSA-secp256k1
  (`ValidatorKeys.cpp` lines 47, 84, 85). There is no hybrid or
  post-quantum signature anywhere. Separately, the only response to a
  master-key compromise is a revocation manifest at sequence
  0xFFFFFFFF, which permanently kills that validator identity — there
  is no re-key path for the same master key, so a compromised validator
  must re-establish its identity and trust from scratch.
- Evidence (MEASURED): secp256k1-only (KEY-01); revocation at
  0xFFFFFFFF (`Manifest.cpp` lines 226–240; `Manifest.h` lines 71–76).
- Model (SIMULATED): `outputs/manifest_model.json` MAN-REV / MAN-FM5 —
  revocation is accepted and terminal in the model.
- Fix: Stage 4 of `docs/migration-plan.md` (hybrid ML-DSA manifests;
  protocol-level change, needs network agreement).

## F-04 — HIGH — Single validator-list publisher trust anchor; mainnet file points at a testnet list URL

- Affected assets: the UNL — every node's view of which validators to
  trust.
- Prerequisites: compromise of the single publisher key, or of the
  single list site, or a DNS/transport attack on the single URL.
- Impact: the mainnet file trusts one site
  (`https://postfiat.org/testnet_vl.json`) and one publisher key, with
  computed threshold 1. One key compromise or one site compromise can
  feed a malicious validator list to every node using this file. The
  URL itself is a testnet list in the mainnet file, so mainnet nodes
  are (at best) trusting the wrong list, or (at worst) the file is a
  copy-paste error that nobody validated.
- Evidence (MEASURED): `cfg/validators-mainnet.txt` lines 56–59
  (UNL-01, UNL-02); threshold computation `ValidatorList.cpp`
  lines 202–212.
- Fix: Stage 0 — correct the URL, add a second independent publisher
  and site, raise the threshold to 2-of-2 (or 2-of-3 with a third
  publisher).

## F-05 — HIGH — Validator tokens are injected from CI secrets over SSH, selected by host IP

- Affected assets: validator ephemeral signing secrets (12 tokens
  across devnet/testnet/ai-devnet); the SSH deploy key.
- Prerequisites: access to the CI secrets store, the GitHub Actions
  run, the SSH key, or any host that receives a token.
- Impact: each token contains a 32-byte validation secret — the live
  signing key for a validator. Tokens transit GitHub Secrets → Actions
  runner → SSH → host, and are selected by host IP in a `case`
  statement, so a wrong-IP mapping or a compromised runner/SSH key
  hands a live signing secret to the wrong party. Tokens persist in
  config on the host and in CI logs' blast radius. Rotation exists
  (`create_token`) but nothing in the workflow rotates tokens
  automatically or detects a leaked one.
- Evidence (MEASURED): `.github/workflows/deploy.yml` lines 96–118
  (SSH action, token secrets, SSH key), 255–269 (per-host-IP token
  selection) (SUP-04).
- Fix: Stage 0 — move tokens to a secrets manager with short-lived
  credentials, inject at container start (not via CI env), audit token
  use, rotate on every deploy.

## F-06 — MEDIUM — Container image is unsigned, referenced by mutable tag, built from an unpinned toolchain

- Affected assets: the postfiatd binary and config on every deployed node.
- Prerequisites: write access to the image registry/tag, or a
  supply-chain compromise of any unpinned toolchain input.
- Impact: the deployed image is referenced by a mutable tag rewritten
  with `sed` at deploy time; nothing verifies the image digest, and
  nothing signs it (no cosign, no `@sha256` anywhere). The build itself
  pulls unpinned inputs (`apt update`, `pipx install conan`, a CMake
  tarball). A tampered image or toolchain input reaches validators
  with no check — and, per F-01, nothing at boot would notice.
- Evidence (MEASURED): `Dockerfile` lines 17, 33–48, 61 (SUP-01,
  SUP-02); no cosign/`@sha256` in Dockerfile, deploy workflow, or
  deployment docs (SUP-03); tag rewrite at `deploy.yml` line 200
  (SUP-05); no pre-exec integrity check in the entrypoint (SUP-08).
- Fix: Stage 0 — pin base image and toolchain by digest, sign images
  (cosign/Sigstore), deploy by digest, verify the digest in the
  entrypoint before exec.

## F-07 — MEDIUM — Fresh peers accept a stale manifest on first sighting (rollback window)

- Affected assets: any validator identity whose ephemeral key was
  rotated or compromised.
- Prerequisites: possession of an old, validly signed manifest (e.g.
  from a compromised ephemeral key) and a peer that has never seen a
  manifest for that master key.
- Impact: sequence monotonicity only protects peers that already hold
  a newer manifest. A fresh peer (new node, wiped cache) accepts any
  valid sequence on first sighting — including a superseded one — so a
  stolen ephemeral key remains usable against fresh peers until they
  learn the newer manifest. The window is bounded by gossip, not by
  any freshness proof.
- Evidence (MEASURED): `Manifest.cpp` lines 400–460 (first-entry path
  of `ManifestCache::applyManifest`); monotonicity rule at line 411
  (MFT-03).
- Model (SIMULATED): `outputs/manifest_model.json` MAN-FM4 — a fresh
  cache accepts the stale sequence-1 manifest.
- Fix: Stage 1 — publish manifests with freshness evidence (quote-bound
  manifest publication); Stage 0 — ship a pinned minimum-sequence list
  with the node image so fresh peers start from a known floor.

## F-08 — MEDIUM — `[validation_seed]` path stores the master-equivalent seed in config, with no manifest indirection

- Affected assets: any validator configured with `[validation_seed]`.
- Prerequisites: read access to the config file (host, backup, image
  layer, CI).
- Impact: the seed derives the validation key pair directly and sets
  manifest sequence 0. Whoever reads the seed owns the validator
  identity outright — there is no ephemeral key to rotate and no
  revocation short of abandoning the identity. The seed format is a
  human-memorable phrase or base58 string sitting in a config file.
- Evidence (MEASURED): `ValidatorKeys.cpp` lines 72–91 (KEY-03);
  `cfg/postfiatd-mainnet-full.cfg` lines 700–711.
- Fix: Stage 0 — deprecate the seed path for production validators;
  require the token path with an offline master key.

## F-09 — MEDIUM — Domain attestation is a hosted file, unbound to boot state

- Affected assets: validator domain claims; the trust users place in a
  named validator.
- Prerequisites: control of the domain's web root (or a compromise of
  the validator host, which also controls the web root).
- Impact: `.well-known/pft-ledger.toml` proves control of a web server,
  not the integrity of the validator. A compromised host serves the
  file and keeps its domain claim; a compromised web host can claim a
  domain it does not validate with. The domain field in the manifest is
  the only binding, and it is asserted by the same key that benefits
  from it.
- Evidence (MEASURED): `docs/DomainAttestation.md` lines 3, 11, 15–24
  (OPS-04).
- Fix: Stage 1 — bind the domain claim to a fresh hardware quote
  (quote covers the manifest + domain), so the claim is only valid
  from a measured host.

## F-10 — MEDIUM — Validator list sites may be plain HTTP

- Affected assets: the UNL fetch path.
- Prerequisites: a network position between a node and its list site.
- Impact: `ValidatorSite` accepts `http` as well as `https` for list
  sites, and the example file documents an `http://127.0.0.1:8000`
  site. The list itself is signature-checked (UNL-03), so a
  network attacker cannot forge a list — but they can block, delay,
  or replay stale lists, and any future weakening of the signature
  check would immediately become exploitable over plaintext transport.
  Plain HTTP also leaks which lists a node fetches and when.
- Evidence (MEASURED): `ValidatorSite.cpp` lines 65–68, 520–535
  (UNL-05); `cfg/validators-mainnet.txt` lines 17–31.
- Fix: Stage 0 — require `https` (or `file://`) for list sites;
  reject `http` except loopback.

## F-11 — LOW — Revocation distribution depends on gossip, with no out-of-band channel

- Affected assets: compromised validator identities and publishers.
- Prerequisites: a compromised key whose revocation manifest has not
  yet reached some peers.
- Impact: revocation only takes effect when the revocation manifest
  reaches a peer through the normal gossip path. There is no CRL,
  OCSP-like, or out-of-band distribution, and no deadline after which
  a manifest must be re-validated. A partitioned or slow peer keeps
  trusting a revoked key indefinitely.
- Evidence (MEASURED): revocation handled inside
  `ManifestCache::applyManifest` (`Manifest.cpp` lines 438–444) and
  publisher revocation in `ValidatorList.cpp` lines 1392–1397 (UNL-04);
  no other distribution channel exists in the tree.
- Fix: Stage 1 — a revocation feed with freshness deadlines; peers
  refuse manifests older than a configured age without re-validation.

## F-12 — LOW — No golden reference values and no integrity event-log retention

- Affected assets: the ability to detect, investigate, and prove a
  boot compromise after the fact.
- Prerequisites: none — the capability simply does not exist.
- Impact: even if measured boot were enabled tomorrow, there are no
  published golden PCR values, no reference-value provider, and no
  retention requirement for boot event logs. Log shipping to Loki is
  observability: logs are unsigned, unmeasured, and mutable. A
  compromise could be undetectable in retrospect because the evidence
  was never collected or was collected in a forgeable form.
- Evidence (MEASURED): no reference values or log-retention rules in
  the tree or deployment docs (ATT-01); Promtail/Loki shipping in
  `docs/DeploymentWorkflows.md`.
- Model (SIMULATED): `outputs/pcr_model.json` — golden values exist
  only inside the model; `outputs/quote_verify.json` Q-FM6 — a genuine
  quote against stale golden values is rejected, showing why
  reference-value lifecycle management matters.
- Fix: Stage 1 — publish and version golden values; retain signed
  event logs; define the re-enrollment procedure for updates.

## F-13 — INFORMATIONAL — PCR sealing is brittle without a signed-policy path (model result)

- Affected assets: any future sealed validator secret.
- Prerequisites: a firmware or bootloader update (routine).
- Impact: sealing a secret to raw PCR values makes every legitimate
  update unsealable — the sealed secret becomes unrecoverable until
  re-sealed. This is a design constraint for Stage 2, not a current
  vulnerability: there is nothing sealed today.
- Evidence (SIMULATED): `outputs/seal_model.json` SEAL-FM2 (update
  refuses unseal) vs SEAL-FM3 (authority-signed policy digest releases
  it) and SEAL-FM6 (forged authority signature refuses).
- Fix: Stage 2 — seal under a signed-policy (PolicyAuthorize) design
  from the start; never seal to raw PCR values alone.

## Cross-reference

| Finding | Inventory | Model output |
|---|---|---|
| F-01 | inventory/boot-chain-inventory.md | outputs/pcr_model.json, outputs/quote_verify.json |
| F-02 | inventory/attestation-surfaces.md S-2 | outputs/seal_model.json |
| F-03 | inventory/attestation-surfaces.md S-1 | outputs/manifest_model.json |
| F-04 | inventory/attestation-surfaces.md S-4 | — (source fact) |
| F-05 | inventory/attestation-surfaces.md S-6 | — (source fact) |
| F-06 | inventory/attestation-surfaces.md S-6 | outputs/pcr_model.json (PCR 10) |
| F-07 | inventory/attestation-surfaces.md S-1 | outputs/manifest_model.json MAN-FM4 |
| F-08 | inventory/attestation-surfaces.md S-3 | — (source fact) |
| F-09 | inventory/attestation-surfaces.md S-5 | outputs/quote_verify.json |
| F-10 | inventory/attestation-surfaces.md S-4 | — (source fact) |
| F-11 | inventory/attestation-surfaces.md S-1/S-4 | outputs/manifest_model.json MAN-REV |
| F-12 | inventory/boot-chain-inventory.md | outputs/pcr_model.json, outputs/quote_verify.json |
| F-13 | inventory/attestation-surfaces.md S-2 | outputs/seal_model.json |
