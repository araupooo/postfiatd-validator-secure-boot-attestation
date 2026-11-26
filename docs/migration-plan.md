# Staged hardening and post-quantum migration plan

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
Findings cited as F-01…F-13 refer to `findings/findings-register.md`.

## Stage 0 — Immediate, no hardware (weeks)

Goal: remove the cheapest attacks with configuration and process changes only.

1. **Offline master keys (F-02, F-08).** Master keys live offline
   (air-gapped store or hardware wallet); only ephemeral signing
   secrets ever touch networked hosts. Deprecate `[validation_seed]`
   for production validators; require the `[validator_token]` path.
   Encrypt every `validator-keys.json` backup; inventory and delete
   stray copies; stop shuttling plaintext keys with `docker cp` / `scp`.
2. **Fix the UNL anchor (F-04, F-10).** Correct
   `cfg/validators-mainnet.txt` to point at the real mainnet list URL;
   add a second independent publisher and site; set
   `[validator_list_threshold]` to 2; reject `http://` list sites
   except loopback.
3. **Token handling (F-05).** Move validator tokens out of CI
   environment variables into a secrets manager with short-lived
   credentials; inject at container start; audit every token use;
   rotate tokens on every deploy and on any suspected exposure.
4. **Image provenance (F-06).** Pin the base image and every toolchain
   input by digest; sign built images (Sigstore/cosign); deploy by
   digest, never by mutable tag; verify the digest in the entrypoint
   before `exec`. Record the digest in the deploy log.
5. **Fresh-peer floor (F-07).** Ship a pinned minimum-manifest-sequence
   list with the node image so a fresh peer never accepts a manifest
   older than the shipped floor.
6. **Revocation runbook (F-03, F-11).** Document who can issue a
   revocation manifest, how fast it must propagate, and how a revoked
   validator re-establishes identity. Exercise it on a testnet validator.

Exit criteria: no plaintext master key on any networked host; two
independent UNL publishers; images deployed by digest; runbook exercised.

## Stage 1 — Measured boot and remote attestation (1–2 quarters, needs hardware)

Goal: make a compromised boot detectable, and give the network evidence
instead of trust.

1. **Hardware baseline.** Inventory every validator host: UEFI Secure
   Boot state, TPM 2.0 presence and firmware version, CPU
   confidential-computing support. Hosts without a TPM 2.0 are
   scheduled for replacement or for Stage 3 enclave hosting. (This
   inventory is UNTESTABLE from the build machine — it must be measured
   on the hosts.)
2. **Measured boot.** Enable UEFI Secure Boot with a custom db (operator
   keys, not only the vendor defaults); enable TPM 2.0 measured boot;
   record the boot event log. PCR assignments follow the TCG PC Client
   Platform Firmware Profile v1.06 rev 52 (PCR 0 firmware, 1 config,
   2/3 option ROM, 4 boot manager, 5 boot config, 7 Secure Boot policy,
   8–15 OS). The model in `scripts/harness/pcr_model.py` is the
   reference for the extend/replay semantics.
3. **Golden values.** Publish versioned golden PCR values per host
   class and firmware version (F-12); define the re-enrollment procedure
   for every firmware/kernel update (the model shows an update changes
   PCR 0 exactly like tampering — PCR-FM5).
4. **Attestation service (RATS roles, RFC 9334).** Enroll an Attestation
   Key per host (bound to the TPM Endorsement Key certificate);
   the verifier checks signature, fresh nonce, PCR selection, PCR
   digest, and golden values — exactly the checks modelled in
   `scripts/harness/quote_verify.py` (7/7 cases, including replay and
   narrowed-selection rejection). The Relying Party (the network /
   operators) consumes the attestation result, not the raw quote.
5. **Quote-bound domain claims (F-09).** A domain claim is only valid
   when accompanied by a fresh quote covering the manifest + domain.
6. **Revocation freshness (F-11).** A revocation feed with deadlines;
   peers refuse manifests older than the configured age without
   re-validation.

Exit criteria: every production validator produces a verifiable quote
on demand; golden values published and versioned; a compromised-boot
drill (tampered test image) is detected by the verifier.

## Stage 2 — Sealing (follows Stage 1)

Goal: the validator signing secret is unusable off the measured host.

1. **Seal the ephemeral signing secret** to the PCR policy
   (TPM2_Create with authPolicy, TPM2_PolicyPCR, TPM2_Unseal).
2. **Signed-policy design from the start (F-13).** Seal under a
   PolicyAuthorize policy: the authority signs new policy digests for
   legitimate updates, so an update does not brick the validator.
   The model in `scripts/harness/seal_model.py` demonstrates both the
   brittleness (SEAL-FM2) and the authorized path (SEAL-FM3, SEAL-FM6).
3. **Key release gated on a fresh quote:** the secret is released only
   after the host attests; release is logged.
4. **Recovery path:** define the break-glass procedure for a host whose
   TPM fails (re-seal from the offline master key; never store the
   secret in plaintext as a fallback).

Exit criteria: no validator signing secret exists in plaintext on any
host; an update drill (firmware bump + authorized policy) succeeds
without manual secret handling.

## Stage 3 — Enclave / confidential-computing evaluation

Goal: decide, with evidence, whether the validator process itself
should run inside a hardware enclave or confidential VM.

1. Evaluate Intel SGX (EREPORT-based attestation) and Intel TDX
   (TD-Quote), and AMD SEV-SNP (SNP_REPORT), against the validator's
   needs: the validator is a long-running, network-facing, I/O-heavy
   daemon, which is a poor fit for SGX enclaves and a better fit for
   TDX/SEV-SNP confidential VMs.
2. Measure the performance cost (consensus latency, I/O throughput)
   on representative hardware before any commitment.
3. Decision gate: adopt only if the measured cost is acceptable AND
   the deployment can actually provision TDX/SEV-SNP hosts. Otherwise
   stay at Stage 2 — a sealed TPM design is the better cost/benefit
   for this workload.

This stage is an evaluation, not a commitment. No enclave code is
proposed for the pinned tree until the evaluation reports.

## Stage 4 — Post-quantum migration (protocol-level, longest horizon)

Goal: validator authentication that survives a cryptographically
relevant quantum computer.

1. **Inventory (done in this pack).** All validator authentication is
   ECDSA-secp256k1 (F-03). Manifests, validations, and validator-list
   signatures all depend on it.
2. **Hybrid manifests.** Design a manifest format carrying both a
   classical (secp256k1) and a post-quantum (ML-DSA, FIPS 204)
   signature, with the rule that both must verify during migration.
   SLH-DSA (FIPS 205) is the hash-based fallback if lattice schemes
   are ever weakened; it is larger and slower, so ML-DSA is the
   primary candidate.
3. **Key transport.** Any future mechanism that moves keys to hosts
   uses ML-KEM (FIPS 203), not RSA/ECDH.
4. **Cryptography supply.** Evaluate liboqs / OpenSSL provider
   support for ML-DSA and ML-KEM in the C++ build before writing
   protocol code; the pinned tree has no PQ dependency today.
5. **Network agreement.** A manifest format change is a consensus /
   protocol change: it needs agreement across implementations and
   operators, a testnet trial, and a coordinated activation. It cannot
   be shipped unilaterally by one operator.
6. **Deprecation.** Only after hybrid manifests are live and widely
   adopted can classical-only manifests be deprecated — with a long
   notice period, because revocation is terminal for an identity
   (F-03) and a rushed cutover would strand validators.

Exit criteria: hybrid manifests on testnet; classical-only deprecation
timeline agreed; no validator depends solely on a quantum-vulnerable
signature for its identity.

## Sequencing summary

| Stage | Depends on | Removes |
|---|---|---|
| 0 — hygiene | Nothing | F-02 (partial), F-04, F-05, F-06, F-08, F-10 |
| 1 — measured boot + attestation | Host hardware inventory | F-01, F-09, F-11, F-12 |
| 2 — sealing | Stage 1 | F-02 (rest), F-13 |
| 3 — enclave evaluation | Stage 1 hardware | Evaluates residual risk only |
| 4 — post-quantum | Network agreement, crypto supply | F-03 |
