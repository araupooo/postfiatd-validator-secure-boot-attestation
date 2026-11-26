# Decision memo — validator secure boot and attestation

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
All claims are labelled MEASURED, SIMULATED, or UNTESTABLE; see
`docs/claim-evidence-index.md` for the per-claim evidence.

## Bottom line

[ANALYSIS] The validator trust chain is currently a signatures-only
chain: a validator is trusted because its manifest signatures verify,
and the network has no way to know whether the host that produced them
was booted cleanly. That is a defensible design for a small,
operator-run network, but it is not a secure-boot or attestation design,
and it should not be described as one. The single highest-value change
is Stage 1 (measured boot + remote attestation); the single cheapest
change with immediate effect is Stage 0 (key hygiene, UNL anchor fix,
image signing).

## Priorities

1. **Fix the UNL anchor first (F-04).** [ANALYSIS] One publisher key
   and one site, with the mainnet file pointing at a testnet URL, is
   the most fragile single point in the network's trust configuration.
   It is also the cheapest to fix: correct the URL, add a second
   publisher, raise the threshold. No hardware, no protocol change.
2. **Get master keys offline (F-02).** [ANALYSIS] The master key is the
   identity, it is plaintext JSON, and it is deleted on container
   restart — the operational pattern that most often produces both loss
   and theft. Offline storage plus the token-only path removes the
   largest present-day compromise surface.
3. **Sign and pin images (F-06).** [ANALYSIS] An unsigned, mutable-tag
   image plus an unverified boot means a supply-chain compromise is
   undetectable end to end. Digest pinning + cosign closes the
   cheapest injection path.
4. **Measured boot + attestation (F-01).** [ANALYSIS] This is the
   structural fix and the subject of this assessment. It needs hardware
   inventory first — do not buy or deploy attestation software before
   knowing which hosts have a TPM 2.0.
5. **Sealing (F-02 remainder, F-13).** Only after Stage 1, and only
   under a signed-policy design. Sealing to raw PCR values will brick
   validators on the first firmware update.
6. **Post-quantum (F-03).** Longest horizon; start the design and the
   network conversation now, ship nothing unilaterally.

## What this assessment proves and what it does not

- [MEASURED] The pinned tree contains no TPM, Secure Boot, SGX, SEV,
  enclave, measured-boot, PCR, UEFI, or HSM code (ATT-01, 1,947 paths
  scanned). The validator's only trust anchors are manifest signatures
  and the validator list.
- [MEASURED] Validator signing is secp256k1-only; manifests are
  two-tier with monotonic sequences and terminal revocation at
  0xFFFFFFFF; tokens carry a 32-byte secret; the mainnet UNL file
  trusts one publisher and a testnet URL.
- [SIMULATED] The harness shows a measured-boot + quote + sealing
  design behaving correctly across 28 model cases (6 PCR, 7 quote,
  7 seal, 8 manifest), including the failure modes that matter:
  tampering, replay, narrowed PCR selection, forged authorization,
  stale golden values, and firmware-update brittleness.
- [UNTESTABLE] Whether any actual validator host has a TPM 2.0, has
  Secure Boot enabled, or would produce a valid quote. That requires
  host access and hardware that was not available to this assessment.
- [UNTESTABLE] The real-world performance cost of TDX/SEV-SNP for a
  validator workload, and the real host inventory. Stage 3 exists to
  answer these with measurements, not opinions.

## Unresolved dependencies

1. **Host hardware inventory (UNTESTABLE).** The tree and the deploy
   workflow do not record TPM presence, firmware versions, or Secure
   Boot state for any validator host. Stage 1 cannot start without it.
2. **Operator control.** Validator hosts are third-party (Vultr) VMs
   provisioned by GitHub Actions. Whether the operator can enable
   Secure Boot / TPM 2.0 / confidential computing on those hosts is a
   property of the hosting contract, not of the code — it must be
   confirmed with the provider.
3. **Protocol change for PQ (F-03, Stage 4).** A hybrid manifest
   format is a consensus-level change. It needs agreement across
   implementations and operators and a testnet trial; no single
   operator can ship it.
4. **Cryptography supply for PQ.** ML-DSA / ML-KEM support in the C++
   build (liboqs or an OpenSSL provider) has not been evaluated
   against this tree. FIPS 203/204/205 standardize the algorithms;
   integration effort is still unknown.
5. **Reference-value governance (F-12).** Who publishes golden PCR
   values, who signs them, and how updates re-enroll them is an
   operational decision that does not exist yet.
6. **Enclave suitability (Stage 3).** Whether a long-running,
   network-facing validator daemon is a good fit for SGX vs TDX vs
   SEV-SNP is an open evaluation question, not a foregone conclusion.

## What not to do

- Do not seal secrets to raw PCR values (F-13): the first firmware
  update will brick the validator.
- Do not describe the current domain attestation as hardware evidence
  (F-09): it is a hosted file.
- Do not adopt an enclave design before measuring its cost on the
  validator workload (Stage 3).
- Do not ship a unilateral PQ manifest format (Stage 4): it is a
  network-level change.

## Sources

Pinned postfiatd source (see `PINNED-SOURCES.md` and
`evidence/pinned-tree-manifest.json`); TCG TPM 2.0 Library Parts 1 and
3; TCG PC Client Platform Firmware Profile v1.06 rev 52; UEFI 2.10
ch. 32; NIST SP 800-155 (draft, retired 2024-10-25) and SP 1800-34;
RFC 9334; NIST FIPS 203/204/205.
