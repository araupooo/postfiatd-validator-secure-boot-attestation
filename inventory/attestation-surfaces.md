# Attestation surfaces — PostFiat validator at pinned postfiatd `0085a1ff`

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, 1.0.9).
Line numbers verified against `evidence/pinned-sources/` by
`scripts/harness/inventory_check.py` (31/31 pass).

## S-1. Validator manifest (two-tier key indirection)

- Design (MEASURED): a master secret key signs a manifest vouching for
  an ephemeral signing key, with a sequence number and a domain
  (`src/xrpld/app/misc/Manifest.h` lines 43–48, 60–76). The manifest
  carries the master public key, the ephemeral public key, the sequence,
  and the signatures (`Manifest.h` lines 82–99).
- Verification (MEASURED): `Manifest::verify()` requires both the
  ephemeral signing-key signature and the master-key signature
  (`src/xrpld/app/misc/detail/Manifest.cpp` lines 196–215).
- Sequence rule (MEASURED): a manifest is accepted only if its sequence
  is strictly greater than the stored one (`Manifest.cpp` line 411).
- Revocation (MEASURED): sequence `0xFFFFFFFF` (4,294,967,295) revokes
  the master key permanently; no higher sequence exists
  (`Manifest.cpp` lines 226–240; `Manifest.h` lines 71–76).
- Lifecycle model (SIMULATED): `scripts/harness/manifest_model.py`
  exercises rotation, replay rejection, tampered-signature rejection,
  first-sighting acceptance of a stale manifest, and terminal revocation
  with real secp256k1 ECDSA on fixed test keys (8/8 pass,
  `outputs/manifest_model.json`).
- Cryptography (MEASURED): validator keys are secp256k1 ECDSA only
  (`src/xrpld/app/misc/detail/ValidatorKeys.cpp` lines 47, 84, 85);
  no Ed25519 use in the validator-key path, no post-quantum signature.

## S-2. Validator token (what the server actually holds)

- Format (MEASURED): base64 JSON with `manifest` and a 32-byte
  `validation_secret_key` (`Manifest.cpp` lines 264–300, `loadValidatorToken`).
- Loading (MEASURED): the token path derives the public key from the
  secret and rejects the token unless it equals the manifest signing
  key (`ValidatorKeys.cpp` lines 43–61); a bad token is a fatal config
  error (lines 67–70).
- Rotation (MEASURED, documented): `validator-keys create_token`
  issues a new token; `set_domain` also rotates the signing key
  (`docs/ValidatorKeyUpdate.md` lines 104, 109–116); documented
  rotation cadence is every 6–12 months (line 81).
- Key storage (MEASURED): the master key file `validator-keys.json`
  is DELETED whenever the container is restarted or recreated
  (`docs/ValidatorKeyUpdate.md` lines 16, 207–209) and must be copied
  back in with `docker cp` / `scp` (lines 23–24, 40–44). The file is
  plaintext JSON; no sealing, no HSM/KMS binding exists anywhere in
  the tree (ATT-01).
- Sealing model (SIMULATED): `scripts/harness/seal_model.py` shows a
  PCR-policy seal releasing the secret only on the matching boot state,
  refusing on tampered boot, on a firmware update without re-authorization,
  and on a different platform — and releasing on an update when the new
  policy digest carries a valid authority signature (PolicyAuthorize
  model), but not when that signature is forged (7/7 pass,
  `outputs/seal_model.json`).

## S-3. Seed path (alternative to the token)

- Behaviour (MEASURED): `[validation_seed]` derives the key pair
  directly from the seed and sets manifest sequence 0
  (`ValidatorKeys.cpp` lines 72–91). There is no manifest indirection:
  whoever holds the seed holds the validator identity, and rotation
  means a new identity. The example seed format is documented in
  `cfg/postfiatd-mainnet-full.cfg` lines 700–711.

## S-4. Validator list (UNL) trust anchor

- Trust anchor (MEASURED): the mainnet file trusts exactly one list
  site (`https://postfiat.org/testnet_vl.json`) and one publisher key
  (`ED6B26F2...`, 66 hex chars with the Ed25519 `ED` prefix), with
  `[validator_list_threshold]` 0, i.e. computed threshold 1
  (`cfg/validators-mainnet.txt` lines 56–59, 71–86; `ValidatorList.cpp`
  lines 202–212). Note the mainnet file points at a *testnet* list URL.
- List verification (MEASURED): a fetched list is accepted only if its
  signature verifies against the publisher manifest's signing key
  (`src/xrpld/app/misc/detail/ValidatorList.cpp` lines 1404–1407,
  applied at line 1166).
- Publisher revocation (MEASURED): a revoked publisher manifest removes
  its list and clears pending lists (`ValidatorList.cpp` lines 1392–1397).
- Transport (MEASURED): list sites may be plain `http` as well as
  `https` (`src/xrpld/app/misc/detail/ValidatorSite.cpp` lines 65–68
  and redirect handling at lines 520–535); the example file even lists
  `http://127.0.0.1:8000` as a site.

## S-5. Domain attestation

- Mechanism (MEASURED): a file hosted at
  `https://<domain>/.well-known/pft-ledger.toml`
  (`docs/DomainAttestation.md` lines 3, 11); the validator's domain
  status is read via the `validator_info` RPC (lines 15–24). The domain
  is baked into the manifest by `set_domain` (lines 58–60).
- Binding (MEASURED): none to boot state. A compromised host can serve
  the file; the check proves control of the web root, not the integrity
  of the validator. No hardware evidence is involved.

## S-6. Deployment and supply chain

- Image build (MEASURED): `Dockerfile` — base `ubuntu:24.04` by tag
  (line 17), unpinned toolchain (`apt update`, `pipx install conan`,
  CMake 3.25.1 tarball, lines 33–48), Conan `--build missing` (line 61),
  config copied by network/size build args (lines 89–90). No image
  signing or digest pinning anywhere (SUP-03).
- Deploy (MEASURED): `.github/workflows/deploy.yml` runs over SSH
  (`appleboy/ssh-action@v1.2.0`, line 96) with `VULTR_SSH_KEY`; 12
  validator-token secrets are passed as environment variables
  (lines 100–118); the token for a host is selected by host IP in a
  `case` statement (lines 255–269); the image tag is rewritten with
  `sed` (line 200). `update.yml` pulls the latest tag and restarts.
- Entrypoint (MEASURED): `scripts/docker-entrypoint.sh` starts cron
  and logrotate, then execs postfiatd with no integrity check of the
  binary or config first (SUP-08).
- Key tooling (MEASURED): `validator-keys-tool` is pinned to commit
  `05742108d4b7c0b7d9a97c073acd690d2c75a2b4` via FetchContent
  (`cmake/RippledValidatorKeys.cmake` lines 9, 15) — the one pinned
  external dependency in the build.
- Logging (MEASURED): Promtail ships logs to Loki
  (`docs/DeploymentWorkflows.md`); log shipping is observability, not
  integrity evidence — logs are not signed or measured.

## S-7. Remote attestation (TPM quote / enclave report)

- Present state (MEASURED): absent. No TPM quote, no AK enrollment, no
  verifier, no reference (golden) values, no enclave report handling
  anywhere in the tree or the deployment (ATT-01).
- What it would look like (SIMULATED): `scripts/harness/quote_verify.py`
  models TPM2_Quote verification — AK signature, fresh nonce, PCR
  selection, PCR digest, golden-value comparison — with 7/7 cases passing,
  including rejection of tampered signatures, replayed (stale-nonce)
  quotes, wrong PCR values, non-enrolled AKs, narrowed PCR selection,
  and genuine quotes against stale golden values
  (`outputs/quote_verify.json`).

## Surface summary

| Surface | Authenticated? | Hardware-bound? | Revocable? | Gap |
|---|---|---|---|---|
| Manifest | Yes (secp256k1 ×2) | No | Yes (seq 0xFFFFFFFF, terminal) | No PQ, fresh-peer rollback window |
| Validator token | Yes (via manifest) | No | Yes (rotate) | Plaintext secret in CI + config |
| Master key file | No | No | No (loss = identity loss) | Plaintext JSON, deleted on restart |
| Validator list | Yes (publisher sig) | No | Yes (publisher revocation) | Single publisher, testnet URL in mainnet file, http allowed |
| Domain attestation | Weak (web file) | No | Yes (rotate) | No boot binding |
| Container image | No | No | n/a | Mutable tag, no signing |
| Remote attestation | n/a | n/a | n/a | Absent entirely |
