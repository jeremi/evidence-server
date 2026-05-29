# Signing Key Provider Spec

## Status

Proposed. No production compatibility guarantee is required for the current
Notary configuration shape, so this spec intentionally uses a breaking config
cleanup. Current runtime still uses credential profile issuer key configuration
described in [Credential issuance guide](credential-issuance-guide.md).

## Purpose

Make Registry Notary signing simple, auditable, and ready for production key
management without forcing every deployment to use the same key backend.

The design keeps one stable application abstraction:

```rust
registry_platform_crypto::SigningProvider
```

Credential issuance should ask a provider to sign bytes. It should not know
whether the key came from a local JWK, a PKCS#11 token, a PKCS#12 file, or a
future KMS/remote signer.

## Background

Current Notary credential profiles carry private-key loading details directly:

```yaml
credential_profiles:
  civil_status_sd_jwt:
    issuer: https://notary.example.gov
    issuer_key_env: REGISTRY_NOTARY_ISSUER_JWK
    issuer_kid: did:web:notary.example.gov#issuer
```

At startup, `EvidenceIssuerRegistry::from_config` reads each profile's env var,
builds an `EvidenceIssuer` from the private JWK, and stores issuers by profile.
This works for local demos, but it couples credential profiles to one key
storage mechanism.

The better lower-level boundary already exists. `registry-platform-crypto`
defines `SigningProvider`, and `registry-platform-sdjwt` can build an issuer
with `SdJwtIssuer::from_signing_provider`. Registry Notary should expose that
boundary in config instead of exposing private-key env vars on profiles.

## Goals

- Replace profile-level `issuer_key_env` and `issuer_kid` with named signing
  keys.
- Keep local development easy with a first-class local JWK provider.
- Add a production-capable PKCS#11 provider for HSMs and SoftHSM tests.
- Add PKCS#12 support only as a local/import compatibility provider, not as the
  preferred production key-management story.
- Publish verifier metadata from the signing-key registry, not by re-reading
  private key material.
- Validate all signer/profile wiring at startup and fail closed.
- Keep crypto dependencies narrow, optional, and testable.

## Non-Goals

- No runtime production key generation by the Notary service.
- No general key-management API in Notary.
- No support for arbitrary PKCS#11 mechanisms before the SD-JWT and verification
  stack supports the matching algorithm.
- No remote signer, Vault, cloud KMS, or KMIP implementation in this change.
  The provider registry should make those easy later.
- No backward compatibility with `issuer_key_env`. Existing configs should be
  migrated.

## Design Principles

- Profiles describe credentials. Signing keys describe signing.
- A private key must not be printable through `Debug`, error messages, config
  dumps, metrics, traces, or audit events.
- A signer must expose its public verification key without exposing private key
  material.
- A signer must prove it can sign during startup readiness checks.
- Algorithm support is explicit. Config validation must reject algorithms that
  the issuer, verifier, and provider stack do not all support.
- Local convenience must be isolated from production semantics.

## Configuration

Add `signing_keys` under the existing `evidence` config block. Credential
profiles reference a key by id.

```yaml
evidence:
  signing_keys:
    notary-issuer-dev:
      provider: local_jwk_env
      private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
      alg: EdDSA
      kid: did:web:notary.example.gov#issuer-2026-05
      status: active

  credential_profiles:
    civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: https://notary.example.gov
      signing_key: notary-issuer-dev
      vct: https://registry.example.gov/credentials/civil-status
      validity_seconds: 600
```

Remove these fields from `CredentialProfileConfig`:

- `issuer_key_env`
- `issuer_kid`

Add:

- `signing_key: String`

### Local JWK Provider

Use this for demos, tests, and simple local deployment.

```yaml
signing_keys:
  notary-issuer-dev:
    provider: local_jwk_env
    private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
    alg: EdDSA
    kid: did:web:notary.example.gov#issuer-2026-05
    status: active
```

Rules:

- `private_jwk_env` must name a non-empty env var.
- The env var must contain a private JWK supported by
  `registry-platform-crypto`.
- The configured `kid` must be non-empty.
- If the private JWK contains `kid`, it must match the configured `kid`.
- The provider builder must set `jwk.kid = configured kid` and `jwk.alg =
  configured alg` before constructing `LocalJwkSigner`.
- The public JWK published for this key must use the configured `kid`.

### PKCS#11 Provider

Use this for HSMs and SoftHSM-backed local integration tests.

```yaml
signing_keys:
  notary-issuer-hsm:
    provider: pkcs11
    module_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: registry-notary
    pin_env: REGISTRY_NOTARY_PKCS11_PIN
    key_label: issuer-signing-key
    key_id_hex: "01ab23cd"
    alg: EdDSA
    kid: did:web:notary.example.gov#issuer-2026-05
    status: active
    public_jwk_env: REGISTRY_NOTARY_ISSUER_PUBLIC_JWK
```

Rules:

- Use the `cryptoki` crate for PKCS#11 access.
- Do not load private key material from PKCS#11.
- `pin_env` must name a non-empty env var. The PIN value must never be logged.
- `module_path`, `token_label`, `key_label`, `key_id_hex`, `alg`, and `kid`
  are required for active keys.
- `module_path` must be an absolute trusted deployment path. Do not support
  shell expansion, env expansion, or relative paths. Deployment docs must treat
  the PKCS#11 module as privileged native code and require non-writable module
  files and parent directories.
- Private-key lookup must filter by token, `CKO_PRIVATE_KEY`, `CKA_SIGN=true`,
  expected key type/curve, `CKA_LABEL`, and `CKA_ID`. Startup must reject zero
  matches or multiple matches.
- `public_jwk_env` is required in the first implementation. Reading the public
  object from the token can be added later if it stays simple and well-tested.
- `public_jwk_env` must contain a public-only JWK. It must not contain `d`; for
  EdDSA it must be `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, valid base64url
  fields, and a `kid` equal to the configured `kid`.
- Startup must sign a fixed self-test challenge and verify the signature with
  `public_jwk_env` for active keys.
- The provider is ready only after login, key lookup, mechanism validation, and
  self-test signature verification succeed.
- PKCS#11 operations are blocking FFI and must not run directly on Tokio worker
  threads. The first implementation may use a single serialized signing session
  protected by a mutex plus `spawn_blocking`, with a bounded request-time
  timeout. A later provider may replace this with a bounded session pool.
- Session handling must define login behavior per session, tolerate
  `CKR_USER_ALREADY_LOGGED_IN`, recreate invalid sessions where possible, fail
  closed on device removal, and call `C_Finalize` only during provider shutdown.

Why require `public_jwk_env` first: PKCS#11 public object extraction is
vendor-sensitive and can add parsing complexity. A configured public JWK plus a
startup self-test gives a simpler and more deterministic correctness check.

### PKCS#12 Provider

Use this only when an operator already has a `.p12`/`.pfx` bundle or when local
testing needs parity with systems that package keys that way.

```yaml
signing_keys:
  notary-issuer-p12:
    provider: local_pkcs12_file
    path: /run/secrets/notary-issuer.p12
    password_env: REGISTRY_NOTARY_PKCS12_PASSWORD
    alg: EdDSA
    kid: did:web:notary.example.gov#issuer-2026-05
    status: active
```

Rules:

- Treat PKCS#12 as local private-key loading, not HSM support.
- Prefer the `openssl` crate's PKCS#12 support for the first implementation if
  PKCS#12 signing is truly needed. The pure Rust `pkcs12` crate is promising
  but should not be assumed to cover all extraction/signing needs until verified
  with fixtures.
- The parsed private key must be converted into the same signer semantics as
  `LocalJwkSigner`.
- `path`, `password_env`, `alg`, and `kid` are required.
- Startup must fail if the archive has no supported private key or has
  ambiguous private keys.
- The provider builder must derive/export the raw public key, set or verify the
  configured `kid`, and perform a sign/verify self-test before serving.
- If a certificate is present, its public key must match the private key.
- Deployment docs must require secret-file permissions suitable for private key
  material.

PKCS#12 should be implemented after `local_jwk_env` and `pkcs11`, unless a real
operator integration requires it sooner.

## Algorithm Policy

Current `registry-platform-crypto` signing support is EdDSA only. The first
config migration should preserve that behavior:

```yaml
alg: EdDSA
```

For the first implementation, `EdDSA` has exactly one meaning:

| Config `alg` | JWK requirement | PKCS#11 mechanism | JWS signature bytes |
| --- | --- | --- | --- |
| `EdDSA` | `kty=OKP`, `crv=Ed25519` | `CKM_EDDSA`, Ed25519 scheme, no context, no prehash | 64-byte Ed25519 signature over the JWS signing input |

Do not accept `ES256`, `RS256`, or other values in Notary config until all of
these are true:

- `registry-platform-crypto::SigningAlgorithm` supports the algorithm.
- `registry-platform-sdjwt` can issue and verify the algorithm.
- Holder-proof and JWT header validation know the allowed algorithm.
- The selected provider can sign with the algorithm and has integration tests.
- JWKS publication emits a standards-compliant public JWK for the algorithm.

If common HSMs require `ES256` before Ed25519 is practical, add `ES256` as a
separate, tested algorithm-expansion change. Do not hide that inside the
PKCS#11 provider change.

## Runtime Model

Startup builds a signing-key registry:

```rust
pub struct SigningKeyRegistry {
    providers: BTreeMap<String, Arc<dyn SigningProvider>>,
}
```

Credential issuer startup becomes:

1. Parse `EvidenceConfig`.
2. Validate every `credential_profiles[*].signing_key` references an existing
   `signing_keys` entry.
3. Build every provider once through `SigningKeyRegistry::build_from_config`.
4. Run provider builder validation and self-tests.
5. Build every `EvidenceIssuer` with
   `SdJwtIssuer::from_signing_provider(provider.clone())`.
6. Start serving only if every configured issuer is valid.

Issuance flow:

1. Resolve credential profile.
2. Resolve signer by profile `signing_key`.
3. Build SD-JWT protected header from `provider.algorithm()` and
   `provider.key_id()`.
4. Sign through `provider.sign(payload)`.
5. Return the credential.

No issuance path should read env vars or key files directly after startup.

The `SigningProvider` trait stays intentionally small. Provider builders are
responsible for returning only initialized, validated, self-tested providers:

```rust
impl SigningKeyRegistry {
    pub async fn build_from_config(config: &EvidenceConfig) -> Result<Self, SigningKeyBuildError>;
}
```

Active providers must prove signing readiness during this build step.
`publish_only` providers must validate public metadata only and must never
require private-key access.

## Public Key Publication

JWKS publication should come from the signing-key registry:

```rust
provider.public_jwk()
```

`/.well-known/evidence/jwks.json` should publish active verification keys
without requiring private-key access. Credential verification metadata must not
depend on local JWK parsing when the active provider is PKCS#11.

Rotation status is part of the initial signing-key schema. It is required before
production PKCS#11 rollout:

```yaml
signing_keys:
  issuer-2026-05:
    provider: pkcs11
    status: active
    # ...

  issuer-2026-04:
    provider: pkcs11
    status: publish_only
    # ...
```

Statuses:

- `active`: may sign and must be published.
- `publish_only`: must be published but must not sign new credentials.
- `disabled`: must not sign and must not be published.

Rules:

- Only one active signing key should be allowed per credential profile.
- `kid` values must be unique across all active and publish-only keys.
- `publish_only` keys must not need access to private-key material.
- Retain publish-only keys for at least the maximum credential lifetime plus
  accepted clock skew.
- JWKS output must de-duplicate by `kid` and publish active plus publish-only
  keys exactly once, independent of how many profiles reference a key.
- JWKS responses set `Cache-Control: public, max-age=600`; planned key rotation
  overlap must be longer than that TTL and at least the maximum credential
  lifetime plus accepted clock skew.

Profile/key binding must also be validated. When a profile uses an HTTPS
issuer and the referenced key has a `did:web` `kid`, require the DID authority
to match the issuer host unless an explicit, reviewed escape hatch is added.

## Crate Layout

Keep the stable trait in `registry-platform-crypto`:

```rust
#[async_trait]
pub trait SigningProvider: Send + Sync {
    fn algorithm(&self) -> SigningAlgorithm;
    fn key_id(&self) -> &str;
    fn public_jwk(&self) -> PublicJwk;
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError>;
}
```

Recommended implementation layout:

- `registry-platform-crypto`: trait, algorithm enum, JWK parsing, local JWK
  signer, verification helpers.
- `registry-platform-crypto-pkcs11`: optional PKCS#11 provider using
  `cryptoki`.
- `registry-platform-crypto-pkcs12`: optional PKCS#12 provider if needed.
- `registry-notary-core`: config structs and validation.
- `registry-notary-server`: config-to-provider wiring and issuer registry.

This keeps HSM dependencies out of the default local/test path while preserving
one application-facing signer trait.

## Library Choices

- PKCS#11: use `cryptoki`, the safe Rust wrapper over PKCS#11. Its own docs use
  SoftHSM for local development and CI-style examples:
  <https://docs.rs/cryptoki/latest/cryptoki/>.
- PKCS#12: prefer `openssl::pkcs12::Pkcs12` for the first practical provider if
  PKCS#12 is needed: <https://docs.rs/openssl/latest/openssl/pkcs12/struct.Pkcs12.html>.
- Pure Rust PKCS#12: track `pkcs12`, but verify extraction and algorithm needs
  before depending on it: <https://docs.rs/pkcs12/latest/pkcs12/>.

## Implementation Plan

### Phase 1: Breaking Config Cleanup

- Add `SigningKeyConfig` and `SigningKeyProviderConfig` to
  `registry-notary-core`.
- Add `evidence.signing_keys: BTreeMap<String, SigningKeyConfig>`.
- Replace `CredentialProfileConfig.issuer_key_env` and `issuer_kid` with
  `signing_key`.
- Update validation to require all profile signing-key references to resolve.
- Update validation for status, unique `kid`, supported algorithm, and
  profile/key issuer binding.
- Update demo, perf, tests, and docs configs.

### Phase 2: Local Provider Registry

- Add a server-side builder that turns `signing_keys` into
  `Arc<dyn SigningProvider>` values.
- Build `local_jwk_env` with `LocalJwkSigner`.
- Add `EvidenceIssuer::from_signing_provider`.
- Update `EvidenceIssuerRegistry::from_config` to use the signing-key registry.
- Update JWKS publication to read from providers.
- Add tests for missing key id, missing env var, mismatched `kid`, mismatched
  profile reference, and successful local issuance.

### Phase 3: PKCS#11 Provider

- Add optional PKCS#11 provider crate or feature using `cryptoki`.
- Implement module loading, token selection, login, private-key object lookup,
  mechanism selection, sign, and logout/session cleanup.
- Add SoftHSM integration tests that generate/import a test key and issue a
  credential through the same Notary path.
- Add startup self-test verification using configured `public_jwk_env`.
- Add concurrency tests that prove PKCS#11 signing is serialized or pooled
  safely and does not block Tokio workers directly.
- Add deployment docs for module path, token setup, PIN secret, public JWK, and
  readiness behavior.

### Phase 4: PKCS#12 Provider

- Add only if needed by an integration or local parity requirement.
- Parse a `.p12` file from a configured path and password env var.
- Convert the private key into a local signer with the same public-JWK and `kid`
  checks as `local_jwk_env`.
- Add fixture-based tests with a generated `.p12` file.

### Phase 5: Rotation

- Enforce `status: active | publish_only | disabled`.
- Reject profile configs that reference a non-active key for signing.
- Publish active and publish-only public keys once per `kid`.
- Add tests proving old credentials remain verifiable while new credentials use
  only the active key.

## Testing Requirements

Focused tests:

- Config accepts `signing_keys` plus profile `signing_key`.
- Config rejects legacy `issuer_key_env` and `issuer_kid`.
- Config rejects unknown signing-key references.
- Config rejects unsupported algorithms.
- Config rejects duplicate active/publish-only `kid` values.
- Config rejects profile/key issuer binding mismatches.
- Local JWK provider signs and publishes matching public JWK.
- Local JWK provider rejects mismatched configured `kid`.
- Issued SD-JWT header `kid` equals provider `key_id()`.
- JWKS endpoint publishes configured signer public keys.
- Logs and errors do not include private JWK contents, PKCS#12 passwords, or
  PKCS#11 PIN values.

PKCS#11 tests:

- SoftHSM token initializes in test setup.
- Provider fails closed for missing module, missing token, bad PIN, missing key,
  duplicate key match, unsupported mechanism, and bad public JWK.
- Provider signs a startup challenge and a real SD-JWT payload.
- Signature verifies with the configured public JWK.
- Concurrent signing requests do not share a stateful PKCS#11 operation
  unsafely and do not block Tokio worker threads directly.

PKCS#12 tests:

- Valid fixture loads and signs.
- Bad password fails closed.
- Multi-key or unsupported-key fixture fails closed.
- Extracted public key, certificate public key, and configured `kid` checks are
  enforced.

## Security Notes

- Never log loaded JWK JSON, PKCS#11 PINs, PKCS#12 passwords, or raw key bytes.
- Avoid `Debug` derives on structs that contain secret values.
- Use `Zeroizing` or equivalent wrappers for secret strings loaded from env.
- Treat PKCS#12 as secret material at rest. File permissions and secret mounts
  matter because the private key is extractable by the process.
- Treat PKCS#11 as the production HSM path because signing happens without
  exporting private key material.
- A provider self-test is mandatory because config-only validation cannot prove
  a token key and public JWK belong together.
- A PKCS#11 module is native code loaded into the Notary process. Its path and
  file permissions are part of the trusted deployment boundary.

## Acceptance Criteria

- A credential profile no longer names a private-key env var.
- All signing happens through `SigningProvider`.
- Local demos still work with one env var containing a private JWK.
- PKCS#11 is available behind an optional dependency path and tested with
  SoftHSM before production use.
- PKCS#12 support is either implemented with fixtures or explicitly deferred.
- JWKS publication works for local and HSM-backed keys.
- Unsupported algorithms fail during config/startup validation.
- Active and publish-only key statuses are enforced before production PKCS#11
  support is considered complete.
- The service fails closed on signer initialization errors and never starts with
  a partially configured issuer.

## Delivery Definition Of Done

This work is done only when all criteria below are true and evidenced in the
final implementation PRs:

- Config schema has `evidence.signing_keys` and
  `credential_profiles[*].signing_key`; `issuer_key_env` and `issuer_kid` are
  removed from runtime config structs, demo configs, perf configs, tests, and
  docs.
- Every credential issuance path constructs SD-JWT issuers from
  `Arc<dyn SigningProvider>`; no request-time issuance path reads private keys,
  env vars, PKCS#12 files, or PKCS#11 module config directly.
- Startup fails before binding the server if any active signer is missing,
  unsupported, misbound to a profile, has a duplicate active/publish-only `kid`,
  has invalid public metadata, or fails its self-test.
- `local_jwk_env` signs a credential in an integration test, publishes the same
  key through JWKS exactly once, and rejects missing env, missing `kid`,
  mismatched `kid`, and unsupported algorithm fixtures.
- JWKS publication is driven by the signing-key registry, de-duplicates by
  `kid`, publishes active plus publish-only keys, excludes disabled keys, and
  has tests for shared keys across multiple profiles.
- Rotation status is implemented before PKCS#11 is considered complete:
  `active` signs and publishes, `publish_only` publishes without signing access,
  and `disabled` neither signs nor publishes.
- PKCS#11 support is behind an optional dependency path, uses `cryptoki`, looks
  up private keys by token, label, `CKA_ID`, key type/curve, and `CKA_SIGN`,
  rejects zero/multiple matches, runs blocking calls off Tokio workers, and has
  SoftHSM tests for success and listed failure cases.
- PKCS#12 is either explicitly deferred in code/docs with no dead config path,
  or implemented with fixture tests for valid archive, bad password, ambiguous
  keys, unsupported key, certificate mismatch, and sign/verify self-test.
- Logs, errors, `Debug` output, metrics, traces, and audit events are tested or
  reviewed to avoid exposing private JWK fields, PKCS#11 PINs, PKCS#12
  passwords, raw key bytes, or full secret env values.
- Focused tests and the closest relevant crate test suites pass in CI or local
  verification. Any skipped PKCS#11/PKCS#12 integration test must be marked with
  an explicit feature/env requirement and documented command.

## Delivery Wave Plan

Use workers in parallel only where write scopes are independent. Each wave ends
with a code-review checkpoint before the next wave starts.

### Wave 1: Config And Local Signing

Parallel work:

- Worker A owns `registry-notary-core`: add `SigningKeyConfig`, move signing
  config to `evidence.signing_keys`, remove `issuer_key_env`/`issuer_kid`, and
  add validation for key references, status, unique `kid`, algorithm, and
  profile/key issuer binding.
- Worker B owns demo/perf/docs fixtures: migrate YAML and guide examples to
  `evidence.signing_keys`.
- Main implementer owns `registry-notary-server` and `registry-notary-core`
  issuance wiring: build `SigningKeyRegistry`, wire `local_jwk_env`, add
  `EvidenceIssuer::from_signing_provider`, and make JWKS registry-driven.

Definition of done:

- `rg "issuer_key_env|issuer_kid"` returns only migration notes/spec text, not
  active config structs, fixtures, or runtime code.
- Config tests reject legacy fields, unknown signing keys, duplicate `kid`s,
  unsupported algorithms, and issuer/key binding mismatches.
- Integration tests issue an SD-JWT through `local_jwk_env` and verify header
  `kid`, signature, and JWKS output.
- Code review confirms no issuance request path reads private key env vars.

Code-review checkpoint:

- Review config schema, validation errors, local signer secret handling, JWKS
  de-duplication, and docs/examples before any PKCS#11 work merges.

### Wave 2: Rotation And Publication Semantics

Parallel work:

- Worker A owns status validation and resolver behavior for `active`,
  `publish_only`, and `disabled`.
- Worker B owns JWKS endpoint tests, cache headers, and multi-profile shared-key
  cases.
- Main implementer owns issuance tests proving only active keys sign.

Definition of done:

- Tests prove active keys sign and publish.
- Tests prove publish-only keys publish but cannot be selected for signing.
- Tests prove disabled keys neither sign nor publish.
- Tests prove old credentials remain verifiable after active key rotation.
- JWKS response contains one entry per active/publish-only `kid`.

Code-review checkpoint:

- Review rotation semantics against maximum credential lifetime, cache headers,
  and verifier behavior before HSM support is merged.

### Wave 3: PKCS#11 Provider

Parallel work:

- Worker A owns the optional PKCS#11 provider crate/feature using `cryptoki`,
  including module loading, token selection, key lookup, mechanism selection,
  session lifecycle, and signing.
- Worker B owns SoftHSM test setup and failure fixtures.
- Main implementer owns Notary integration, startup readiness, deployment docs,
  and redaction/error review.

Definition of done:

- SoftHSM success test issues and verifies a real SD-JWT through PKCS#11.
- Failure tests cover missing module, missing token, bad PIN, missing key,
  duplicate key match, unsupported mechanism, invalid public JWK, and failed
  self-test.
- Concurrency test proves PKCS#11 signing is serialized or pooled safely and
  blocking FFI does not run directly on Tokio worker threads.
- Startup refuses to serve when active PKCS#11 signer initialization fails.
- Deployment docs name required module path, token label, PIN env, key label,
  `key_id_hex`, public JWK env, and file-permission expectations.

Code-review checkpoint:

- Review HSM key lookup, EdDSA mechanism parameters, session safety,
  `spawn_blocking`/timeout behavior, module trust boundary, and secret
  redaction before enabling the feature in any deployment profile.

### Wave 4: PKCS#12 Decision

Parallel work:

- Worker A verifies whether current integrations actually require PKCS#12.
- Worker B, only if needed, owns fixture generation and archive parsing tests.
- Main implementer either removes/defer-documents the provider path or wires the
  tested provider behind an optional feature.

Definition of done:

- If deferred: no runtime config accepts `local_pkcs12_file`, and docs state
  PKCS#12 is intentionally deferred.
- If implemented: fixture tests pass for valid archive, bad password, ambiguous
  keys, unsupported key, certificate mismatch, public-key derivation, configured
  `kid`, and sign/verify self-test.
- Code review confirms PKCS#12 is documented as local private-key loading, not
  HSM support.

Code-review checkpoint:

- Review whether PKCS#12 adds enough value to justify the dependency and
  operational risk. Do not merge a partial provider.

### Wave 5: Final Hardening And Release Gate

Parallel work:

- Worker A owns focused regression tests across config, issuance, JWKS, and
  rotation.
- Worker B owns docs consistency across configuration, deployment, credential
  issuance, and security model.
- Main implementer owns final dependency/feature review, CI, and release notes.

Definition of done:

- All wave-specific tests pass.
- Relevant crate test suites pass with default features.
- PKCS#11 feature tests pass in an environment with SoftHSM configured, or CI
  documents the exact command and environment required.
- Documentation examples are executable or covered by config parsing tests.
- Final review signs off that every global definition-of-done bullet above is
  satisfied or explicitly deferred by a documented non-goal.

Code-review checkpoint:

- Final review must verify the global definition of done item by item. No wave
  or feature is marked complete while tests, docs, config migration, or
  fail-closed behavior remain partial.
