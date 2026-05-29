# Registry Notary Client API Spec

## Status

Implemented design record. Practical usage guidance lives in
[Client SDK guide](client-sdk-guide.md). Keep this spec for client surface
rationale and binding design.

## Purpose

Define a first-class Registry Notary client that is easy to use from Rust and
can be wrapped cleanly for Python and Node.js consumers.

The client should encode the Notary wire contract, operational safety defaults,
authentication headers, media type negotiation, purpose handling, idempotency,
and error parsing so application code does not need to reimplement those details.

## Goals

- Provide a canonical Rust client crate for Registry Notary HTTP APIs.
- Reuse `registry-notary-core` DTOs where they are bidirectional and
  deserializable. Request DTOs are reusable as-is; response families that are
  currently `Serialize`-only must either gain `Deserialize` in core before the
  client lands or be mirrored as client-owned response DTOs.
- Provide ergonomic Rust builders for common evaluation and credential flows.
- Provide a binding-safe facade that Python and Node.js wrappers can call.
- Preserve a single implementation of transport, auth, retry, redaction, and
  Problem Details parsing.
- Make required domain semantics visible, especially data purpose and
  idempotency.
- Keep protocol-specific features such as OID4VCI and federation separate from
  the common evidence evaluation path.

## Non-Goals

- Do not replace the server OpenAPI document.
- Do not generate the Rust client from OpenAPI for the in-repository client.
- Do not hide Notary authorization, purpose, disclosure, or holder-proof
  semantics behind generic convenience helpers.
- Do not expose bearer tokens, API keys, SD-JWT disclosures, holder proofs, or
  source data in debug output or errors.
- Do not make Python or Node.js users consume Rust-shaped builder APIs directly.

## Crate And Package Layout

```text
crates/registry-notary-client/
  src/
    lib.rs
    client.rs
    builder.rs
    auth.rs
    error.rs
    options.rs
    headers.rs
    discovery.rs
    evaluate.rs
    batch.rs
    credential.rs
    status.rs
    responses.rs
    oid4vci/
      mod.rs
      metadata.rs
    federation/
      mod.rs

crates/registry-notary-client-ffi/
  src/
    lib.rs
    facade.rs
    error.rs

bindings/python/
  pyproject.toml
  src/registry_notary/

bindings/node/
  package.json
  src/
```

`headers.rs` owns shared constants such as `data-purpose`, `Idempotency-Key`,
`x-request-id`, and the Registry Notary media types. `discovery.rs` owns
well-known endpoints and OpenAPI fetches. `responses.rs` owns optional helper
wrappers over raw DTOs.

`registry-notary-client` is the canonical implementation. Python and Node.js
wrappers should call a stable facade instead of reimplementing HTTP behavior.

## Rust Client Layers

### Low-Level Typed Client

The low-level client maps directly to Registry Notary routes and accepts typed
wire DTOs from `registry-notary-core`.

```rust
let response = client.evaluate_dto(request, options).await?;
let batch = client.batch_evaluate_dto(request, options).await?;
let rendered = client.render_dto(request, options).await?;
let credential = client.issue_credential_dto(request, options).await?;
```

This layer is useful for service integrations, tests, generated workflows, and
callers that already construct Notary DTOs.

### Ergonomic Workflow Builders

The ergonomic layer exposes common operations with fluent builders:

```rust
let evaluation = client
    .evaluate("subj-0000001")
    .id_type("NATIONAL_ID")
    .claims(["date-of-birth", "farmer-under-4ha"])
    .purpose("benefits_eligibility")
    .disclosure("minimal")
    .send()
    .await?;
```

The builder should remain thin. It should construct typed DTOs and delegate to
the low-level client.

### Workflow Helpers

Higher-level helpers can chain common Notary operations after the core API is
stable:

```rust
let credential = client
    .evaluate_then_issue("subj-0000001")
    .id_type("NATIONAL_ID")
    .claim("smallholder-farmer")
    .purpose("benefits_eligibility")
    .credential_profile("smallholder-farmer-v1")
    .holder_jwk(holder_jwk)
    .send()
    .await?;
```

These helpers are convenience only. The lower-level operations must remain
available for callers that need explicit control.

## Client Construction

```rust
let client = RegistryNotaryClient::builder("https://notary.example")
    .bearer_token(token)
    .default_purpose("benefits_eligibility")
    .user_agent("benefits-service/1.0")
    .timeout(Duration::from_secs(30))
    .build()?;
```

Supported construction options:

- `base_url`, required.
- `bearer_token`, for `Authorization: Bearer`.
- `api_key`, for `X-Api-Key`.
- `auth_provider`, optional future trait for rotating credentials.
- `default_purpose`, optional default for evaluation and batch evaluation.
- `timeout`, default 30 seconds.
- `user_agent`, strongly recommended for services.
- `reqwest_client`, available only under `#[cfg(any(test, feature =
  "test-support"))]`.
- `retry_policy`, disabled or conservative by default.

The default HTTP client should use production-safe settings:

- redirects disabled;
- proxy environment variables ignored;
- bounded response body reads;
- TLS through Rustls by default;
- TLS certificate verification enabled;
- TLS 1.2 or newer;
- automatic gzip, brotli, zstd, and deflate decompression disabled;
- no secrets in `Debug`.

The client should reject non-HTTPS `base_url` values unless `test-support` is
enabled and the URL is HTTP loopback. Production builds must not expose an
escape hatch for disabled certificate verification or cleartext bearer-token
transport.

The client should reuse `registry-platform-httputil::OutboundClientBuilder` for
transport defaults and call `registry-platform-httputil::read_bounded` for every
response body. Bounded reads are a client responsibility, not a property of the
builder.

Default post-decompression body limits:

- health, readiness, and status routes: 64 KiB;
- discovery, claims, formats, OpenAPI, and JWKS routes: 2 MiB;
- evaluate, render, direct credential issue, and OID4VCI routes: 8 MiB;
- batch evaluate: 16 MiB by default, configurable up to an explicit caller
  maximum.

Because automatic decompression is disabled, `Content-Length` preflight checks
and streamed body caps measure the same wire body. If a future version enables
decompression, the streamed body cap must apply to the expanded bytes.

HTTP connection pooling and HTTP/2 should use reqwest defaults. Callers that
need custom pool settings can get them only through the test-support client
override or a future narrowly scoped pool configuration API.

## Auth Model

```rust
pub enum Auth {
    Bearer(SecretString),
    ApiKey(SecretString),
    Provider(Arc<dyn AuthProvider>),
}
```

`SecretString` means `secrecy::SecretString`, or an equivalent type with the
same redaction and zeroization properties.

Only one auth mode can be active per client. Calling more than one auth setter
is a `.build()` error:

```rust
NotaryClientBuildError::MultipleAuthModes
```

The builder must never silently prefer one credential over another. Auth
variants cannot be combined.

Secret-bearing types must redact their values in `Debug`, errors, and traces.

`AuthProvider` is optional for the first version:

```rust
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn auth_header(&self) -> Result<AuthHeader, NotaryClientError>;
}
```

`AuthHeader` must also redact in `Debug` and `Display`, and must zeroize secret
material on drop.

## Request Options

```rust
#[non_exhaustive]
pub struct RequestOptions {
    pub purpose: Option<String>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub accept: Option<String>,
    pub traceparent: Option<String>,
    pub cancellation_token: Option<CancellationToken>,
}
```

`RequestOptions` should expose `RequestOptions::builder()`. Route-specific
builders are the primary public surface for application code and internally
produce `RequestOptions`.

Builder methods should expose the route-appropriate options fluently:

```rust
client
    .batch_evaluate()
    .subjects(subjects)
    .claims(["date-of-birth"])
    .purpose("benefits_eligibility")
    .idempotency_key("batch-2026-05-29-001")
    .send()
    .await?;
```

Header mapping:

- `purpose` maps to `data-purpose` and, where needed, request body `purpose`.
- `request_id` maps to `x-request-id`.
- `idempotency_key` maps to `Idempotency-Key`.
- `traceparent` maps to W3C `traceparent`.
- evaluation and batch evaluation default `Accept` to
  `application/vnd.registry-notary.claim-result+json`.

If both a body purpose and header purpose are present, they must match
byte-for-byte after no case conversion or normalization. On mismatch, the client
must fail client-side with `NotaryClientBuildError::PurposeConflict`. It must
never silently pick one value.

`Idempotency-Key` is honored by the server for batch evaluation only. The client
must reject idempotency keys on routes that ignore them.

Cancellation is best effort. Dropping a Rust future, cancelling Python asyncio
work, or aborting a Node.js request stops waiting on the client-side request.
The client does not promise server-side cancellation after bytes have reached
the Notary process.

## Route Coverage

Initial route coverage:

- `GET /healthz`
- `GET /ready`
- `POST /admin/reload`
- `GET /openapi.json`
- `GET /.well-known/evidence-service`
- `GET /.well-known/evidence/jwks.json`
- `GET /claims`
- `GET /claims/{claim_id}`
- `GET /formats`
- `POST /claims/evaluate`
- `POST /claims/batch-evaluate`
- `POST /evidence/render`
- `POST /credentials/issue`
- `GET /credentials/status/{credential_id}`
- `POST /admin/credentials/status/{credential_id}`

`GET /claims` has no pagination in the current server contract and returns
`{"data": [...]}`.

Separate feature-gated modules:

- OID4VCI:
  - `GET /.well-known/openid-credential-issuer`
  - `GET /oid4vci/credential-offer`
  - `POST /oid4vci/nonce`
  - `POST /oid4vci/credential`
- Federation:
  - `POST /federation/v1/evaluations`

## Response Ergonomics

The low-level client returns raw DTOs. Optional helper wrappers live under a
helpers or responses module and must not hide fields from the server response.

The Rust client can wrap common responses with helper methods while preserving
the underlying DTOs:

```rust
pub struct Evaluation {
    pub results: Vec<ClaimResultView>,
}

impl Evaluation {
    pub fn evaluation_id(&self) -> Option<&str>;
    pub fn first_result(&self) -> Option<&ClaimResultView>;
    pub fn result_for(&self, claim_id: &str) -> Option<&ClaimResultView>;
}
```

```rust
pub struct BatchEvaluation {
    pub inner: BatchEvaluateResponse,
}

impl BatchEvaluation {
    pub fn succeeded(&self) -> impl Iterator<Item = &BatchItemResponse>;
    pub fn failed(&self) -> impl Iterator<Item = &BatchItemResponse>;
}
```

Wrappers should not discard fields from the server response.

Phase 1 cannot rely on `registry-notary-core::BatchEvaluateResponse` until that
family derives `Deserialize`, or until the client crate owns equivalent
response DTOs. This applies to `BatchEvaluateResponse`,
`BatchItemResponse`, `BatchClaimResultView`, `BatchItemError`, and related
enums. Audit event DTOs are not part of the initial route surface, but the same
rule applies if they become client-facing.

Successful responses should retain a safe metadata envelope:

```rust
pub struct NotaryResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
    pub retry_after: Option<RetryAfter>,
}
```

The client must read safe headers such as `x-request-id` and `Retry-After`
before decoding the response body.

Raw headers should not be public by default. A future `raw-headers` feature can
expose them for diagnostics.

## Media Types

The client must centralize these media types:

- `application/vnd.registry-notary.claim-result+json`, for evaluate and batch
  evaluate results.
- `application/dc+sd-jwt`, for SD-JWT VC credentials.
- `application/problem+json`, for Notary Problem Details.
- `application/json`, for normal JSON routes and OpenID4VCI envelopes.

The client should send a single explicit `Accept` value for each route. It does
not need to implement full `q` value negotiation unless callers opt into custom
`Accept` headers.

Error parsing is route-aware. OpenID4VCI routes, and any route documented by the
server as returning OpenID4VCI errors, parse OpenID4VCI error envelopes rather
than Problem Details even when the content type is generic JSON.

## Error Model

The Rust client should expose typed errors:

```rust
#[derive(Debug, thiserror::Error)]
pub enum NotaryClientError {
    #[error("invalid base URL")]
    Url(#[source] url::ParseError),

    #[error("transport error")]
    Transport(#[source] reqwest::Error),

    #[error("registry notary problem: {problem}")]
    Problem {
        status: reqwest::StatusCode,
        problem: ProblemDetails,
        request_id: Option<String>,
    },

    #[error("openid4vci error: {error}")]
    Oid4vci {
        status: reqwest::StatusCode,
        error: Oid4vciError,
        request_id: Option<String>,
    },

    #[error("failed to decode response body")]
    Decode {
        status: reqwest::StatusCode,
        source: serde_json::Error,
        request_id: Option<String>,
    },

    #[error("response body exceeded configured size limit")]
    BodyTooLarge {
        request_id: Option<String>,
    },
}
```

Problem Details:

```rust
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: Option<String>,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
}
```

Useful helpers:

```rust
impl NotaryClientError {
    pub fn status(&self) -> Option<StatusCode>;
    pub fn problem_code(&self) -> Option<&str>;
    pub fn request_id(&self) -> Option<&str>;
    pub fn is_retryable(&self) -> bool;
}
```

The portable error envelope used by Python and Node.js should be stable:

```json
{
  "kind": "problem",
  "status": 404,
  "code": "source.not_found",
  "title": "Source record not found",
  "retryable": false,
  "request_id": "req-123"
}
```

The portable error envelope intentionally excludes `detail` because server
details can include identifiers or field paths that should not cross into
Python or Node.js application logs by default. Language wrappers may expose
`detail` only behind an explicit unsafe diagnostics option that documents the
PII risk.

`Decode` must use an opaque `Display` string such as
`failed to decode response body`. It must not render raw response fragments,
tokens, holder proofs, credential bodies, nonces, or SD-JWT compact values. The
inner `serde_json::Error` can be available through a test-only accessor for
assertions.

## Retry Policy

Retries should be conservative.

Default behavior:

- no automatic retry for evaluation, render, or credential issuance;
- no automatic retry for batch evaluation unless an idempotency key is present;
- no retry for HTTP 400, 401, 403, 404, 406, 409, or 413;
- optional retry for transport errors, 429, and 503 when explicitly enabled.

The retry policy should honor `Retry-After` when the server provides it.

```rust
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub retry_transport_errors: bool,
    pub retry_rate_limited: bool,
    pub retry_unavailable: bool,
}
```

Retry enforcement is route-specific:

- `GET` routes can retry transport errors, 429, and 503 when retry is enabled.
- `POST /claims/batch-evaluate` can retry only when `Idempotency-Key` is set.
- `POST /claims/evaluate`, `POST /evidence/render`, and
  `POST /credentials/issue` must refuse retry attempts unless a future server
  contract adds deduplication for those routes.
- OpenID4VCI credential issuance must not retry by default.

`Retry-After` parsing must support both delta seconds and HTTP-date formats.

## Rust Feature Flags

```toml
[features]
default = ["rustls"]
rustls = ["reqwest/rustls-tls"]
native-tls = ["reqwest/native-tls"]
oid4vci = ["registry-platform-oid4vci"]
federation = []
json-facade = []
test-support = []
```

`oid4vci` and `federation` should stay optional because they add protocol
expectations beyond the common evidence client.

`serde_json` is a normal, non-optional dependency because typed error parsing
and JSON routes need it. `json-facade` gates only the binding-safe facade module.

`federation` does not require `jsonwebtoken` unless the client grows a feature
that mints signed federation request JWTs. The initial federation client posts
an already-signed compact JWS.

## Python Wrapper

Python should ship as a dictionary-friendly package over the same HTTP and JSON
wire contract. A future native Rust-backed binding may use `pyo3` and
`maturin`, but that is not required for the initial Python package.

Async methods should not use ad hoc `block_on`. The initial pure-Python package
may bridge sync HTTP calls with `asyncio.to_thread`; if a native Rust binding is
introduced later, it must use `pyo3-async-runtimes` in Tokio mode with a
binding-owned runtime. The package should expose both sync and async variants
where practical:

- `client.evaluate(...)`, for synchronous callers.
- `await client.aevaluate(...)`, for asyncio callers.

The public API should feel native and dictionary-friendly:

```python
client = RegistryNotaryClient(
    base_url="https://notary.example",
    bearer_token=token,
    default_purpose="benefits_eligibility",
)

evaluation = await client.aevaluate(
    subject_id="subj-0000001",
    id_type="NATIONAL_ID",
    claims=["date-of-birth"],
)
```

Low-level Python escape hatch:

```python
evaluation = await client.evaluate_request(
    {
        "subject": {"id": "subj-0000001", "id_type": "NATIONAL_ID"},
        "claims": ["date-of-birth"],
    },
    purpose="benefits_eligibility",
)
```

Python exception classes:

- `NotaryError`
- `NotaryTransportError`
- `NotaryProblemError`

OpenID4VCI and decode failures should use `NotaryProblemError` with distinct
`kind` values unless a later implementation proves separate classes are needed.
All exported exception classes inherit from `NotaryError`. Exception attributes
should include `status`, `code`, `title`, `retryable`, and `request_id` when
available. `detail` is excluded by default for the same reason it is excluded
from the portable error envelope.

## Node.js Wrapper

Node.js should ship as a Promise-based package over `fetch` and the same HTTP
and JSON wire contract. A future native Rust-backed binding may use `napi-rs`,
but that is not required for the initial Node.js package.

The public API should be Promise-based and object-oriented:

```ts
const client = new RegistryNotaryClient({
  baseUrl: "https://notary.example",
  bearerToken: token,
  defaultPurpose: "benefits_eligibility",
});

const evaluation = await client.evaluate({
  subject: { id: "subj-0000001", idType: "NATIONAL_ID" },
  claims: ["date-of-birth"],
  signal: abortController.signal,
});
```

Low-level Node.js escape hatch. Facade JSON uses the canonical wire shape, so
raw requests are snake_case:

```ts
const evaluation = await client.evaluateRequest(
  {
    subject: { id: "subj-0000001", id_type: "NATIONAL_ID" },
    claims: ["date-of-birth"],
  },
  { purpose: "benefits_eligibility" },
);
```

Node.js error classes:

- `NotaryError`
- `NotaryTransportError`
- `NotaryProblemError`

OpenID4VCI and decode failures should use `NotaryProblemError` with distinct
`kind` values unless a later implementation proves separate classes are needed.
All exported error classes inherit from `NotaryError`. TypeScript declarations
should be generated and checked in or published with the package.

## Binding-Safe Facade

Python and Node.js wrappers should call a facade that accepts and returns JSON
values. The facade should validate JSON through the same Rust DTOs used by the
typed client.

Facade JSON is the canonical wire shape and uses snake_case. Python passes
facade JSON through directly. Node.js high-level methods convert camelCase to
snake_case at the wrapper boundary and convert selected response fields back to
camelCase when returning high-level objects.

```rust
pub struct NotaryClientHandle;

impl NotaryClientHandle {
    pub async fn evaluate_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;

    pub async fn batch_evaluate_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;

    pub async fn render_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;

    pub async fn issue_credential_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;

    pub async fn list_claims_json(
        &self,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;

    pub async fn get_claim_json(
        &self,
        claim_id: String,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;

    pub async fn credential_status_json(
        &self,
        credential_id: String,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError>;
}
```

The v1 facade covers the routes Python and Node.js wrappers need for normal
evaluation, credential issuance, discovery, claims listing, and credential
status. OID4VCI facade methods are added when the `oid4vci` feature is enabled.
This keeps the language wrappers thin while avoiding a public API that exposes
Rust-specific builder lifetimes, traits, or generic types.

## Naming

Rust:

- `RegistryNotaryClient`
- `NotaryClientBuilder`
- `NotaryClientError`
- `RequestOptions`
- `Auth`

Python:

- package: `registry-notary`
- import: `registry_notary`
- class: `RegistryNotaryClient`

Node.js:

- package: `@registry-notary/client`
- class: `RegistryNotaryClient`

Python uses `registry-notary` because `import registry_notary` reads naturally
for Python users. Node.js uses one scoped package name to avoid support churn
from dual package names.

## JWKS And Discovery Cache

`/.well-known/evidence/jwks.json` is load-bearing for clients that verify
Notary-signed artifacts. The server returns `Cache-Control: public,
max-age=600`, and the client should provide a small JWKS cache:

- default TTL: 10 minutes;
- configurable TTL range: 5 to 15 minutes for normal deployments;
- forced refresh on `kid` mismatch before treating the artifact as
  unverifiable;
- explicit `refresh_jwks()` method;
- no stale-key fallback after a failed forced refresh unless the caller opts
  into a documented offline verification mode.

Operators must keep replaced issuer keys published for at least the maximum
credential lifetime plus accepted clock skew and longer than the advertised
JWKS cache TTL. Clients should not assume a new key is visible until one cache
TTL has elapsed, but they must bypass the cached set once when an otherwise
valid artifact references an unknown `kid`.

The client may fetch `/openapi.json` for compatibility diagnostics in debug or
test tooling. It should not require OpenAPI fetches on normal startup.

## Versioning

Registry Notary routes are currently flat except for federation
`/federation/v1/...`. The client treats the current flat routes as v1 by
convention. Breaking server changes should move to new paths or explicit
versioned APIs. The client can offer an optional compatibility check against
`/openapi.json`, but normal request execution should remain route-driven.

## Security Requirements

- Never log credentials, holder proofs, disclosures, SD-JWT compact tokens,
  OID4VCI credential bodies, OID4VCI nonces, or raw source records.
- Redact secret values in `Debug`.
- Disable redirects by default.
- Ignore proxy environment variables by default.
- Enforce a bounded response body limit.
- Require explicit opt-in for retry behavior.
- Preserve request IDs for audit correlation.
- Do not silently fall back from one auth credential to another.
- Do not auto-generate purposes.
- Do not include response bodies in transport errors unless they have already
  been parsed into safe error envelopes.
- Emit tracing spans only with safe labels: request ID, route template, method,
  status class, retry attempt, and outcome. Never emit bodies, `Authorization`,
  `X-Api-Key`, `Idempotency-Key`, subject IDs, claim values, holder material,
  disclosures, SD-JWT compact values, credential bodies, or nonces.
- Do not disable TLS certificate verification in production builds.

## Testing Requirements

Rust client tests:

- builder validation for base URL and auth configuration;
- builder rejection for multiple auth modes;
- HTTPS-only base URL validation, with HTTP loopback allowed only under
  `test-support`;
- auth header selection for bearer and API key modes;
- default claim-result `Accept` header for evaluation routes;
- purpose header behavior;
- client-side purpose conflict rejection;
- batch idempotency header behavior;
- idempotency rejection on routes that ignore it;
- Problem Details parsing;
- Problem Details `type` field rename handling;
- OID4VCI error envelope parsing when the feature is enabled;
- retry policy behavior with and without idempotency;
- route-specific retry refusal for non-deduplicated POST routes;
- bounded response body behavior;
- disabled automatic decompression;
- redacted `Debug` output for secrets;
- opaque decode error display;
- safe response metadata capture on success and failure;
- integration tests against `registry-notary-server` routes where practical.

Python wrapper tests:

- async evaluate and batch evaluate happy paths;
- exception mapping from portable errors;
- argument conversion from Python naming to wire DTO naming;
- wheel build through the package `pyproject.toml`.

Node.js wrapper tests:

- Promise-based evaluate and batch evaluate happy paths;
- exception mapping from portable errors;
- TypeScript declaration checks;
- package dry-run with `npm pack --dry-run`.

## Implementation Phases

### Phase 1: Rust MVP

- Add `registry-notary-client` crate.
- Add or mirror deserializable response DTOs for any core response families that
  are currently `Serialize`-only.
- Implement client builder with bearer and API-key auth.
- Implement safe HTTP defaults.
- Implement typed route methods for health, ready, claims, formats, evaluate,
  batch evaluate, render, issue credential, admin reload, OpenAPI fetch, and
  credential status.
- Implement typed Problem Details errors.
- Implement opt-in, route-aware retry policy.
- Add focused unit and integration tests.

### Phase 2: Binding Facade

- Add JSON facade methods over the Rust typed client.
- Add portable error envelope.
- Add tests proving facade JSON validates through canonical DTOs.
- Keep native FFI optional; pure Python and Node packages may call the HTTP
  contract directly.

### Phase 3: Python Wrapper

- Add Python package with sync and async HTTP methods.
- Map safe client errors to Python exceptions.
- Publish type hints.

### Phase 4: Node.js Wrapper

- Add Node.js package using `fetch`.
- Expose Promise-based methods.
- Map portable errors to JavaScript error classes.
- Publish TypeScript declarations.

### Phase 5: Protocol Extensions

- Add OID4VCI helper module behind `oid4vci`.
- Add federation helper module behind `federation`.
- Add higher-level `evaluate_then_issue` workflows where they reduce repeated
  application code without hiding policy-relevant inputs.

## Settled Design Decisions

- `default_purpose` is optional. The client validates purpose at send time
  rather than using typestate builders, because callers may legitimately vary
  purpose per request.
- Retry support ships in Phase 1 as opt-in `RetryPolicy` with route-specific
  enforcement.
- Python and Node.js packages live in this repository with separate publish
  pipelines.
- Response headers expose only a safe selection by default: request ID,
  `Retry-After`, and any future explicitly safe echo headers. Raw headers require
  a feature-gated diagnostic escape hatch.
- OID4VCI helper APIs wrap endpoints only. They do not generate holder proofs or
  custody holder keys. Callers supply proof JWTs.

## Remaining Open Questions

- Should the client-owned response DTOs be permanent, or should
  `registry-notary-core` add `Deserialize` to every public response family?
- Should offline JWKS verification ever be supported, and if so, what audit
  warning should it emit?

## Delivery Definition Of Done

This work is done only when all of the following are true:

- The Rust client, JSON facade, Python wrapper, and Node.js wrapper implement
  every route and behavior assigned to their completed waves.
- Public request DTO reuse is resolved explicitly: either core response types
  used by the client derive `Deserialize`, or client-owned response DTOs exist
  and are covered by tests.
- The client rejects unsafe construction states in tests: multiple auth modes,
  non-HTTPS non-loopback base URLs, purpose conflicts, and unsupported
  idempotency-key usage.
- All response reads use bounded bodies with the route-family limits named in
  this spec, and automatic decompression is disabled in a test that inspects the
  built client behavior.
- Error handling is verified for Problem Details, OpenID4VCI envelopes,
  body-too-large responses, decode failures, and portable FFI errors without
  leaking `detail`, credentials, holder proofs, nonces, SD-JWT values, or raw
  body fragments through `Debug` or `Display`.
- Retry behavior is verified per route: safe GET retries when enabled, batch
  retries only with `Idempotency-Key`, and refusal for non-deduplicated POST
  routes.
- Success and failure responses expose safe metadata: request ID and
  `Retry-After` where present.
- Python and Node.js wrappers prove their case-conversion contracts with tests:
  Python passes canonical snake_case through, Node high-level APIs accept
  camelCase and raw facade calls use snake_case.
- Required checks pass from a clean invocation:
  `cargo fmt --all -- --check`, relevant `cargo clippy` with `-D warnings`,
  relevant `cargo test` commands, Python package tests and wheel build, Node.js
  tests, TypeScript declaration checks, and package build.
- Each wave has passed its code-review checkpoint, and no item is marked
  complete while its tests are skipped, pending, or manually unverified.

## Concise Implementation Plan

### Wave 0: Contract Prep

Parallel work:

- Worker A: inspect `registry-notary-core` public response types and either add
  `Deserialize` derives or draft client-owned DTOs.
- Worker B: map server routes to client methods, route tags, body limits,
  media types, retry eligibility, and error parser kind.
- Worker C: draft test fixtures for Problem Details, OpenID4VCI errors,
  oversized bodies, malformed JSON, retry-after seconds, and retry-after dates.

Definition of done:

- A checked-in route contract table exists in the client crate or tests.
- Every Phase 1 response type has a deserialization path verified by unit tests.
- No unresolved DTO reuse question blocks compiling the client crate.

Review checkpoint:

- Review DTO ownership, route table completeness, and test fixture coverage
  before any HTTP client behavior is implemented.

### Wave 1: Rust Client MVP

Parallel work:

- Worker A: implement builder, auth model, HTTPS validation, redaction, and
  request option validation.
- Worker B: implement transport defaults, bounded reads, metadata capture,
  media type constants, and route-aware error parsing.
- Worker C: implement route methods for health, ready, discovery, claims,
  formats, evaluate, batch evaluate, render, issue credential, admin reload,
  OpenAPI fetch, and credential status.
- Worker D: implement opt-in route-aware retry policy and tests.

Definition of done:

- All Phase 1 route methods compile and have focused unit or integration tests.
- Tests prove all unsafe construction states are rejected.
- Tests prove decompression is disabled and body limits are enforced.
- Tests prove retry refusal and retry allowance for the route matrix.
- `cargo fmt`, `cargo clippy`, and relevant `cargo test` pass.

Review checkpoint:

- Review public Rust API, security defaults, retry matrix, and error redaction
  before starting binding facade work.

### Wave 2: JSON Facade

Parallel work:

- Worker A: implement facade methods over the Rust typed client for evaluation,
  credential issuance, discovery, claims listing, and credential status.
- Worker B: implement portable error envelope and redaction tests.
- Worker C: implement facade case-shape tests using canonical snake_case JSON.

Definition of done:

- Facade JSON validates through the same DTOs as the typed Rust client.
- Portable errors contain `kind`, `status`, `code`, `title`, `retryable`, and
  `request_id`, and exclude `detail` by default.
- Facade tests cover success, Problem Details, OpenID4VCI error, decode error,
  and body-too-large paths.
- Relevant Rust format, clippy, and tests pass.

Review checkpoint:

- Review FFI boundary safety, portable error shape, and JSON case contract
  before Python or Node wrappers start.

### Wave 3: Python Wrapper

Parallel work:

- Worker A: scaffold Python package and wheel metadata.
- Worker B: implement sync and async Python APIs over the JSON facade.
- Worker C: implement Python exceptions and type hints.

Definition of done:

- `client.evaluate(...)` and `await client.aevaluate(...)` both pass tests.
- Python tests cover snake_case passthrough, exception mapping, cancellation
  behavior, and redaction.
- `python -m pip wheel . --no-deps` succeeds.

Review checkpoint:

- Review asyncio runtime behavior, API ergonomics, exception shape, and type
  hints before Node wrapper work is marked ready.

### Wave 4: Node.js Wrapper

Parallel work:

- Worker A: scaffold Node.js package and TypeScript declarations.
- Worker B: implement Promise APIs, `AbortSignal` support, and camelCase to
  snake_case conversion.
- Worker C: implement JavaScript error classes and package tests.

Definition of done:

- Node tests cover high-level camelCase APIs and raw snake_case facade calls.
- `AbortSignal` cancellation is tested.
- Error mapping and redaction tests pass.
- TypeScript declaration checks and package build pass.

Review checkpoint:

- Review TypeScript API, cancellation behavior, case conversion, and package
  layout before protocol extensions begin.

### Wave 5: Protocol Extensions

Parallel work:

- Worker A: implement OID4VCI endpoint wrappers without holder-proof generation.
- Worker B: implement federation POST for already-signed compact JWS requests.
- Worker C: implement JWKS cache, forced refresh on `kid` mismatch, and
  `refresh_jwks()`.

Definition of done:

- OID4VCI wrappers parse endpoint-specific errors and redact credential bodies
  and nonces.
- Federation wrapper posts already-signed JWS bodies and does not depend on JWT
  minting crates.
- JWKS cache tests cover TTL, forced refresh, and failed refresh behavior.
- Relevant Rust, Python, and Node.js checks pass for any exposed wrapper API.

Review checkpoint:

- Review protocol boundaries, key custody assumptions, JWKS behavior, and
  feature flags before declaring the full client work complete.
