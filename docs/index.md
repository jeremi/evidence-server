# Registry Notary Documentation

Registry Notary evaluates configured registry claims, returns minimized
evidence, issues short-lived SD-JWT VC credentials, supports citizen
self-attestation, and can serve inbound static-peer delegated evaluation.

Use these docs as the practical contract for implemented behavior. Design specs
remain in this folder, but readers should not have to infer runtime behavior
from specs.

## Start Here

- [Overview](overview.md): what the service does and does not do.
- [Concepts](concepts.md): the mental model behind claims, subjects, purposes,
  disclosure, sources, credentials, and federation.
- [Getting started](getting-started.md): run the service locally and evaluate a
  claim.
- [Feature inventory](feature-inventory.md): implementation-reviewed feature
  list, status, and documentation definition of done.
- [User stories](user-stories.md): acceptance stories used to test whether the
  product is moving in the right direction.

## Build Or Integrate

- [Configuration guide](configuration-guide.md): top-level config blocks,
  validation rules, and secret-backed settings.
- [Claim authoring guide](claim-authoring-guide.md): define claims, source
  bindings, rules, disclosure, dependencies, and batch behavior.
- [API guide](api-guide.md): call discovery, evaluation, rendering, credential,
  OID4VCI, status, health, and federation endpoints.
- [Extension boundaries](extension-boundaries.md): where integrations should
  fetch, transform, sign, or only consume credentials.
- [Source connectors guide](source-connectors-guide.md): connect Registry Data
  API, DCI, OAuth2 source auth, and bulk source reads.
- [Client SDK guide](client-sdk-guide.md): use the Rust client and Python and
  Node.js bindings.

## Operate

- [Deployment guide](deployment-guide.md): startup, secrets, Redis, readiness,
  CORS, network policy, and active-active constraints.
- [Security model](security-model.md): trust boundaries, fail-closed behavior,
  replay, redaction, and unsupported assumptions.
- [Audit guide](audit-guide.md): configure and review redacted tamper-evident
  audit envelopes.
- [Observability guide](observability-guide.md): health, readiness, metrics,
  traces, logs, and performance harness notes.
- [CLI reference](cli-reference.md): server startup and operator commands.

## Feature Guides

- [Credential issuance guide](credential-issuance-guide.md)
- [Self-attestation guide](self-attestation-guide.md)
- [Federation guide](federation-guide.md)
- [OpenFn sidecar guide](openfn-sidecar-guide.md)

## Demo And Scenario Docs

- [OpenCRVS DCI standalone tutorial](opencrvs-dci-standalone-tutorial.md)
- [OpenSPP Disability DCI demo](openspp-disability-dci.md)
- [Scenario catalog](notary-scenario-catalog.md)

## Design Records And Existing Specs

- [Client API spec](client-api-spec.md)
- [Citizen self-attestation spec](citizen-self-attestation-spec.md)
- [Federated evaluation MVP spec](federated-evaluation-mvp-spec.md)
- [Federated evaluation operator guide](federated-evaluation-operator-guide.md)
- [Federated Notary manifest spec](federated-notary-manifest-spec.md)
- [OpenCRVS DCI setup simplification spec](opencrvs-dci-setup-simplification-spec.md)
- [OpenID4VCI wallet facade spec](openid4vci-wallet-facade-spec.md)
- [OpenFn sidecar source spec](openfn-sidecar-source-spec.md)
- [Registry Platform spec](registry-platform-spec.md)
- [Scalability spec](scalability-spec.md)
- [SD-JWT VC conformance profile](sd-jwt-vc-conformance-profile.md)
- [Signing key provider spec](signing-key-provider-spec.md)

## Project History

- [Release notes](release-notes.md)
