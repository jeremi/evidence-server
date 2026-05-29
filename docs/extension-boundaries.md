# Extension Boundaries

Registry Notary is intentionally small at its extension points. Integrations
should add systems around the Notary boundary instead of changing where claim
policy, source projection, and credential signing decisions are made.

## Status

This note describes the implemented extension posture after source connector
conformance work. It is an architecture guide, not a plugin API promise.

## Extension Points

| Extension point | Intended use | Boundary |
| --- | --- | --- |
| Source connectors | Fetch configured registry facts from Registry Data API, DCI, or a Registry Data API-shaped sidecar | Connectors return bounded source records to Notary evaluation. They do not decide claims or disclosure. |
| OpenFn sidecar | Transform an external system call into the Registry Data API read shape | The sidecar owns external workflow/adaptor logic. Notary still owns auth, purpose checks, claim evaluation, and audit. |
| Claim configuration | Define source bindings, required fields, rule logic, disclosure, and output formats | Claim config is the policy surface. Runtime callers cannot inject ad hoc transforms. |
| Credential profiles | Configure supported SD-JWT VC issuance profiles, issuer keys, holder binding, validity, and allowed claims | Notary signs credentials only from stored evaluations and configured profiles. |
| Client applications | Consume evidence, rendered results, status, or Witness-issued credentials | Clients do not get raw source rows unless a configured disclosure explicitly allows the derived value. |

## Non-Extension Points

The following areas are not extension surfaces:

- caller authentication and scope enforcement;
- purpose enforcement before source reads;
- self-attestation subject binding before source reads;
- audit redaction and audit chain semantics;
- replay protection for federation, OID4VCI nonces, and holder proofs;
- arbitrary credential signing outside configured profiles;
- runtime caller-supplied source transformations;
- open federation trust or dynamic peer admission.

These boundaries preserve the product invariant that source reads happen only
after Notary policy checks, and that issued credentials represent Notary-owned
evaluations rather than arbitrary upstream assertions.

## Integration Placement

Use this placement rule when deciding where new integration work belongs:

- Fetch data in a source connector when the upstream already exposes a stable
  read API.
- Transform data in an adaptor or sidecar when the upstream needs protocol,
  payload, or job orchestration before it can look like a Registry Data API
  read.
- Express claim policy in Notary claim configuration when the question is about
  what evidence is allowed, what fields are required, or what disclosure can
  leave the service.
- Sign credentials in Notary only when the credential is backed by a stored
  evaluation and a configured credential profile.
- Consume Witness-issued or Notary-issued credentials in relying-party systems
  when the workflow only needs verification, presentation, or status checks.

## Follow-Up Rule

Do not open broad extension tickets such as "make sources pluggable" or "add
custom signing hooks." Open follow-up implementation tickets only when a real
integration exposes concrete friction, such as:

- a source read cannot be represented by Registry Data API, DCI, or an existing
  sidecar shape;
- an adaptor needs a reusable conformance test because multiple deployments use
  the same external API;
- a credential profile cannot express a required standards-compatible issuance
  option;
- a consumer needs a documented response field or status behavior that is
  already safe under the redaction model.

Each follow-up should name the integration, the blocked workflow, the current
boundary that fails, and the smallest runtime or documentation change needed to
unblock it.
