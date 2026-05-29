# registry-notary-core

Portable Registry Notary domain model, configuration, and credential
primitives.

This crate owns the serializable contracts shared by the server, binary, tests,
and downstream tooling.

## DTO Derive Policy

Public HTTP wire DTOs in this crate should support both directions by default:
derive or implement both `serde::Serialize` and `serde::Deserialize`. This
keeps server-owned responses reusable by typed clients, fixtures, and contract
tests. One-way contracts are allowed only when the type is intentionally
write-only or read-only, and the type should carry a local comment explaining
that exception.

When compatibility requires a custom serde implementation, keep the type
bidirectional. For example, `ClaimRef` serializes as the versioned object shape
and manually deserializes both that object shape and the legacy string claim id.

## What It Provides

- Standalone Registry Notary configuration types and validation.
- Claim, subject, source binding, disclosure, and evaluation models.
- Static-peer federation config models, validation constants, and audit fields
  for delegated evaluation.
- Error types used across the workspace.
- SD-JWT VC issuance helpers for claim views.
- OpenAPI-compatible schema derives for public contract types.

## Typical Use

```rust
use registry_notary_core::StandaloneRegistryNotaryConfig;

fn load(raw_yaml: &str) -> Result<StandaloneRegistryNotaryConfig, Box<dyn std::error::Error>> {
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(raw_yaml)?;
    config.validate()?;
    Ok(config)
}
```

## Boundary

This crate is runtime-neutral. It should not own Axum routes, outbound HTTP
clients, tracing setup, process startup, or storage for evaluated evidence.

## Testing

```sh
cargo test -p registry-notary-core
```

## License

Apache-2.0.
