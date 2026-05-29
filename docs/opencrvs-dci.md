# OpenCRVS DCI Demo

This note documents the local Registry Notary demo config for using the
OpenCRVS DCI CRVS API as an evidence source.

## Scope

The demo config is:

`demo/config/opencrvs-dci-registry-notary.yaml`

It targets:

`https://dci-crvs-api.farajaland-integration.opencrvs.dev/registry/sync/search`

The tested query shape is DCI `idtype-value` with `query.type = UIN` and
`reg_event_type = birth`.

## Environment

Fetch an OpenCRVS client-credentials token before starting Registry Notary:

```bash
export OPENCRVS_DCI_CLIENT_ID='<OpenCRVS client id>'
export OPENCRVS_DCI_CLIENT_SECRET='<OpenCRVS client secret>'
export OPENCRVS_DCI_TOKEN="$(
  curl -fsS \
    -H 'content-type: application/json' \
    -d "{\"client_id\":\"$OPENCRVS_DCI_CLIENT_ID\",\"client_secret\":\"$OPENCRVS_DCI_CLIENT_SECRET\",\"grant_type\":\"client_credentials\"}" \
    https://dci-crvs-api.farajaland-integration.opencrvs.dev/oauth2/client/token |
    jq -r .access_token
)"
export REGISTRY_NOTARY_API_KEY="$(openssl rand -hex 32)"
export REGISTRY_NOTARY_API_KEY_HASH="$(
  printf '%s' "$REGISTRY_NOTARY_API_KEY" |
    openssl dgst -sha256 -r |
    awk '{print "sha256:" $1}'
)"
export REGISTRY_NOTARY_AUDIT_HASH_SECRET='<stable audit hash secret>'
```

Then run:

```bash
cargo run -p registry-notary-bin -- \
  --config demo/config/opencrvs-dci-registry-notary.yaml
```

Use the plaintext `REGISTRY_NOTARY_API_KEY` value as the `x-api-key` request
header when calling Registry Notary. The config stores only
`REGISTRY_NOTARY_API_KEY_HASH`, which is the SHA-256 fingerprint of that local
API key.

## Claims

The demo exposes:

- `opencrvs-birth-record-exists`

The claim evaluates whether a registered OpenCRVS birth record exists for the
subject id supplied as a UIN.

## Current Interop Boundaries

- The OpenCRVS DCI API issues short-lived OAuth client tokens. Registry Notary
  currently reads the source bearer token from `OPENCRVS_DCI_TOKEN` at startup,
  so long-running deployments need source OAuth refresh support instead of this
  manual demo token flow.
- The OpenCRVS DCI middleware accepts unsigned requests. If request signatures
  become mandatory, Registry Notary needs real DCI request signing and a
  discoverable JWKS for the configured `sender_id`.
- This config currently targets birth records. Death record checks should use a
  separate DCI source connection or claim with `registry_event_type: death`.
