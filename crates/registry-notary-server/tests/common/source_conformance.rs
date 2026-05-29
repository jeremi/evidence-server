// SPDX-License-Identifier: Apache-2.0
//! Reusable source connector conformance harnesses.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_test::{TestResponse, TestServer};
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use serde_json::{json, Value};
use tempfile::TempDir;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_API_KEY_HASH: &str =
    "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51";

pub const TEST_API_KEY: &str = "api-token";
pub const TEST_SOURCE_TOKEN: &str = "source-token";
pub const TEST_PURPOSE: &str = "https://purpose.example.test/eligibility";
pub const TEST_API_KEY_HASH_ENV: &str = "TEST_CONFORMANCE_RDA_API_KEY_HASH";
pub const CLAIM_ID: &str = "farmed-land-size";

static HARNESS_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
pub struct CapturedSourceRequest {
    pub authorization: Option<String>,
    pub purpose: Option<String>,
    pub query: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
pub struct RdaFixtureState {
    requests: Arc<Mutex<Vec<CapturedSourceRequest>>>,
    total: Arc<AtomicUsize>,
}

impl RdaFixtureState {
    pub fn requests(&self) -> Vec<CapturedSourceRequest> {
        self.requests
            .lock()
            .expect("captured requests lock")
            .clone()
    }

    pub fn total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }
}

pub struct RdaConnectorHarness {
    pub server: TestServer,
    pub source: RdaFixtureState,
    pub audit_path: std::path::PathBuf,
    _upstream: TestServer,
    _tmp: TempDir,
}

#[derive(Clone, Copy)]
pub struct RdaHarnessOptions {
    pub source_token: &'static str,
    pub retry_on_5xx: bool,
}

impl Default for RdaHarnessOptions {
    fn default() -> Self {
        Self {
            source_token: TEST_SOURCE_TOKEN,
            retry_on_5xx: false,
        }
    }
}

pub async fn rda_connector_harness(options: RdaHarnessOptions) -> RdaConnectorHarness {
    let harness_id = HARNESS_ID.fetch_add(1, Ordering::SeqCst);
    let source_token_env = format!("TEST_CONFORMANCE_RDA_SOURCE_TOKEN_{harness_id}");
    set_common_env(&source_token_env, options.source_token);

    let source = RdaFixtureState::default();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/datasets/farmer_registry/farmer", get(rda_fixture))
            .with_state(source.clone()),
    );
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(rda_connector_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &source_token_env,
        options.retry_on_5xx,
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    RdaConnectorHarness {
        server,
        source,
        audit_path,
        _upstream: upstream,
        _tmp: tmp,
    }
}

pub async fn evaluate_claim(
    server: &TestServer,
    subject_id: &str,
    purpose: Option<&str>,
) -> TestResponse {
    let mut request = server
        .post("/claims/evaluate")
        .add_header("x-api-key", TEST_API_KEY)
        .json(&json!({
            "subject": { "id": subject_id },
            "claims": [CLAIM_ID],
            "disclosure": "value",
        }));
    if let Some(purpose) = purpose {
        request = request.add_header("data-purpose", purpose);
    }
    request.await
}

pub fn assert_problem(response: TestResponse, status: StatusCode, code: &str) -> Value {
    response.assert_status(status);
    let body: Value = response.json();
    assert_eq!(body["status"], json!(status.as_u16()));
    assert_eq!(body["code"], json!(code));
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty()),
        "problem details include bounded detail"
    );
    body
}

pub fn audit_text(harness: &RdaConnectorHarness) -> String {
    std::fs::read_to_string(&harness.audit_path).expect("audit was written")
}

fn set_common_env(source_token_env: &str, source_token: &str) {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    std::env::set_var(TEST_API_KEY_HASH_ENV, TEST_API_KEY_HASH);
    std::env::set_var(source_token_env, source_token);
}

async fn rda_fixture(
    State(state): State<RdaFixtureState>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    state.total.fetch_add(1, Ordering::SeqCst);
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let purpose = headers
        .get("data-purpose")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    state
        .requests
        .lock()
        .expect("captured requests lock")
        .push(CapturedSourceRequest {
            authorization: authorization.clone(),
            purpose: purpose.clone(),
            query: query.clone(),
        });

    if authorization.as_deref() != Some("Bearer source-token") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid source token",
                "source_token_hint": "source-token",
                "private_row": "fixture-private-field",
            })),
        )
            .into_response();
    }
    if purpose.as_deref() != Some(TEST_PURPOSE) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "purpose denied",
                "received_purpose": purpose,
                "private_row": "fixture-private-field",
            })),
        )
            .into_response();
    }
    if query.get("fields").map(String::as_str) != Some("id,total_farmed_area")
        || query.get("limit").map(String::as_str) != Some("2")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match query.get("id").map(String::as_str) {
        Some("person-1") => Json(json!({
            "data": [{
                "id": "person-1",
                "total_farmed_area": 3.5,
                "fixture_private_field": "must-not-disclose",
            }]
        }))
        .into_response(),
        Some("missing-person") => Json(json!({ "data": [] })).into_response(),
        Some("ambiguous-person") => Json(json!({
            "data": [
                {
                    "id": "ambiguous-person",
                    "total_farmed_area": 3.5,
                    "fixture_private_field": "must-not-disclose",
                },
                {
                    "id": "ambiguous-person",
                    "total_farmed_area": 2.5,
                    "fixture_private_field": "must-not-disclose",
                }
            ]
        }))
        .into_response(),
        Some("upstream-error") => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "fixture upstream failed",
                "private_row": "fixture-private-field",
            })),
        )
            .into_response(),
        _ => Json(json!({ "data": [] })).into_response(),
    }
}

fn rda_connector_config(
    base_url: &str,
    audit_path: &str,
    source_token_env: &str,
    retry_on_5xx: bool,
) -> StandaloneRegistryNotaryConfig {
    let raw = format!(
        r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      hash_env: {api_key_hash_env}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: {source_token_env}
      retry_on_5xx: {retry_on_5xx}
      max_in_flight: 2
  claims:
    - id: {claim_id}
      title: Farmed land size
      version: 2026-05
      subject_type: person
      value:
        type: number
        unit: hectare
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: subject_id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: extract
        source: farmer
        field: total_farmed_area
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#,
        api_key_hash_env = TEST_API_KEY_HASH_ENV,
        source_token_env = source_token_env,
        claim_id = CLAIM_ID,
    );
    serde_norway::from_str(&raw).expect("config deserializes")
}
