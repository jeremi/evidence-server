// SPDX-License-Identifier: Apache-2.0
//! Contract tests for source connector behavior at the Notary boundary.

#[path = "common/source_conformance.rs"]
mod source_conformance;

use axum::http::StatusCode;
use serde_json::{json, Value};
use source_conformance::{
    assert_problem, audit_text, evaluate_claim, rda_connector_harness, RdaHarnessOptions,
    TEST_PURPOSE, TEST_SOURCE_TOKEN,
};

#[tokio::test]
async fn rda_connector_conformance_positive_and_non_disclosure() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = evaluate_claim(&harness.server, "person-1", Some(TEST_PURPOSE)).await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["results"][0]["value"], json!(3.5));
    assert_eq!(body["results"][0]["provenance"]["source_count"], json!(1));

    let body_text = serde_json::to_string(&body).expect("body serializes");
    assert!(!body_text.contains(TEST_SOURCE_TOKEN));
    assert!(!body_text.contains("must-not-disclose"));
    assert!(!body_text.contains("fixture_private_field"));

    let requests = harness.source.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer source-token")
    );
    assert_eq!(requests[0].purpose.as_deref(), Some(TEST_PURPOSE));
    assert_eq!(
        requests[0].query.get("id").map(String::as_str),
        Some("person-1")
    );
    assert_eq!(
        requests[0].query.get("fields").map(String::as_str),
        Some("id,total_farmed_area")
    );
    assert_eq!(
        requests[0].query.get("limit").map(String::as_str),
        Some("2")
    );

    let audit = audit_text(&harness);
    assert!(audit.contains("\"decision\":\"evaluate\""));
    assert!(!audit.contains(TEST_SOURCE_TOKEN));
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("must-not-disclose"));
    assert!(!audit.contains("fixture_private_field"));

    let metrics = harness.server.get("/metrics").await;
    metrics.assert_status_ok();
    let metrics_body = metrics.text();
    assert!(metrics_body.contains(
        "registry_notary_source_requests_total{connector=\"rda\",outcome=\"success\"} 1"
    ));
    assert!(!metrics_body.contains(TEST_SOURCE_TOKEN));
    assert!(!metrics_body.contains("person-1"));
    assert!(!metrics_body.contains("must-not-disclose"));
}

#[tokio::test]
async fn rda_connector_conformance_not_found() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = evaluate_claim(&harness.server, "missing-person", Some(TEST_PURPOSE)).await;

    assert_problem(response, StatusCode::NOT_FOUND, "source.not_found");
    assert_eq!(harness.source.total(), 1);
}

#[tokio::test]
async fn rda_connector_conformance_ambiguous() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = evaluate_claim(&harness.server, "ambiguous-person", Some(TEST_PURPOSE)).await;

    assert_problem(response, StatusCode::CONFLICT, "source.ambiguous");
    assert_eq!(harness.source.total(), 1);
}

#[tokio::test]
async fn rda_connector_conformance_source_auth_denied_is_bounded() {
    let harness = rda_connector_harness(RdaHarnessOptions {
        source_token: "wrong-source-token",
        ..RdaHarnessOptions::default()
    })
    .await;

    let response = evaluate_claim(&harness.server, "person-1", Some(TEST_PURPOSE)).await;

    let body = assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let body_text = serde_json::to_string(&body).expect("body serializes");
    assert!(!body_text.contains("wrong-source-token"));
    assert!(!body_text.contains(TEST_SOURCE_TOKEN));
    assert!(!body_text.contains("fixture-private-field"));
    assert_eq!(harness.source.total(), 1);
}

#[tokio::test]
async fn rda_connector_conformance_purpose_denied_is_bounded() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = evaluate_claim(
        &harness.server,
        "person-1",
        Some("https://purpose.example.test/not-allowed"),
    )
    .await;

    let body = assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let body_text = serde_json::to_string(&body).expect("body serializes");
    assert!(!body_text.contains("not-allowed"));
    assert!(!body_text.contains("fixture-private-field"));
    let requests = harness.source.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].purpose.as_deref(),
        Some("https://purpose.example.test/not-allowed")
    );
}

#[tokio::test]
async fn rda_connector_conformance_missing_purpose_fails_before_source_read() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = evaluate_claim(&harness.server, "person-1", None).await;

    assert_problem(response, StatusCode::BAD_REQUEST, "auth.purpose_required");
    assert_eq!(harness.source.total(), 0);
}

#[tokio::test]
async fn rda_connector_conformance_caller_auth_denied_fails_before_source_read() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = harness
        .server
        .post("/claims/evaluate")
        .add_header("data-purpose", TEST_PURPOSE)
        .json(&json!({
            "subject": { "id": "person-1" },
            "claims": ["farmed-land-size"],
            "disclosure": "value",
        }))
        .await;

    assert_problem(
        response,
        StatusCode::UNAUTHORIZED,
        "auth.missing_credential",
    );
    assert_eq!(harness.source.total(), 0);
}

#[tokio::test]
async fn rda_connector_conformance_upstream_error_is_bounded_and_not_retried_by_default() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = evaluate_claim(&harness.server, "upstream-error", Some(TEST_PURPOSE)).await;

    let body = assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let body_text = serde_json::to_string(&body).expect("body serializes");
    assert!(!body_text.contains("fixture upstream failed"));
    assert!(!body_text.contains("fixture-private-field"));
    assert_eq!(
        harness.source.total(),
        1,
        "source connector conformance disables retry by default for synchronous sources"
    );
}

#[tokio::test]
async fn rda_connector_conformance_upstream_4xx_is_bounded() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response =
        evaluate_claim(&harness.server, "upstream-bad-request", Some(TEST_PURPOSE)).await;

    let body = assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let body_text = serde_json::to_string(&body).expect("body serializes");
    assert!(!body_text.contains("fixture rejected lookup"));
    assert!(!body_text.contains("upstream-bad-request"));
    assert!(!body_text.contains("fixture-private-field"));
    assert_eq!(harness.source.total(), 1);
}

#[tokio::test(start_paused = true)]
async fn rda_connector_conformance_upstream_timeout_is_bounded() {
    let harness = rda_connector_harness(RdaHarnessOptions::default()).await;

    let response = {
        let request = evaluate_claim(&harness.server, "upstream-timeout", Some(TEST_PURPOSE));
        tokio::pin!(request);
        tokio::select! {
            response = &mut request => response,
            () = async {
                for _ in 0..100 {
                    if harness.source.total() > 0 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(harness.source.total(), 1);
                tokio::time::advance(std::time::Duration::from_secs(11)).await;
            } => request.await,
        }
    };

    let body = assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let body_text = serde_json::to_string(&body).expect("body serializes");
    assert!(!body_text.contains("upstream-timeout"));
    assert!(!body_text.contains("must-not-disclose"));
    assert!(!body_text.contains("fixture_private_field"));
    assert_eq!(harness.source.total(), 1);
}
