// SPDX-License-Identifier: Apache-2.0
//! Client-owned response DTOs and ergonomic wrappers.

use registry_notary_core::{BatchEvaluateResponse, BatchItemResponse, ClaimResultView};
use serde::{Deserialize, Serialize};

use crate::options::RetryAfter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub results: Vec<ClaimResultView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListClaimsResponse {
    pub data: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatsResponse {
    pub formats: Vec<registry_notary_core::EvidenceFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssueResponse {
    pub credential_id: String,
    pub credential_profile: String,
    pub format: String,
    pub issuer: String,
    pub expires_at: String,
    pub credential: String,
    pub issuer_signed_jwt: String,
    pub disclosures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusResponse {
    pub credential_id: String,
    pub issuer: String,
    pub credential_profile: String,
    pub status: String,
    pub issued_at: String,
    pub expires_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusUpdateRequest {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminReloadResponse {
    pub reloaded: bool,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub checks: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct NotaryResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
    pub retry_after: Option<RetryAfter>,
}

impl<T> NotaryResponse<T> {
    pub(crate) fn map<U>(self, body: U) -> NotaryResponse<U> {
        NotaryResponse {
            body,
            request_id: self.request_id,
            retry_after: self.retry_after,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub results: Vec<ClaimResultView>,
}

impl Evaluation {
    #[must_use]
    pub fn evaluation_id(&self) -> Option<&str> {
        self.results
            .first()
            .map(|result| result.evaluation_id.as_str())
    }

    #[must_use]
    pub fn first_result(&self) -> Option<&ClaimResultView> {
        self.results.first()
    }

    #[must_use]
    pub fn result_for(&self, claim_id: &str) -> Option<&ClaimResultView> {
        self.results
            .iter()
            .find(|result| result.claim_id == claim_id)
    }
}

#[derive(Debug, Clone)]
pub struct BatchEvaluation {
    pub inner: BatchEvaluateResponse,
}

impl BatchEvaluation {
    pub fn succeeded(&self) -> impl Iterator<Item = &BatchItemResponse> {
        self.inner.items.iter().filter(|item| {
            matches!(
                item.status,
                registry_notary_core::BatchItemStatus::Succeeded
            )
        })
    }

    pub fn failed(&self) -> impl Iterator<Item = &BatchItemResponse> {
        self.inner
            .items
            .iter()
            .filter(|item| matches!(item.status, registry_notary_core::BatchItemStatus::Failed))
    }
}
