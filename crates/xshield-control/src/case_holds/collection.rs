//! Scope-bound, live hold-history pages; no content-read entitlement is issued.

use super::{
    AccessAction, ControlPlane, EndpointResult, Failure, HoldResponse, PATH, STORE_DEADLINE,
    audit_unavailable, component_signature, internal_error, single_header,
};
use crate::{CURSOR_VERSION, CursorError, lower_hex, parse_cursor_query, parse_lower_hex_32};
use axum::{
    Json,
    extract::{Path, RawQuery, State, rejection::PathRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use openssl::memcmp;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{CaseId, EventId},
};
use xshield_postgres::CaseEvidenceHoldQuery;

const ACCESS: AccessAction = AccessAction {
    event_type: "console.evidence.hold.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::AuditAdministrator,
};

#[derive(Serialize)]
struct CollectionResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    case_id: String,
    case_status: &'static str,
    as_of: String,
    items: Vec<HoldResponse>,
    truncated: bool,
    next_cursor: Option<String>,
}

pub(crate) async fn list_handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    control
        .read_holds(
            single_header(&headers, "authorization"),
            target.ok().map(|Path(id)| id),
            query,
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn read_holds(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
        query: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request, ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let Some(case) = target.and_then(|id| CaseId::parse(id).ok()) else {
            return self
                .finish_hold_collection(request_id, subject, None, Err(Failure::CaseId))
                .await;
        };
        let after = match parse_cursor_query(query.as_deref()).and_then(|cursor| {
            cursor
                .map(|cursor| self.decode_hold_cursor(&subject, &case, cursor))
                .transpose()
        }) {
            Ok(after) => after,
            Err(error) => {
                return self
                    .finish_hold_collection(
                        request_id,
                        subject,
                        Some(case),
                        Err(match error {
                            CursorError::Invalid => Failure::Cursor,
                            CursorError::Unavailable => Failure::CursorUnavailable,
                        }),
                    )
                    .await;
            }
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .finish_hold_collection(request_id, subject, Some(case), Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // Admission survives disconnection until the read and required audit finish.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .query_holds(&task_request, &subject, &case, after.as_ref())
                .await;
            self.finish_hold_collection(task_request, subject, Some(case), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn query_holds(
        &self,
        request_id: &str,
        subject: &str,
        case: &CaseId,
        after: Option<&EventId>,
    ) -> Result<CollectionResponse, Failure> {
        let query = CaseEvidenceHoldQuery::new(
            &self.config.tenant_id,
            &self.config.site_id,
            case,
            after,
            self.config.limits.max_query_artifacts,
        )
        .map_err(|_| Failure::Store)?;
        let page =
            tokio::time::timeout(STORE_DEADLINE, self.catalog.list_case_evidence_holds(query))
                .await
                .map_err(|_| Failure::Store)?
                .map_err(|_| Failure::Store)?
                .ok_or(Failure::Target)?;
        let next_cursor = page
            .next_hold_id()
            .map(|id| {
                self.hold_cursor_signature(subject, case, id)
                    .map(|signature| {
                        format!("{CURSOR_VERSION}.{}.{}", id.as_str(), lower_hex(&signature))
                    })
            })
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        Ok(CollectionResponse {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            case_id: page.case_id().as_str().to_owned(),
            case_status: page.case_status(),
            as_of: page.as_of().to_rfc3339_opts(SecondsFormat::Micros, true),
            items: page.items().iter().map(HoldResponse::from).collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn finish_hold_collection(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target: Option<CaseId>,
        result: Result<CollectionResponse, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |error| (error.outcome(), error.code()),
                |_| ("PASS", "CONTROL_EVIDENCE_HOLD_READ"),
            );
            // Successive holds may reference the same artifact; envelope refs are a set.
            let mut refs = result
                .as_ref()
                .map(|page| {
                    page.items
                        .iter()
                        .map(|item| item.artifact_id.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            refs.sort_unstable();
            refs.dedup();
            self.append_access_event_with_evidence(
                &audit_request,
                Some(&subject),
                ACCESS,
                None,
                None,
                target.as_ref(),
                None,
                outcome,
                reason,
                &refs,
            )?;
            Ok::<_, crate::ControlError>(result)
        })
        .await;
        let Ok(Ok(result)) = audited else {
            return audit_unavailable(&request_id);
        };
        match result {
            Ok(response) => EndpointResult::Raw((StatusCode::OK, Json(response)).into_response()),
            Err(error) => error.response(&request_id),
        }
    }

    fn decode_hold_cursor(
        &self,
        subject: &str,
        case: &CaseId,
        cursor: &str,
    ) -> Result<EventId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some(version), Some(id), Some(signature)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if version != CURSOR_VERSION || parts.next().is_some() {
            return Err(CursorError::Invalid);
        }
        let id = EventId::parse(id).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .hold_cursor_signature(subject, case, &id)
            .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(id)
    }

    fn hold_cursor_signature(
        &self,
        subject: &str,
        case: &CaseId,
        id: &EventId,
    ) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                b"xshield-control-case-hold-cursor-v1",
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                case.as_str().as_bytes(),
                &self.config.limits.max_query_artifacts.to_be_bytes(),
                id.as_str().as_bytes(),
            ],
        )
    }
}
