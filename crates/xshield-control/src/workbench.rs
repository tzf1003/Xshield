//! Role-projected, read-only operating snapshot for the management console.

use super::{AccessAction, ControlPlane, no_store};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use chrono::Utc;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::admin::ManagementRole;
use xshield_postgres::ProtectedSiteConfigListItem;
use xshield_worker::{PublicationHealth, inspect_publication_health};

/// Stable route for the console workbench.
pub const PATH: &str = "/control/v1/workbench/overview";

/// Largest site page projected into one snapshot; a full page is `partial`.
const MAX_SITES: u16 = 128;

const ACCESS: AccessAction = AccessAction {
    event_type: "console.workbench.overview.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::Observer,
};

#[derive(Serialize)]
struct Observation<T> {
    observed_at: String,
    source_state: &'static str,
    reason_code: &'static str,
    value: Option<T>,
}

#[derive(Serialize)]
struct SiteSnapshot {
    site_id: String,
    display_name: String,
    public_origin: String,
    edge: Observation<&'static str>,
    upstream: Observation<&'static str>,
    audit: Observation<&'static str>,
    current_revision: Option<u64>,
    apply_state: String,
    reason_code: String,
    updated_at: String,
}

#[derive(Serialize)]
struct OverviewResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    as_of: String,
    completeness: &'static str,
    index_watermark: Option<xshield_worker::IndexWatermark>,
    has_gaps: bool,
    posture: Observation<&'static str>,
    sites: Vec<SiteSnapshot>,
    queues: Vec<serde_json::Value>,
    recent_activity: Vec<serde_json::Value>,
    audit: Observation<PublicationHealth>,
}

/// Returns a bounded server-scoped snapshot. The browser supplies no tenant or
/// site selector; all projection decisions come from the authenticated principal.
pub async fn handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = format!("req_{}", Uuid::now_v7());
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let auth = match control.authorize_any_identity(
        authorization,
        &request_id,
        ACCESS,
        &[
            ManagementRole::Observer,
            ManagementRole::Investigator,
            ManagementRole::AuditAdministrator,
            ManagementRole::SystemAdmin,
        ],
    ) {
        Ok(identity) => identity,
        Err(response) => return response.into_response(),
    };
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let roles = auth.principal.roles();
    let mut completeness = "complete";
    let mut sites = Vec::new();
    if roles.contains(&ManagementRole::SystemAdmin) {
        match control
            .catalog
            .list_protected_site_configs(&control.config.tenant_id, None, MAX_SITES)
            .await
        {
            Ok(records) => {
                // The store clamps one page to `MAX_SITES`; a full page may
                // hide further sites, so it is reported as partial.
                if records.len() >= usize::from(MAX_SITES) {
                    completeness = "partial";
                }
                sites.extend(
                    records
                        .into_iter()
                        .map(|record| site_snapshot(record, &now)),
                );
            }
            Err(_) => completeness = "partial",
        }
    } else {
        completeness = "partial";
    }
    // A principal without the audit role, or a failed health read, yields an
    // explicit "unavailable" observation instead of a guessed state.
    let audit = if roles.contains(&ManagementRole::AuditAdministrator) {
        inspect_publication_health(
            &control.config.publisher,
            &control.config.source_journal_key_id,
            &control.source_journal_key,
            &control.seal_key,
        )
        .ok()
    } else {
        None
    };
    if audit.is_none() {
        completeness = "partial";
    }
    response(
        &control,
        &auth,
        request_id,
        &now,
        completeness,
        sites,
        audit,
    )
}

fn site_snapshot(record: ProtectedSiteConfigListItem, now: &str) -> SiteSnapshot {
    let unavailable = |reason_code| Observation {
        observed_at: now.to_owned(),
        source_state: "unavailable",
        reason_code,
        value: None,
    };
    SiteSnapshot {
        site_id: record.site_id,
        display_name: record.display_name,
        public_origin: record.public_origin,
        edge: unavailable("WORKBENCH_EDGE_STATUS_UNAVAILABLE"),
        upstream: unavailable("WORKBENCH_UPSTREAM_STATUS_UNAVAILABLE"),
        audit: unavailable("WORKBENCH_SITE_AUDIT_STATUS_UNAVAILABLE"),
        current_revision: record.active_revision,
        apply_state: record.apply_state,
        reason_code: record.reason_code,
        updated_at: record
            .updated_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

fn response(
    control: &ControlPlane,
    auth: &super::identity::VerifiedRequestIdentity,
    request_id: String,
    as_of: &str,
    completeness: &'static str,
    sites: Vec<SiteSnapshot>,
    audit: Option<PublicationHealth>,
) -> axum::response::Response {
    let has_gaps = audit.as_ref().is_some_and(|value| value.has_gaps);
    let watermark = audit
        .as_ref()
        .and_then(|value| value.index_watermark.clone());
    let audit_observation = match audit {
        Some(value) => Observation {
            observed_at: as_of.to_owned(),
            source_state: "available",
            reason_code: "WORKBENCH_AUDIT_READ",
            value: Some(value),
        },
        None => Observation {
            observed_at: as_of.to_owned(),
            source_state: "unavailable",
            reason_code: "WORKBENCH_AUDIT_NOT_AUTHORIZED",
            value: None,
        },
    };
    if control
        .append_access_event(
            &request_id,
            Some(auth.principal.subject()),
            ACCESS,
            None,
            "PASS",
            "WORKBENCH_OVERVIEW_READ",
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    no_store(
        (
            StatusCode::OK,
            Json(OverviewResponse {
                request_id,
                tenant_id: control.config.tenant_id.as_str().to_owned(),
                site_id: control.config.site_id.as_str().to_owned(),
                as_of: as_of.to_owned(),
                completeness,
                index_watermark: watermark,
                has_gaps,
                posture: Observation {
                    observed_at: as_of.to_owned(),
                    source_state: "available",
                    reason_code: "WORKBENCH_POSTURE_SCOPED",
                    value: Some(if has_gaps { "degraded" } else { "observed" }),
                },
                sites,
                queues: Vec::new(),
                recent_activity: Vec::new(),
                audit: audit_observation,
            }),
        )
            .into_response(),
    )
}
