//! Role-projected, read-only operating snapshot for the management console.

use super::{AccessAction, ControlPlane, api_key_authz, no_store, site_config};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use chrono::Utc;
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::admin::{ApiKeyCapability, ManagementRole};
use xshield_postgres::{ProtectedSiteConfigListItem, ProtectedSiteHealthSnapshot};
use xshield_worker::{PublicationHealth, inspect_publication_health};

/// Stable route for the console workbench.
pub const PATH: &str = "/control/v1/workbench/overview";

/// Largest site page projected into one snapshot; a full page is `partial`.
const MAX_SITES: u16 = 128;

/// The edge answers on loopback; a slow answer is reported as unreachable
/// instead of delaying the whole snapshot.
const EDGE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
    // A key sees the workbench only through `site.read`, and only the sites
    // that capability names; people are decided by role as before.
    let auth = match control.authorize_any_identity_or_capability(
        authorization,
        &request_id,
        ACCESS,
        &[
            ManagementRole::Observer,
            ManagementRole::Investigator,
            ManagementRole::AuditAdministrator,
            ManagementRole::SystemAdmin,
        ],
        ApiKeyCapability::SiteRead,
    ) {
        Ok(identity) => identity,
        Err(response) => return response.into_response(),
    };
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let roles = auth.principal.roles();
    let mut completeness = "complete";
    let mut sites = Vec::new();
    // Which sites are projected comes from the principal's own scope, never
    // from its mere role: a tenant-scoped SystemAdmin sees the tenant, a key sees
    // its `site.read` sites, an exact-scope administrator sees its scoped sites.
    if let Some(visibility) = api_key_authz::projected_sites(
        &auth.principal,
        &control.config.tenant_id,
        ManagementRole::SystemAdmin,
    ) {
        match api_key_authz::list_visible_site_configs(&control, &visibility, None, MAX_SITES).await
        {
            Ok(records) => {
                // The store clamps one page to `MAX_SITES`; a full page may
                // hide further sites, so it is reported as partial.
                if records.len() >= usize::from(MAX_SITES) {
                    completeness = "partial";
                }
                let edge = probe_edge(&control).await;
                let mut health = BTreeMap::new();
                match control
                    .catalog
                    .latest_protected_site_health_snapshots(&control.config.tenant_id, MAX_SITES)
                    .await
                {
                    Ok(rows) => {
                        health.extend(rows.into_iter().map(|row| (row.site_id.clone(), row)));
                    }
                    Err(_) => completeness = "partial",
                }
                sites.extend(records.into_iter().map(|record| {
                    let snapshot = health.get(&record.site_id);
                    site_snapshot(record, &now, &edge, snapshot)
                }));
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

/// Live view of the edge process, shared by every site of the tenant.
struct EdgeView {
    configured: bool,
    edge_state: Option<&'static str>,
    audit_state: Option<&'static str>,
}

/// Asks the configured edge for its own health. An unreachable or slow edge is
/// an observed `unavailable`; an edge that is not configured is not observed.
async fn probe_edge(control: &ControlPlane) -> EdgeView {
    let Ok(health) =
        tokio::time::timeout(EDGE_PROBE_TIMEOUT, site_config::edge_health(control)).await
    else {
        return EdgeView {
            configured: true,
            edge_state: Some("unavailable"),
            audit_state: None,
        };
    };
    let state = |field: &str| {
        health
            .get(field)
            .and_then(serde_json::Value::as_str)
            .and_then(static_state)
    };
    EdgeView {
        configured: health.get("edge_state").and_then(serde_json::Value::as_str)
            != Some("unconfigured"),
        edge_state: state("edge_state"),
        audit_state: state("audit_state"),
    }
}

/// Maps a stored or reported state onto the closed vocabulary the console
/// understands; anything else is "not observed".
fn static_state(value: &str) -> Option<&'static str> {
    match value {
        "healthy" => Some("healthy"),
        "degraded" => Some("degraded"),
        "unavailable" => Some("unavailable"),
        _ => None,
    }
}

fn observation(
    state: Option<&'static str>,
    observed_at: &str,
    observed: &'static str,
    missing: &'static str,
) -> Observation<&'static str> {
    match state {
        Some(value) => Observation {
            observed_at: observed_at.to_owned(),
            source_state: "available",
            reason_code: observed,
            value: Some(value),
        },
        None => Observation {
            observed_at: observed_at.to_owned(),
            source_state: "unavailable",
            reason_code: missing,
            value: None,
        },
    }
}

fn site_snapshot(
    record: ProtectedSiteConfigListItem,
    now: &str,
    edge: &EdgeView,
    health: Option<&ProtectedSiteHealthSnapshot>,
) -> SiteSnapshot {
    let edge_state = edge.configured.then_some(edge.edge_state).flatten();
    let audit_state = edge.configured.then_some(edge.audit_state).flatten();
    let upstream = match health {
        Some(snapshot) => observation(
            static_state(&snapshot.upstream_state),
            &snapshot
                .captured_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "WORKBENCH_UPSTREAM_LAST_OBSERVED",
            "WORKBENCH_UPSTREAM_STATE_UNKNOWN",
        ),
        None => observation(
            None,
            now,
            "WORKBENCH_UPSTREAM_LAST_OBSERVED",
            "WORKBENCH_UPSTREAM_NEVER_OBSERVED",
        ),
    };
    SiteSnapshot {
        site_id: record.site_id,
        display_name: record.display_name,
        public_origin: record.public_origin,
        edge: observation(
            edge_state,
            now,
            "WORKBENCH_EDGE_PROBED",
            if edge.configured {
                "WORKBENCH_EDGE_STATE_UNKNOWN"
            } else {
                "WORKBENCH_EDGE_NOT_CONFIGURED"
            },
        ),
        upstream,
        audit: observation(
            audit_state,
            now,
            "WORKBENCH_EDGE_AUDIT_PROBED",
            "WORKBENCH_EDGE_AUDIT_UNKNOWN",
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn record() -> ProtectedSiteConfigListItem {
        ProtectedSiteConfigListItem {
            site_id: "site_a".to_owned(),
            display_name: "A".to_owned(),
            public_origin: "https://a.example".to_owned(),
            listen_port: 6100,
            security_entry: "ui_action_required".to_owned(),
            sensor_enabled: false,
            policy_revision: "policy-v1".to_owned(),
            status: "active".to_owned(),
            revision: 3,
            config_digest: [0; 32],
            updated_by: "alice".to_owned(),
            updated_at: Utc.with_ymd_and_hms(2026, 10, 4, 1, 2, 3).unwrap(),
            desired_revision: 3,
            active_revision: Some(3),
            apply_id: "apply_1".to_owned(),
            apply_state: "active".to_owned(),
            reason_code: "CONTROL_SITE_APPLY_ACTIVE".to_owned(),
            requires_approval: false,
        }
    }

    fn snapshot(upstream_state: &str) -> ProtectedSiteHealthSnapshot {
        ProtectedSiteHealthSnapshot {
            site_id: "site_a".to_owned(),
            captured_at: Utc.with_ymd_and_hms(2026, 10, 4, 1, 0, 0).unwrap(),
            edge_state: "healthy".to_owned(),
            upstream_state: upstream_state.to_owned(),
            config_state: "active".to_owned(),
            audit_state: "healthy".to_owned(),
            reason_code: "CONTROL_SITE_HEALTH_OBSERVED".to_owned(),
        }
    }

    fn view(site: &SiteSnapshot, field: &str) -> serde_json::Value {
        serde_json::to_value(site).unwrap()[field].clone()
    }

    #[test]
    fn live_edge_and_last_upstream_observation_are_reported_with_their_own_times() {
        let edge = EdgeView {
            configured: true,
            edge_state: Some("healthy"),
            audit_state: Some("unavailable"),
        };
        let site = site_snapshot(
            record(),
            "2026-10-04T02:00:00Z",
            &edge,
            Some(&snapshot("degraded")),
        );
        let edge_view = view(&site, "edge");
        assert_eq!(edge_view["value"], "healthy");
        assert_eq!(edge_view["observed_at"], "2026-10-04T02:00:00Z");
        // A failed durable-audit barrier is an observed state, not a missing one.
        let audit = view(&site, "audit");
        assert_eq!(audit["value"], "unavailable");
        assert_eq!(audit["source_state"], "available");
        let upstream = view(&site, "upstream");
        assert_eq!(upstream["value"], "degraded");
        assert_eq!(upstream["observed_at"], "2026-10-04T01:00:00Z");
        assert_eq!(upstream["reason_code"], "WORKBENCH_UPSTREAM_LAST_OBSERVED");
    }

    #[test]
    fn missing_sources_stay_unobserved_instead_of_guessed() {
        let unconfigured = EdgeView {
            configured: false,
            edge_state: None,
            audit_state: None,
        };
        let site = site_snapshot(record(), "2026-10-04T02:00:00Z", &unconfigured, None);
        for field in ["edge", "upstream", "audit"] {
            let observation = view(&site, field);
            assert_eq!(observation["source_state"], "unavailable", "{field}");
            assert!(observation["value"].is_null(), "{field}");
        }
        assert_eq!(
            view(&site, "edge")["reason_code"],
            "WORKBENCH_EDGE_NOT_CONFIGURED"
        );
        assert_eq!(
            view(&site, "upstream")["reason_code"],
            "WORKBENCH_UPSTREAM_NEVER_OBSERVED"
        );

        // An unknown stored state is also "not observed", never "healthy".
        let site = site_snapshot(
            record(),
            "2026-10-04T02:00:00Z",
            &unconfigured,
            Some(&snapshot("unknown")),
        );
        assert_eq!(
            view(&site, "upstream")["reason_code"],
            "WORKBENCH_UPSTREAM_STATE_UNKNOWN"
        );
        assert!(view(&site, "upstream")["value"].is_null());
    }

    #[test]
    fn static_state_accepts_only_the_closed_vocabulary() {
        assert_eq!(static_state("healthy"), Some("healthy"));
        assert_eq!(static_state("unavailable"), Some("unavailable"));
        assert_eq!(static_state("unconfigured"), None);
        assert_eq!(static_state("HEALTHY"), None);
    }
}
