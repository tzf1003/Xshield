//! Page-root admission, page-delivery issuance and bootstrap reference lookup.
//!
//! Trust boundary: a top-level browser navigation carries the `HttpOnly` WAF
//! cookie but never the application's `Authorization` header. A configured
//! page root (`SENSOR_HTML` with `page_actions`) is therefore admitted from the
//! WAF session alone when no credential is presented, and only for that exact
//! digest-pinned document. Everything issued from it is bound to the session's
//! binding and epoch and re-verified against the complete credential set when
//! presented. The bootstrap likewise reads references only for the session
//! that owns the page instance; a handle copied into another session yields
//! nothing.

use super::{
    IdentityRuntimeError, MAX_SESSION_BYTES, ProtectedAdmission, ProtectedIdentity,
    ResponseIdentity, WAF_COOKIE, denied, denied_reason, fingerprint, response_issue::hex,
    response_issue::prefixed_uuid, transaction_envelope, unique_cookie,
};
use chrono::{DateTime, SecondsFormat};
use pingora::http::RequestHeader;
use serde_json::json;
use std::collections::BTreeSet;
use uuid::{Uuid, Version};
use xshield_core::{
    admission::AdmissionProof,
    audit::ReasonCode,
    domain::{ActionRef, EventId, PageEvidenceId, RequestId, WafSessionId},
    identity::{IdentityDenied, UnixSeconds},
    ports::IdentityProofState,
    provenance::{
        ActionGrant, ActionGrantDraft, ActionTarget, BuildFingerprint, PageEvidence,
        ProvenanceError,
    },
};
use xshield_gateway::{GatewayConfig, GatewayOutcome, page_actions::PageActionPlan};
use xshield_postgres::{
    DocumentSessionQuery, PageActionQuery, PageActionView, PageProvenanceBatch,
    PageProvenanceOutcome, ProvenancePersistence, SensorSessionQuery, SensorSessionState,
};

/// What the bootstrap may deliver for one request.
pub(crate) enum SensorBootstrapDelivery {
    /// No page handle was named: the frozen 1.0.0 document shape.
    Legacy,
    /// One page instance; `actions` is empty unless this session owns it.
    Page {
        page_handle: String,
        actions: Vec<PageActionView>,
    },
}

/// Parsed bootstrap query: absent, exactly one `page=pgh_<UUIDv7>`, or invalid.
enum BootstrapQuery<'a> {
    Legacy,
    Page(&'a str),
    Invalid,
}

fn bootstrap_query(query: Option<&str>) -> BootstrapQuery<'_> {
    let Some(query) = query else {
        return BootstrapQuery::Legacy;
    };
    match query.strip_prefix("page=") {
        Some(handle) if page_evidence_id(handle).is_some() => BootstrapQuery::Page(handle),
        _ => BootstrapQuery::Invalid,
    }
}

/// Maps an edge-generated page handle to its page evidence ID (same UUID).
pub(crate) fn page_evidence_id(page_handle: &str) -> Option<PageEvidenceId> {
    let uuid = page_handle.strip_prefix("pgh_")?;
    let parsed = Uuid::parse_str(uuid).ok()?;
    if parsed.get_version() != Some(Version::SortRand) || parsed.hyphenated().to_string() != uuid {
        return None;
    }
    PageEvidenceId::parse(format!("page_{uuid}")).ok()
}

/// A browser `fetch` from this origin, or a non-browser client that sends no
/// fetch metadata. Navigations and cross-site requests receive no references.
fn same_origin_fetch(request: &RequestHeader) -> bool {
    let mut sites = request.headers.get_all("sec-fetch-site").iter();
    match (sites.next(), sites.next()) {
        (None, _) => true,
        (Some(site), None) => site.as_bytes() == b"same-origin",
        (Some(_), Some(_)) => false,
    }
}

impl ProtectedIdentity {
    /// Admits a configured page root from the WAF session alone. Called only
    /// when the request presents no `Authorization` header; a presented
    /// credential always takes the complete-credential path instead.
    pub(super) async fn admit_page_session(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<ProtectedAdmission, IdentityRuntimeError> {
        let session = match unique_cookie(request, WAF_COOKIE) {
            Ok(session) if session.len() <= MAX_SESSION_BYTES => session,
            Ok(_) | Err(IdentityRuntimeError::Malformed | IdentityRuntimeError::Missing) => {
                return Ok(ProtectedAdmission::without_identity(denied(
                    config,
                    method,
                    path,
                    now,
                    IdentityDenied::BindingMismatch,
                )));
            }
            Err(error) => return Err(error),
        };
        let Ok(session_id) = WafSessionId::parse(session) else {
            return Ok(ProtectedAdmission::without_identity(denied(
                config,
                method,
                path,
                now,
                IdentityDenied::BindingMismatch,
            )));
        };
        let session_fingerprint = fingerprint(&self.fingerprint_key, session.as_bytes())?;
        let state = self
            .store()
            .await?
            .load_document_session(DocumentSessionQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                session_id: &session_id,
                session_fingerprint: &session_fingerprint,
                now,
            })
            .await?;
        Ok(match state {
            IdentityProofState::Verified { binding, snapshot } => {
                let mut decision = config.admit_with_proof(
                    method,
                    path,
                    now,
                    AdmissionProof::Authenticated {
                        binding: &binding,
                        snapshot: &snapshot,
                    },
                );
                if decision.outcome == GatewayOutcome::Allowed {
                    decision.reason_code = ReasonCode::PageRootSessionAllowed;
                }
                ProtectedAdmission {
                    response_identity: Some(ResponseIdentity {
                        binding,
                        snapshot,
                        share_source: None,
                    }),
                    ..ProtectedAdmission::without_identity(decision)
                }
            }
            IdentityProofState::Denied(error) => {
                ProtectedAdmission::without_identity(denied(config, method, path, now, error))
            }
        })
    }

    /// Resolves what the versioned bootstrap may deliver. Store failures are
    /// returned as errors so the request fails closed with a dependency status.
    pub(super) async fn admit_sensor_bootstrap(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<ProtectedAdmission, IdentityRuntimeError> {
        let decision = config.admit(method, path, now);
        let page_handle = match bootstrap_query(request.uri.query()) {
            BootstrapQuery::Legacy => {
                return Ok(ProtectedAdmission {
                    sensor_bootstrap: Some(SensorBootstrapDelivery::Legacy),
                    ..ProtectedAdmission::without_identity(decision)
                });
            }
            BootstrapQuery::Invalid => {
                return Ok(ProtectedAdmission::without_identity(denied_reason(
                    config,
                    method,
                    path,
                    now,
                    ReasonCode::SensorBootstrapInvalid,
                )));
            }
            BootstrapQuery::Page(page_handle) => page_handle,
        };
        let actions = self
            .session_page_actions(config, request, page_handle, now)
            .await?;
        Ok(ProtectedAdmission {
            sensor_bootstrap: Some(SensorBootstrapDelivery::Page {
                page_handle: page_handle.to_owned(),
                actions,
            }),
            ..ProtectedAdmission::without_identity(decision)
        })
    }

    async fn session_page_actions(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        page_handle: &str,
        now: UnixSeconds,
    ) -> Result<Vec<PageActionView>, IdentityRuntimeError> {
        let Some(page_evidence_id) = page_evidence_id(page_handle) else {
            return Ok(Vec::new());
        };
        let session = match unique_cookie(request, WAF_COOKIE) {
            Ok(session) if session.len() <= MAX_SESSION_BYTES && same_origin_fetch(request) => {
                session
            }
            Ok(_) | Err(IdentityRuntimeError::Missing | IdentityRuntimeError::Malformed) => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        if WafSessionId::parse(session).is_err() {
            return Ok(Vec::new());
        }
        let session_fingerprint = fingerprint(&self.fingerprint_key, session.as_bytes())?;
        let store = self.store().await?;
        let SensorSessionState::Verified(sensor_session) = store
            .load_sensor_session(SensorSessionQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                session_fingerprint: &session_fingerprint,
                now,
            })
            .await?
        else {
            return Ok(Vec::new());
        };
        if !sensor_session.authenticated() {
            return Ok(Vec::new());
        }
        Ok(store
            .load_page_actions(PageActionQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                binding_id: sensor_session.binding_id(),
                epoch: sensor_session.epoch(),
                page_evidence_id: &page_evidence_id,
                policy_revision: config.policy_revision(),
                now,
            })
            .await?)
    }

    /// Issues every action the delivered page root declares, atomically.
    ///
    /// Evidence names the page operation as its template and the verified
    /// origin digest as its build. Each action lease is the configured TTL
    /// capped by the binding's absolute expiry; the evidence lease is the
    /// longest action lease. References and event IDs are HMAC-derived from
    /// the request and page instance, so a retry reproduces them exactly.
    /// Returns the issued count or the stable reason the page holds none.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn issue_page_actions(
        &self,
        config: &GatewayConfig,
        identity: &ResponseIdentity,
        plan: &PageActionPlan,
        request_id: &RequestId,
        trace_id: &str,
        page_handle: &str,
        origin_sha256: &str,
        injected_sha256: &str,
        now: UnixSeconds,
    ) -> Result<usize, ReasonCode> {
        let page_evidence_id =
            page_evidence_id(page_handle).ok_or(ReasonCode::UiEvidenceUnverified)?;
        let session_end = identity.binding.absolute_expires_at().value();
        let lease = |ttl: u64| now.value().saturating_add(ttl).min(session_end);
        let evidence_expiry = plan
            .actions()
            .iter()
            .map(|action| lease(action.ttl_seconds()))
            .max()
            .filter(|expiry| *expiry > now.value())
            .ok_or(ReasonCode::UiActionExpiryInvalid)?;
        let evidence = PageEvidence::verified(
            page_evidence_id.clone(),
            &identity.binding,
            identity.snapshot.clone(),
            request_id.clone(),
            plan.page_template().clone(),
            BuildFingerprint::parse(origin_sha256).map_err(ProvenanceError::reason_code)?,
            config.policy_revision().clone(),
            plan.mapping_revision().clone(),
            UnixSeconds::new(evidence_expiry),
            now,
        )
        .map_err(ProvenanceError::reason_code)?;
        let timestamp = i64::try_from(now.value())
            .ok()
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            .ok_or(ReasonCode::ClockUnavailable)?
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut grants = Vec::with_capacity(plan.actions().len());
        let mut events = Vec::with_capacity(plan.actions().len());
        for (index, action) in plan.actions().iter().enumerate() {
            let descriptor = action.descriptor();
            let item_digest = self.digest(&[
                b"page-action-v1",
                request_id.as_str().as_bytes(),
                page_evidence_id.as_str().as_bytes(),
                descriptor.action_id().as_str().as_bytes(),
                plan.mapping_revision().as_str().as_bytes(),
            ])?;
            let grant = ActionGrant::issue(
                &identity.binding,
                &identity.snapshot,
                &evidence,
                descriptor,
                ActionGrantDraft {
                    action_ref: ActionRef::parse(format!("action.{}", hex(item_digest)))
                        .map_err(|_| ReasonCode::UiActionNotAvailable)?,
                    target: ActionTarget::None,
                    fields: BTreeSet::new(),
                    expires_at: UnixSeconds::new(lease(action.ttl_seconds())),
                },
                now,
            )
            .map_err(ProvenanceError::reason_code)?;
            let event_id = EventId::parse(prefixed_uuid(
                "ev_",
                request_id,
                self.digest(&[b"page-action-event-v1", &item_digest])?,
            )?)
            .map_err(|_| ReasonCode::UiActionNotAvailable)?;
            let sequence =
                u64::try_from(index + 1).map_err(|_| ReasonCode::UiActionNotAvailable)?;
            let payload = issued_payload(&grant, &evidence, plan.actions().len(), origin_sha256);
            events.push((
                event_id.clone(),
                transaction_envelope(
                    config,
                    request_id,
                    trace_id,
                    &event_id,
                    "ui_action.issued",
                    "gateway-ui-action",
                    sequence,
                    &timestamp,
                    &payload,
                )?,
            ));
            grants.push(grant);
        }
        let artifact_ref = format!("sha256.{injected_sha256}");
        let items = grants
            .iter()
            .zip(&events)
            .map(|(grant, (event_id, envelope))| {
                ProvenancePersistence::new(&evidence, grant, &artifact_ref, event_id, envelope, now)
                    .map_err(|_| ReasonCode::UiActionNotAvailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.persist_page(items, plan.max_active_pages()).await
    }

    async fn persist_page(
        &self,
        items: Vec<ProvenancePersistence<'_>>,
        max_active_pages: u32,
    ) -> Result<usize, ReasonCode> {
        let count = items.len();
        let batch = PageProvenanceBatch::new(items, max_active_pages)
            .map_err(|_| ReasonCode::UiActionNotAvailable)?;
        match self
            .store()
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
            .persist_page_provenance(batch)
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
        {
            PageProvenanceOutcome::Created | PageProvenanceOutcome::Existing => Ok(count),
            denied => Err(denied.reason_code()),
        }
    }
}

/// Closed `ui_action.issued` payload; the worker's `ui_action` family parser
/// accepts exactly these members. References stay in the `SENSITIVE` payload.
fn issued_payload(
    grant: &ActionGrant,
    evidence: &PageEvidence,
    action_count: usize,
    build_fingerprint: &str,
) -> serde_json::Value {
    json!({
        "stage": "ui_action",
        "outcome": "PASS",
        "reason_code": ReasonCode::UiActionIssued.as_str(),
        "action_ref": grant.action_ref().as_str(),
        "action_id": grant.action_id().as_str(),
        "binding_id": evidence.snapshot().binding_id().as_str(),
        "auth_epoch": evidence.snapshot().epoch().value(),
        "page_evidence_id": evidence.evidence_id().as_str(),
        "page_template": evidence.page_template().as_str(),
        "build_fingerprint": build_fingerprint,
        "operation_id": grant.operation_id().as_str(),
        "method": grant.method().as_str(),
        "route_template": grant.route().as_str(),
        "field_profile": grant.field_profile().as_str(),
        "fields": [],
        "target_kind": "none",
        "mapping_revision": grant.mapping_revision().as_str(),
        "action_count": action_count,
        "issued_at_unix": grant.issued_at().value(),
        "expires_at_unix": grant.expires_at().value(),
        "page_expires_at_unix": evidence.expires_at().value(),
    })
}

#[cfg(test)]
mod tests {
    use super::{BootstrapQuery, bootstrap_query, page_evidence_id, same_origin_fetch};
    use pingora::http::RequestHeader;

    const HANDLE: &str = "pgh_018f2a3b-4c5d-7000-8000-000000000001";

    #[test]
    fn bootstrap_names_at_most_one_canonical_page_handle() {
        assert!(matches!(bootstrap_query(None), BootstrapQuery::Legacy));
        assert!(matches!(
            bootstrap_query(Some(&format!("page={HANDLE}"))),
            BootstrapQuery::Page(HANDLE)
        ));
        for query in [
            String::new(),
            "page=".to_owned(),
            format!("page={HANDLE}&page={HANDLE}"),
            format!("page={HANDLE}&v=1"),
            format!("v=1&page={HANDLE}"),
            "page=pgh_018f2a3b-4c5d-4000-8000-000000000001".to_owned(),
            "page=pgh_018F2A3B-4C5D-7000-8000-000000000001".to_owned(),
            "page=pgh_018f2a3b4c5d70008000000000000001".to_owned(),
            format!("page={}", HANDLE.replace("pgh_", "page_")),
        ] {
            assert!(
                matches!(bootstrap_query(Some(&query)), BootstrapQuery::Invalid),
                "{query}"
            );
        }
        assert_eq!(
            page_evidence_id(HANDLE).unwrap().as_str(),
            "page_018f2a3b-4c5d-7000-8000-000000000001"
        );
    }

    #[test]
    fn references_go_only_to_same_origin_fetches() {
        let mut request = RequestHeader::build("GET", b"/__xshield/v1/bootstrap", None).unwrap();
        assert!(same_origin_fetch(&request));
        request
            .insert_header("Sec-Fetch-Site", "same-origin")
            .unwrap();
        assert!(same_origin_fetch(&request));
        for site in ["cross-site", "same-site", "none"] {
            request.insert_header("Sec-Fetch-Site", site).unwrap();
            assert!(!same_origin_fetch(&request), "{site}");
        }
        request
            .insert_header("Sec-Fetch-Site", "same-origin")
            .unwrap();
        request
            .append_header("Sec-Fetch-Site", "same-origin")
            .unwrap();
        assert!(!same_origin_fetch(&request));
    }
}
