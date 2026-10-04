//! Authenticated loopback control channel for atomic edge snapshot loading.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use xshield_core::{GatewayApplyAck, GatewayApplyRequest};

use crate::durable_audit::AuditReadiness;
use crate::listener_supervisor::{ApplyError, ListenerSupervisor};
use xshield_gateway::{MAX_CONFIG_BYTES, multi_site::GatewaySnapshot};

const SIGNATURE_HEADER: &str = "x-xshield-apply-signature";
const MAX_APPLY_BYTES: usize = MAX_CONFIG_BYTES * 8;

/// Authenticated state shared by the loopback apply handler.
#[derive(Clone)]
pub struct ApplyState {
    supervisor: Arc<ListenerSupervisor>,
    tenant_id: String,
    key: [u8; 32],
    snapshot_path: Option<Arc<PathBuf>>,
    apply_lock: Arc<Mutex<()>>,
    audit: AuditReadiness,
}

impl ApplyState {
    /// Creates an apply endpoint bound to one deployment tenant.
    #[must_use]
    pub fn new(
        supervisor: Arc<ListenerSupervisor>,
        tenant_id: String,
        key: [u8; 32],
        snapshot_path: Option<PathBuf>,
        audit: AuditReadiness,
    ) -> Self {
        Self {
            supervisor,
            tenant_id,
            key,
            snapshot_path: snapshot_path.map(Arc::new),
            apply_lock: Arc::new(Mutex::new(())),
            audit,
        }
    }
}

/// Serves the internal edge apply API. The caller must bind `listener` to a
/// loopback or private management socket before calling this function.
pub async fn serve(listener: TcpListener, state: ApplyState) -> Result<(), std::io::Error> {
    axum::serve(listener, router(state)).await
}

fn router(state: ApplyState) -> Router {
    Router::new()
        .route("/internal/v1/apply", post(apply_handler))
        .route("/internal/v1/health", get(health_handler))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_APPLY_BYTES))
        .with_state(state)
}

async fn apply_handler(
    State(state): State<ApplyState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut signatures = headers.get_all(SIGNATURE_HEADER).iter();
    let Some(signature) = signatures
        .next()
        .filter(|_| signatures.next().is_none())
        .and_then(|value| value.to_str().ok())
        .and_then(decode_hex)
    else {
        return error(StatusCode::UNAUTHORIZED, "EDGE_APPLY_SIGNATURE_INVALID");
    };
    let Some(expected) = sign(&state.key, &body) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EDGE_APPLY_SIGNATURE_UNAVAILABLE",
        );
    };
    if !memcmp::eq(&expected, &signature) {
        return error(StatusCode::UNAUTHORIZED, "EDGE_APPLY_SIGNATURE_INVALID");
    }
    let request: GatewayApplyRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "EDGE_APPLY_PAYLOAD_INVALID"),
    };
    if request.tenant_id != state.tenant_id {
        return error(StatusCode::FORBIDDEN, "EDGE_APPLY_SCOPE_DENIED");
    }
    let apply_id = request.apply_id.clone();
    let Ok(snapshot) = GatewaySnapshot::from_apply_request(request.clone()) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EDGE_APPLY_VALIDATION_FAILED",
        );
    };
    // The supervisor serializes socket/snapshot replacement, while this lock
    // also serializes the durable pending->active promotion around it. Without
    // both, concurrent requests could persist B while serving A after restart.
    let _apply_guard = state.apply_lock.lock().await;
    if let Some(path) = state.snapshot_path.as_deref() {
        let Ok(canonical_body) = serde_json::to_vec(&request) else {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE",
            );
        };
        let Some(persistence_signature) = sign(&state.key, &canonical_body) else {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE",
            );
        };
        if write_pending_snapshot(path, &request, &persistence_signature)
            .await
            .is_err()
        {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE",
            );
        }
    }
    let active_revision = match state.supervisor.apply(snapshot).await {
        Ok(revision) => revision,
        Err(ApplyError::ListenerUnavailable) => {
            if let Some(path) = state.snapshot_path.as_deref() {
                let _ = remove_pending_snapshot(path).await;
            }
            return error(StatusCode::CONFLICT, "EDGE_APPLY_LISTENER_UNAVAILABLE");
        }
        Err(ApplyError::StaleRevision) => {
            if let Some(path) = state.snapshot_path.as_deref() {
                let _ = remove_pending_snapshot(path).await;
            }
            return error(StatusCode::CONFLICT, "EDGE_APPLY_STALE_REVISION");
        }
        Err(ApplyError::RevisionConflict) => {
            if let Some(path) = state.snapshot_path.as_deref() {
                let _ = remove_pending_snapshot(path).await;
            }
            return error(StatusCode::CONFLICT, "EDGE_APPLY_IDEMPOTENCY_CONFLICT");
        }
    };
    if let Some(path) = state.snapshot_path.as_deref()
        && promote_pending_snapshot(path).await.is_err()
    {
        // A new in-memory route without a durable signed snapshot cannot
        // survive restart safely. Stop data-plane listeners until an operator
        // retries after fixing the snapshot volume.
        state.supervisor.fail_closed().await;
        let _ = remove_pending_snapshot(path).await;
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE",
        );
    }
    (
        StatusCode::OK,
        axum::Json(GatewayApplyAck {
            apply_id,
            active_revision,
            apply_state: "active".to_owned(),
            reason_code: "EDGE_APPLY_CONFIRMED".to_owned(),
        }),
    )
        .into_response()
}

async fn health_handler(State(state): State<ApplyState>, headers: HeaderMap) -> Response {
    // Health is intentionally on the same authenticated loopback channel;
    // unauthenticated liveness probes must not disclose tenant topology.
    let mut signatures = headers.get_all(SIGNATURE_HEADER).iter();
    let Some(signature) = signatures
        .next()
        .filter(|_| signatures.next().is_none())
        .and_then(|value| value.to_str().ok())
        .and_then(decode_hex)
    else {
        return error(StatusCode::UNAUTHORIZED, "EDGE_APPLY_SIGNATURE_INVALID");
    };
    let Some(expected) = sign(&state.key, b"health-v1") else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EDGE_APPLY_SIGNATURE_UNAVAILABLE",
        );
    };
    if !memcmp::eq(&expected, &signature) {
        return error(StatusCode::UNAUTHORIZED, "EDGE_APPLY_SIGNATURE_INVALID");
    }
    let snapshot = state.supervisor.current();
    let listener_count = state.supervisor.listener_count().await;
    (
        StatusCode::OK,
        axum::Json(health_body(
            snapshot.tenant_id().as_str(),
            snapshot.revision(),
            snapshot.site_count(),
            listener_count,
            state.audit.is_ready(),
        )),
    )
        .into_response()
}

/// Edge health as observed by this process. `audit_state` mirrors the durable
/// audit barrier that fails admission closed, so it is `unavailable` exactly
/// when requests are being refused for lack of durable evidence.
fn health_body(
    tenant_id: &str,
    active_revision: u64,
    site_count: usize,
    listener_count: usize,
    audit_ready: bool,
) -> serde_json::Value {
    serde_json::json!({
        "tenant_id": tenant_id,
        "active_revision": active_revision,
        "site_count": site_count,
        "listener_count": listener_count,
        "edge_state": if listener_count == 0 { "unavailable" } else { "healthy" },
        "audit_state": if audit_ready { "healthy" } else { "unavailable" }
    })
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    reason_code: &'static str,
}

fn error(status: StatusCode, reason_code: &'static str) -> Response {
    (
        status,
        axum::Json(ErrorBody {
            error: "edge_apply_failed",
            reason_code,
        }),
    )
        .into_response()
}

fn sign(key: &[u8; 32], body: &[u8]) -> Option<Vec<u8>> {
    let key = PKey::hmac(key).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    signer.update(body).ok()?;
    signer.sign_to_vec().ok()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedSnapshot {
    request: GatewayApplyRequest,
    signature: String,
}

/// Loads and verifies the last acknowledged complete snapshot before sockets
/// are opened. A malformed or unsigned file is a startup error, not a reason
/// to fall back to an older static route.
pub(crate) fn load_persisted_snapshot(
    path: &Path,
    key: &[u8; 32],
    tenant_id: &str,
) -> Result<Option<(GatewayApplyRequest, GatewaySnapshot)>, std::io::Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if bytes.len() > MAX_APPLY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot is too large",
        ));
    }
    let envelope: PersistedSnapshot = serde_json::from_slice(&bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot is invalid",
        )
    })?;
    let signature = decode_hex(&envelope.signature).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot signature is invalid",
        )
    })?;
    let body = serde_json::to_vec(&envelope.request).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot cannot be canonicalized",
        )
    })?;
    let expected = sign(key, &body).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot signature unavailable",
        )
    })?;
    if !memcmp::eq(&expected, &signature) || envelope.request.tenant_id != tenant_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot signature or scope mismatch",
        ));
    }
    let snapshot = GatewaySnapshot::from_apply_request(envelope.request.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot failed validation",
        )
    })?;
    Ok(Some((envelope.request, snapshot)))
}

async fn write_pending_snapshot(
    path: &Path,
    request: &GatewayApplyRequest,
    signature: &[u8],
) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let pending = pending_path(path);
    let temporary = temporary_path(&pending);
    let envelope = PersistedSnapshot {
        request: request.clone(),
        signature: lower_hex(signature),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted edge snapshot cannot be serialized",
        )
    })?;
    let mut file = tokio::fs::File::create(&temporary).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temporary, &pending).await
}

async fn promote_pending_snapshot(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::rename(pending_path(path), path).await
}

async fn remove_pending_snapshot(path: &Path) -> Result<(), std::io::Error> {
    match tokio::fs::remove_file(pending_path(path)).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn pending_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pending", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tmp-{}", path.display(), uuid::Uuid::now_v7()))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Parses the deployment-provided lowercase hexadecimal HMAC key.
pub fn key_from_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut key = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = pair[0] - if pair[0] <= b'9' { b'0' } else { b'a' - 10 };
        let low = pair[1] - if pair[1] <= b'9' { b'0' } else { b'a' - 10 };
        key[index] = (high << 4) | low;
    }
    Some(key)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = value.as_bytes();
    Some(
        bytes
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => 0,
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reports_audit_barrier_and_listener_state() {
        let healthy = health_body("tenant_a", 7, 2, 3, true);
        assert_eq!(healthy["edge_state"], "healthy");
        assert_eq!(healthy["audit_state"], "healthy");
        assert_eq!(healthy["active_revision"], 7);
        let failed_audit = health_body("tenant_a", 7, 2, 3, false);
        assert_eq!(failed_audit["edge_state"], "healthy");
        assert_eq!(failed_audit["audit_state"], "unavailable");
        assert_eq!(
            health_body("tenant_a", 0, 0, 0, true)["edge_state"],
            "unavailable"
        );
    }

    #[test]
    fn parses_only_fixed_lowercase_keys() {
        assert!(key_from_hex(&"00".repeat(32)).is_some());
        assert!(key_from_hex(&"AA".repeat(32)).is_none());
        assert!(key_from_hex("00").is_none());
    }
}
