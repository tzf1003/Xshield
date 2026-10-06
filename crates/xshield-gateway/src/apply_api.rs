//! Authenticated loopback control channel for atomic edge snapshot loading.
//!
//! An apply is all-or-nothing for the whole tenant snapshot. Under one lock,
//! in this order: the snapshot compiles (no side effects), it must be allowed
//! to replace the serving one, every site that declares page issuance has its
//! edge-managed action descriptors supplied to `PostgreSQL`, the signed pending
//! file is written, sockets are bound and the pointer is swapped, and the
//! pending file is promoted. A refusal at any step before the swap leaves the
//! serving snapshot and the persisted files as they were. Only the success
//! acknowledgement is signed; refusals carry a stable reason code and, for a
//! descriptor refusal, the site that caused it.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use xshield_core::constant_time;
use xshield_core::{
    GatewayApplyAck, GatewayApplyRequest,
    domain::SiteId,
    edge_channel::{APPLY_ACK_SIGNATURE_HEADER, APPLY_SIGNATURE_HEADER, apply_ack_message},
};

use crate::descriptor_supply::{
    APPLY_SUPPLY_DEADLINE, DescriptorStore, SupplyRefusal, supply_descriptors,
};
use crate::durable_audit::AuditReadiness;
use crate::edge_health::HealthGate;
use crate::listener_supervisor::{ApplyError, ListenerSupervisor};
use xshield_gateway::{
    MAX_CONFIG_BYTES,
    edge_transport::TransportStatus,
    multi_site::{GatewaySnapshot, SnapshotRefusal},
};

const SIGNATURE_HEADER: &str = APPLY_SIGNATURE_HEADER;
// Built at compile time: `from_static` rejects an invalid name there, so no
// request can ever reach a panic on it.
const ACK_SIGNATURE_HEADER: HeaderName = HeaderName::from_static(APPLY_ACK_SIGNATURE_HEADER);
const MAX_APPLY_BYTES: usize = MAX_CONFIG_BYTES * 8;
/// A site's edge-managed descriptors conflict with the rows its policy
/// revision already binds (another digest, a revision that is not `active`,
/// or a descriptor that means something else). A changed descriptor set
/// needs a new policy revision label; retrying the same snapshot cannot help.
const DESCRIPTOR_CONFLICT: &str = "EDGE_APPLY_DESCRIPTOR_CONFLICT";
/// A site's edge-managed descriptors could not be supplied: the edge has no
/// identity store, or `PostgreSQL` was unreachable or too slow. Retryable.
const DESCRIPTOR_UNAVAILABLE: &str = "EDGE_APPLY_DESCRIPTOR_UNAVAILABLE";

/// Authenticated state shared by the loopback apply handler.
#[derive(Clone)]
pub struct ApplyState {
    supervisor: Arc<ListenerSupervisor>,
    tenant_id: String,
    key: [u8; 32],
    health: Arc<HealthGate>,
    snapshot_path: Option<Arc<PathBuf>>,
    apply_lock: Arc<Mutex<()>>,
    audit: AuditReadiness,
    descriptors: Option<Arc<dyn DescriptorStore>>,
}

impl ApplyState {
    /// Creates an apply endpoint bound to one deployment tenant.
    ///
    /// `descriptors` is the identity store the edge was started with, or
    /// `None` when it has none; a snapshot with a page-issuing site is then
    /// refused instead of being served without its descriptors.
    #[must_use]
    pub fn new(
        supervisor: Arc<ListenerSupervisor>,
        tenant_id: String,
        key: [u8; 32],
        snapshot_path: Option<PathBuf>,
        audit: AuditReadiness,
        descriptors: Option<Arc<dyn DescriptorStore>>,
    ) -> Self {
        Self {
            supervisor,
            tenant_id,
            key,
            health: Arc::new(HealthGate::new(key)),
            snapshot_path: snapshot_path.map(Arc::new),
            apply_lock: Arc::new(Mutex::new(())),
            audit,
            descriptors,
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
    if !constant_time::eq(&expected, &signature) {
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
    // The descriptor supply runs under it too, so the snapshot it checked is
    // still the serving one when the supply decides anything.
    let _apply_guard = state.apply_lock.lock().await;
    let serving = state.supervisor.current();
    if let Err(refusal) = prepare_switch(
        &serving,
        &snapshot,
        &request,
        state.descriptors.as_deref(),
        state
            .snapshot_path
            .as_deref()
            .map(|path| (path.as_path(), &state.key)),
        APPLY_SUPPLY_DEADLINE,
    )
    .await
    {
        return refusal.response();
    }
    drop(serving);
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
    signed_ack_response(
        &state.key,
        &expected,
        &GatewayApplyAck {
            apply_id,
            active_revision,
            apply_state: "active".to_owned(),
            reason_code: "EDGE_APPLY_CONFIRMED".to_owned(),
        },
    )
}

/// Why an apply was refused before the in-memory swap.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplyRefusal {
    status: StatusCode,
    reason_code: &'static str,
    /// The site a descriptor refusal is about. It lets a control plane hold
    /// that one site back; it is not signed, so it can only ever explain a
    /// refusal, never confirm anything.
    site_id: Option<SiteId>,
}

impl ApplyRefusal {
    const fn new(status: StatusCode, reason_code: &'static str) -> Self {
        Self {
            status,
            reason_code,
            site_id: None,
        }
    }

    fn descriptors(refusal: SupplyRefusal) -> Self {
        let (status, reason_code, site_id) = match refusal {
            SupplyRefusal::Conflict { site_id, .. } => {
                (StatusCode::CONFLICT, DESCRIPTOR_CONFLICT, site_id)
            }
            SupplyRefusal::Unavailable { site_id } => (
                StatusCode::SERVICE_UNAVAILABLE,
                DESCRIPTOR_UNAVAILABLE,
                site_id,
            ),
        };
        Self {
            status,
            reason_code,
            site_id: Some(site_id),
        }
    }

    fn response(&self) -> Response {
        error_with_site(
            self.status,
            self.reason_code,
            self.site_id.as_ref().map(SiteId::as_str),
        )
    }
}

/// Everything that must hold before sockets are bound and the pointer is
/// swapped, in order; the first refusal stops the apply, so nothing after it
/// has happened:
/// 1. `incoming` may replace `serving` (the same verdict the supervisor
///    reaches again under its own lock). Asked first so a stale or
///    conflicting snapshot never touches `PostgreSQL`.
/// 2. Every site that declares page issuance has its descriptors supplied,
///    unless `incoming` is the exact payload already serving (an idempotent
///    retry), whose descriptors were supplied before it ever served.
/// 3. With persistence configured, the signed pending file is written.
///
/// The caller holds the apply lock, so `serving` cannot change underneath.
async fn prepare_switch(
    serving: &GatewaySnapshot,
    incoming: &GatewaySnapshot,
    request: &GatewayApplyRequest,
    descriptors: Option<&dyn DescriptorStore>,
    persistence: Option<(&Path, &[u8; 32])>,
    supply_deadline: std::time::Duration,
) -> Result<(), ApplyRefusal> {
    match serving.check_replacement(incoming) {
        Ok(()) => {}
        Err(SnapshotRefusal::Stale) => {
            return Err(ApplyRefusal::new(
                StatusCode::CONFLICT,
                "EDGE_APPLY_STALE_REVISION",
            ));
        }
        Err(SnapshotRefusal::Conflict) => {
            return Err(ApplyRefusal::new(
                StatusCode::CONFLICT,
                "EDGE_APPLY_IDEMPOTENCY_CONFLICT",
            ));
        }
    }
    let already_serving =
        serving.payload_digest().is_some() && serving.payload_digest() == incoming.payload_digest();
    if !already_serving {
        supply_descriptors(descriptors, incoming.sites(), supply_deadline)
            .await
            .map_err(ApplyRefusal::descriptors)?;
    }
    if let Some((path, key)) = persistence {
        let persistence_unavailable =
            |status| ApplyRefusal::new(status, "EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE");
        let canonical_body = serde_json::to_vec(request)
            .map_err(|_| persistence_unavailable(StatusCode::INTERNAL_SERVER_ERROR))?;
        let signature = sign(key, &canonical_body)
            .ok_or_else(|| persistence_unavailable(StatusCode::INTERNAL_SERVER_ERROR))?;
        write_pending_snapshot(path, request, &signature)
            .await
            .map_err(|_| persistence_unavailable(StatusCode::SERVICE_UNAVAILABLE))?;
    }
    Ok(())
}

/// The acknowledgement, signed with the shared key over a message that
/// includes the signature of the request it answers. The control plane can
/// then tell the edge's answer from anything else able to reach its socket,
/// and cannot be handed the acknowledgement of a different apply.
fn signed_ack_response(
    key: &[u8; 32],
    request_signature: &[u8],
    ack: &GatewayApplyAck,
) -> Response {
    let Ok(body) = serde_json::to_vec(ack) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EDGE_APPLY_SIGNATURE_UNAVAILABLE",
        );
    };
    let message = apply_ack_message(&lower_hex(request_signature), &body);
    let Some(signature) = sign(key, &message) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EDGE_APPLY_SIGNATURE_UNAVAILABLE",
        );
    };
    let Ok(signature) = HeaderValue::from_str(&lower_hex(&signature)) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "EDGE_APPLY_SIGNATURE_UNAVAILABLE",
        );
    };
    let mut response = (
        StatusCode::OK,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        body,
    )
        .into_response();
    response
        .headers_mut()
        .insert(ACK_SIGNATURE_HEADER, signature);
    response
}

async fn health_handler(State(state): State<ApplyState>, headers: HeaderMap) -> Response {
    // Health is intentionally on the same authenticated loopback channel;
    // unauthenticated liveness probes must not disclose tenant topology.
    if let Err(refusal) = state.health.check(&headers, unix_now(), Instant::now()) {
        return refusal.response();
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
            state.supervisor.transport_status(),
        )),
    )
        .into_response()
}

/// Seconds since the epoch. An unreadable clock reads as 0, which is outside
/// every request's window, so a broken clock refuses health requests instead
/// of accepting stale ones.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Edge health as observed by this process. `audit_state` mirrors the durable
/// audit barrier that fails admission closed, so it is `unavailable` exactly
/// when requests are being refused for lack of durable evidence.
///
/// The transport fields report configuration (`tls_enabled`,
/// `proxy_protocol_enabled`) and process-lifetime counts of connections that
/// never reached admission: TLS handshakes that failed or timed out, trusted
/// balancer connections refused for their PROXY header, and connections shed
/// because every setup slot was busy. Such connections have no request, so
/// these counters, not audit events, are their record; they reset on restart.
fn health_body(
    tenant_id: &str,
    active_revision: u64,
    site_count: usize,
    listener_count: usize,
    audit_ready: bool,
    transport: TransportStatus,
) -> serde_json::Value {
    serde_json::json!({
        "tenant_id": tenant_id,
        "active_revision": active_revision,
        "site_count": site_count,
        "listener_count": listener_count,
        "edge_state": if listener_count == 0 { "unavailable" } else { "healthy" },
        "audit_state": if audit_ready { "healthy" } else { "unavailable" },
        "tls_enabled": transport.tls_enabled,
        "tls_handshake_failures": transport.tls_handshake_failures,
        "proxy_protocol_enabled": transport.proxy_protocol_enabled,
        "proxy_header_rejections": transport.proxy_header_rejections,
        "connection_setup_shed": transport.setup_shed
    })
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'static str,
    reason_code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    site_id: Option<&'a str>,
}

pub(crate) fn error(status: StatusCode, reason_code: &'static str) -> Response {
    error_with_site(status, reason_code, None)
}

/// A refusal body; `site_id` is present only when one site caused it.
fn error_with_site(
    status: StatusCode,
    reason_code: &'static str,
    site_id: Option<&str>,
) -> Response {
    (
        status,
        axum::Json(ErrorBody {
            error: "edge_apply_failed",
            reason_code,
            site_id,
        }),
    )
        .into_response()
}

pub(crate) fn sign(key: &[u8; 32], body: &[u8]) -> Option<Vec<u8>> {
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
    if !constant_time::eq(&expected, &signature) || envelope.request.tenant_id != tenant_id {
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
    restrict_to_owner(path);
    Ok(Some((envelope.request, snapshot)))
}

async fn write_pending_snapshot(
    path: &Path,
    request: &GatewayApplyRequest,
    signature: &[u8],
) -> Result<(), std::io::Error> {
    let parent = parent_directory(path);
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
    // The snapshot is the complete tenant routing and policy set, so it is
    // created readable by the edge user only. The mode is set at creation
    // (a later chmod would leave a window in which another local user could
    // open the file) and `create_new` refuses to follow a pre-planted name.
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temporary, &pending).await?;
    // A rename is durable only once the directory entry is: without this a
    // power loss after the 200 could resurrect the previous snapshot.
    sync_directory(parent).await
}

async fn promote_pending_snapshot(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::rename(pending_path(path), path).await?;
    sync_directory(parent_directory(path)).await
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Flushes a directory so a rename inside it survives a crash. A failure is
/// reported, not ignored: the caller then refuses or fails closed instead of
/// acknowledging a snapshot that a restart could lose.
async fn sync_directory(directory: &Path) -> Result<(), std::io::Error> {
    tokio::fs::File::open(directory).await?.sync_all().await
}

/// Tightens a snapshot written before files were created with mode 0600, so a
/// deployment is not left exposed until its next apply rewrites the file.
/// Failing to chmod (for example a read-only volume) must not stop the edge
/// from serving the snapshot it was configured with, so it is only reported.
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    // Any group or other permission bit means someone else can read the file.
    if metadata.permissions().mode() & 0o077 != 0
        && let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    {
        eprintln!("xshield edge could not restrict the snapshot file mode: {error}");
    }
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
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = pair[0] - if pair[0] <= b'9' { b'0' } else { b'a' - 10 };
        let low = pair[1] - if pair[1] <= b'9' { b'0' } else { b'a' - 10 };
        key[index] = (high << 4) | low;
    }
    Some(key)
}

pub(crate) fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = value.as_bytes();
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
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
    use crate::descriptor_supply::fake::{FakeStore, Mode, page_site};
    use xshield_gateway::GatewayConfig;

    const PLAINTEXT: TransportStatus = TransportStatus {
        tls_enabled: false,
        tls_handshake_failures: 0,
        proxy_protocol_enabled: false,
        proxy_header_rejections: 0,
        setup_shed: 0,
    };

    #[test]
    fn health_reports_audit_barrier_and_listener_state() {
        let healthy = health_body("tenant_a", 7, 2, 3, true, PLAINTEXT);
        assert_eq!(healthy["edge_state"], "healthy");
        assert_eq!(healthy["audit_state"], "healthy");
        assert_eq!(healthy["active_revision"], 7);
        let failed_audit = health_body("tenant_a", 7, 2, 3, false, PLAINTEXT);
        assert_eq!(failed_audit["edge_state"], "healthy");
        assert_eq!(failed_audit["audit_state"], "unavailable");
        assert_eq!(
            health_body("tenant_a", 0, 0, 0, true, PLAINTEXT)["edge_state"],
            "unavailable"
        );
    }

    // Connections that fail before admission have no request and no audit
    // event; the health body is where an operator sees them.
    #[test]
    fn health_reports_transport_configuration_and_setup_failures() {
        let body = health_body(
            "tenant_a",
            7,
            2,
            3,
            true,
            TransportStatus {
                tls_enabled: true,
                tls_handshake_failures: 4,
                proxy_protocol_enabled: true,
                proxy_header_rejections: 2,
                setup_shed: 1,
            },
        );
        assert_eq!(body["tls_enabled"], true);
        assert_eq!(body["tls_handshake_failures"], 4);
        assert_eq!(body["proxy_protocol_enabled"], true);
        assert_eq!(body["proxy_header_rejections"], 2);
        assert_eq!(body["connection_setup_shed"], 1);
        // A handshake failure is not an edge outage.
        assert_eq!(body["edge_state"], "healthy");
        let plaintext = health_body("tenant_a", 7, 2, 3, true, PLAINTEXT);
        assert_eq!(plaintext["tls_enabled"], false);
        assert_eq!(plaintext["tls_handshake_failures"], 0);
    }

    fn empty_request(revision: u64) -> GatewayApplyRequest {
        GatewayApplyRequest {
            protocol_version: 1,
            tenant_id: "tenant_a".to_owned(),
            apply_id: "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01".to_owned(),
            snapshot_revision: revision,
            sites: Vec::new(),
        }
    }

    fn scratch_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("xshield-apply-{name}-{}", uuid::Uuid::now_v7()))
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn leftovers(directory: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    // Reviewer finding: the pending and active snapshot files were created
    // with `File::create`, i.e. 0666 minus the process umask (0644 under the
    // usual 022), so any local user could read the complete tenant routing
    // and policy snapshot the control plane had pushed.
    #[tokio::test]
    async fn persisted_snapshots_are_private_to_the_edge_user() {
        let directory = scratch_directory("private");
        let path = directory.join("edge").join("snapshot.json");
        write_pending_snapshot(&path, &empty_request(1), b"signature")
            .await
            .unwrap();
        assert_eq!(mode_of(&pending_path(&path)), 0o600);
        promote_pending_snapshot(&path).await.unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(
            leftovers(&directory.join("edge")),
            ["snapshot.json"],
            "no pending or temporary file may outlive a promotion"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    // A restart must not leave an old deployment exposed until its next apply:
    // a file written by an edge from before the fix is tightened when loaded.
    #[test]
    fn a_snapshot_written_by_an_older_edge_is_made_private_when_it_is_loaded() {
        use std::os::unix::fs::PermissionsExt;
        let directory = scratch_directory("legacy");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("snapshot.json");
        let key = [7_u8; 32];
        let request = empty_request(1);
        let signature = sign(&key, &serde_json::to_vec(&request).unwrap()).unwrap();
        let envelope = PersistedSnapshot {
            request,
            signature: lower_hex(&signature),
        };
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load_persisted_snapshot(&path, &key, "tenant_a").unwrap();
        assert_eq!(loaded.unwrap().1.revision(), 1);
        assert_eq!(mode_of(&path), 0o600);
        std::fs::remove_dir_all(directory).unwrap();
    }

    // That the kernel really flushes the directory entry cannot be observed
    // from a unit test; what can be pinned is that a failure to do so is an
    // error the apply handler turns into a refusal, never a silent success.
    #[tokio::test]
    async fn a_directory_that_cannot_be_synced_is_an_error_not_a_success() {
        let directory = scratch_directory("sync");
        std::fs::create_dir_all(&directory).unwrap();
        sync_directory(&directory).await.unwrap();
        assert!(sync_directory(&directory.join("missing")).await.is_err());
        let path = directory.join("snapshot.json");
        // Nothing to promote: the rename fails before any sync is attempted.
        assert!(promote_pending_snapshot(&path).await.is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_second_apply_replaces_the_pending_file_without_leaving_temporaries() {
        let directory = scratch_directory("rewrite");
        let path = directory.join("snapshot.json");
        for revision in [1, 2] {
            write_pending_snapshot(&path, &empty_request(revision), b"signature")
                .await
                .unwrap();
            promote_pending_snapshot(&path).await.unwrap();
        }
        assert_eq!(leftovers(&directory), ["snapshot.json"]);
        assert_eq!(mode_of(&path), 0o600);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn pinned_ack() -> GatewayApplyAck {
        GatewayApplyAck {
            apply_id: "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01".to_owned(),
            active_revision: 7,
            apply_state: "active".to_owned(),
            reason_code: "EDGE_APPLY_CONFIRMED".to_owned(),
        }
    }

    // Reviewer finding: the answer to an apply was plain JSON, so anything able
    // to answer on the edge's port could confirm a snapshot the edge never
    // applied. The expected values were computed independently with Python's
    // `hmac`; the control plane's tests pin the same literals from its side.
    #[tokio::test]
    async fn the_apply_acknowledgement_is_signed_over_the_request_it_answers() {
        let key = key_from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .unwrap();
        let response = signed_ack_response(&key, &[0xab_u8; 32], &pinned_ack());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(
            response
                .headers()
                .get_all(&ACK_SIGNATURE_HEADER)
                .iter()
                .count(),
            1
        );
        let signature = response.headers()[&ACK_SIGNATURE_HEADER]
            .to_str()
            .unwrap()
            .to_owned();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            br#"{"apply_id":"apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01","active_revision":7,"apply_state":"active","reason_code":"EDGE_APPLY_CONFIRMED"}"#
        );
        assert_eq!(
            signature,
            "0611268a882723b00c849321661f8020d1c627074fd8031173a5420415e2e5f3"
        );
        // Another request, another key: another tag.
        let other_request = signed_ack_response(&key, &[0xcd_u8; 32], &pinned_ack());
        assert_ne!(
            other_request.headers()[&ACK_SIGNATURE_HEADER],
            signature.as_str()
        );
        let other_key = signed_ack_response(&[1_u8; 32], &[0xab_u8; 32], &pinned_ack());
        assert_ne!(
            other_key.headers()[&ACK_SIGNATURE_HEADER],
            signature.as_str()
        );
    }

    #[test]
    fn parses_only_fixed_lowercase_keys() {
        assert!(key_from_hex(&"00".repeat(32)).is_some());
        assert!(key_from_hex(&"AA".repeat(32)).is_none());
        assert!(key_from_hex("00").is_none());
    }

    // ---- Descriptor supply before the swap -------------------------------

    const KEY: [u8; 32] = [7_u8; 32];

    /// A complete snapshot of page-issuing sites `(site, port, list path)`.
    fn page_request(revision: u64, sites: &[(&str, u16, &str)]) -> GatewayApplyRequest {
        GatewayApplyRequest {
            protocol_version: 1,
            tenant_id: "tenant_supply".to_owned(),
            apply_id: "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01".to_owned(),
            snapshot_revision: revision,
            sites: sites
                .iter()
                .map(|(site, port, list_path)| xshield_core::GatewayApplySite {
                    site_id: (*site).to_owned(),
                    listen_port: *port,
                    public_origin: format!("https://{}.example", site.replace('_', "-")),
                    gateway_config: page_site(site, *port, list_path),
                    revision,
                })
                .collect(),
        }
    }

    /// The bootstrap-only snapshot an edge starts with.
    fn placeholder() -> GatewaySnapshot {
        GatewaySnapshot::compile_for_tenant(
            1,
            xshield_core::domain::TenantId::parse("tenant_supply").unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    fn compiled(request: &GatewayApplyRequest) -> GatewaySnapshot {
        GatewaySnapshot::from_apply_request(request.clone()).unwrap()
    }

    async fn prepare(
        serving: &GatewaySnapshot,
        request: &GatewayApplyRequest,
        store: Option<&dyn DescriptorStore>,
        path: &Path,
    ) -> Result<(), ApplyRefusal> {
        prepare_switch(
            serving,
            &compiled(request),
            request,
            store,
            Some((path, &KEY)),
            APPLY_SUPPLY_DEADLINE,
        )
        .await
    }

    fn digest_of(request: &GatewayApplyRequest, site: &str) -> String {
        compiled(request)
            .sites()
            .find(|config| config.site_id().as_str() == site)
            .and_then(GatewayConfig::edge_descriptors)
            .unwrap()
            .content_digest_hex()
    }

    fn refused(status: StatusCode, reason_code: &'static str, site: &str) -> ApplyRefusal {
        ApplyRefusal {
            status,
            reason_code,
            site_id: Some(SiteId::parse(site).unwrap()),
        }
    }

    /// Nothing was persisted: no pending, active or temporary file.
    fn nothing_persisted(directory: &Path) {
        assert!(
            !directory.exists() || leftovers(directory).is_empty(),
            "{:?}",
            leftovers(directory)
        );
    }

    #[tokio::test]
    async fn a_page_issuing_site_is_supplied_before_its_pending_snapshot_is_written() {
        let directory = scratch_directory("supply-created");
        let path = directory.join("snapshot.json");
        let store = FakeStore::new(Mode::Up);
        let request = page_request(1, &[("site_a", 6100, "/orders")]);
        prepare(&placeholder(), &request, Some(&store), &path)
            .await
            .unwrap();
        // The rows exist, bound to this configuration's own digest, before
        // the pending file that a restart could serve from exists.
        assert_eq!(
            store.revision("tenant_supply", "site_a", "policy-r1"),
            Some(("active", digest_of(&request, "site_a")))
        );
        assert_eq!(leftovers(&directory), ["snapshot.json.pending"]);
        // A snapshot with page-issuing sites is a valid restart source now.
        promote_pending_snapshot(&path).await.unwrap();
        let (restored, snapshot) = load_persisted_snapshot(&path, &KEY, "tenant_supply")
            .unwrap()
            .unwrap();
        assert_eq!(restored.snapshot_revision, 1);
        assert!(
            snapshot
                .sites()
                .all(|config| config.edge_descriptors().is_some())
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_revision_that_is_already_supplied_is_accepted_as_existing() {
        let directory = scratch_directory("supply-existing");
        let path = directory.join("snapshot.json");
        let store = FakeStore::new(Mode::Up);
        let first = page_request(1, &[("site_a", 6100, "/orders")]);
        prepare(&placeholder(), &first, Some(&store), &path)
            .await
            .unwrap();
        promote_pending_snapshot(&path).await.unwrap();
        // The next snapshot keeps the site's configuration (another site may
        // have changed): the same digest under the same revision is fine.
        let second = page_request(2, &[("site_a", 6100, "/orders")]);
        prepare(&compiled(&first), &second, Some(&store), &path)
            .await
            .unwrap();
        assert_eq!(store.calls().len(), 2);
        assert_eq!(store.calls()[0], store.calls()[1]);
        assert_eq!(
            leftovers(&directory),
            ["snapshot.json", "snapshot.json.pending"]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    // One conflicting site refuses the whole tenant snapshot, because an
    // apply is atomic; the refusal names that site so a control plane could
    // hold just it back.
    #[tokio::test]
    async fn a_digest_conflict_refuses_the_whole_snapshot_and_names_the_site() {
        let directory = scratch_directory("supply-conflict");
        let path = directory.join("snapshot.json");
        let store = FakeStore::new(Mode::Up);
        store.seed(
            "tenant_supply",
            "site_b",
            "policy-r1",
            "active",
            &"e".repeat(64),
        );
        let request = page_request(
            1,
            &[("site_a", 6100, "/orders"), ("site_b", 6101, "/orders")],
        );
        assert_eq!(
            prepare(&placeholder(), &request, Some(&store), &path).await,
            Err(refused(
                StatusCode::CONFLICT,
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                "site_b"
            ))
        );
        nothing_persisted(&directory);
        // Nothing was overwritten. The site checked before the conflict keeps
        // its own idempotent binding; the next attempt reads it as existing.
        assert_eq!(
            store.revision("tenant_supply", "site_b", "policy-r1"),
            Some(("active", "e".repeat(64)))
        );
        assert!(
            store
                .revision("tenant_supply", "site_a", "policy-r1")
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_policy_revision_that_is_not_active_refuses_the_apply() {
        let directory = scratch_directory("supply-retired");
        let path = directory.join("snapshot.json");
        let request = page_request(1, &[("site_a", 6100, "/orders")]);
        let store = FakeStore::new(Mode::Up);
        store.seed(
            "tenant_supply",
            "site_a",
            "policy-r1",
            "retired",
            &digest_of(&request, "site_a"),
        );
        assert_eq!(
            prepare(&placeholder(), &request, Some(&store), &path).await,
            Err(refused(
                StatusCode::CONFLICT,
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                "site_a"
            ))
        );
        nothing_persisted(&directory);
    }

    #[tokio::test]
    async fn a_stored_descriptor_with_another_meaning_refuses_the_apply() {
        let directory = scratch_directory("supply-drift");
        let path = directory.join("snapshot.json");
        let store = FakeStore::new(Mode::Up);
        store.drift_descriptor("tenant_supply", "site_a", "policy-r1");
        let request = page_request(1, &[("site_a", 6100, "/orders")]);
        assert_eq!(
            prepare(&placeholder(), &request, Some(&store), &path).await,
            Err(refused(
                StatusCode::CONFLICT,
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                "site_a"
            ))
        );
        nothing_persisted(&directory);
    }

    #[tokio::test]
    async fn an_unreachable_or_hung_database_refuses_and_writes_no_pending_file() {
        let directory = scratch_directory("supply-down");
        let path = directory.join("snapshot.json");
        let request = page_request(1, &[("site_a", 6100, "/orders")]);
        let unavailable = refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "EDGE_APPLY_DESCRIPTOR_UNAVAILABLE",
            "site_a",
        );
        let down = FakeStore::new(Mode::Down);
        assert_eq!(
            prepare(&placeholder(), &request, Some(&down), &path).await,
            Err(unavailable.clone())
        );
        nothing_persisted(&directory);
        let hung = FakeStore::new(Mode::Hung);
        assert_eq!(
            prepare_switch(
                &placeholder(),
                &compiled(&request),
                &request,
                Some(&hung),
                Some((&path, &KEY)),
                std::time::Duration::from_millis(50),
            )
            .await,
            Err(unavailable)
        );
        nothing_persisted(&directory);
    }

    // The edge's identity store comes from its bootstrap configuration. An
    // edge started without one cannot make the descriptors exist, so it must
    // refuse a page-issuing site rather than serve it without them; sites
    // without page issuance do not need a database at all.
    #[tokio::test]
    async fn an_edge_without_an_identity_store_refuses_only_page_issuing_sites() {
        let directory = scratch_directory("supply-no-store");
        let path = directory.join("snapshot.json");
        let request = page_request(1, &[("site_a", 6100, "/orders")]);
        assert_eq!(
            prepare(&placeholder(), &request, None, &path).await,
            Err(refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "EDGE_APPLY_DESCRIPTOR_UNAVAILABLE",
                "site_a"
            ))
        );
        nothing_persisted(&directory);
        let mut plain = page_request(1, &[("site_a", 6100, "/orders")]);
        let config = &mut plain.sites[0].gateway_config;
        config["operations"] = serde_json::json!([
            {"operation_id": "entry", "method": "GET", "path": "/", "admission": "PUBLIC"}
        ]);
        config.as_object_mut().unwrap().remove("sensor");
        prepare(&placeholder(), &plain, None, &path).await.unwrap();
        assert_eq!(leftovers(&directory), ["snapshot.json.pending"]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn stale_and_conflicting_snapshots_never_reach_the_database() {
        let directory = scratch_directory("supply-stale");
        let path = directory.join("snapshot.json");
        let store = FakeStore::new(Mode::Up);
        let serving = compiled(&page_request(3, &[("site_a", 6100, "/orders")]));
        assert_eq!(
            prepare(
                &serving,
                &page_request(2, &[("site_a", 6100, "/orders")]),
                Some(&store),
                &path
            )
            .await,
            Err(ApplyRefusal::new(
                StatusCode::CONFLICT,
                "EDGE_APPLY_STALE_REVISION"
            ))
        );
        assert_eq!(
            prepare(
                &serving,
                &page_request(3, &[("site_a", 6100, "/orders-v2")]),
                Some(&store),
                &path
            )
            .await,
            Err(ApplyRefusal::new(
                StatusCode::CONFLICT,
                "EDGE_APPLY_IDEMPOTENCY_CONFLICT"
            ))
        );
        assert_eq!(store.calls(), [] as [std::string::String; 0]);
        nothing_persisted(&directory);
    }

    // A retry of the exact payload already serving was supplied before it
    // ever served; asking the database again would only turn a database
    // outage into a failed no-op.
    #[tokio::test]
    async fn an_identical_retry_of_the_serving_snapshot_needs_no_database() {
        let directory = scratch_directory("supply-retry");
        let path = directory.join("snapshot.json");
        let request = page_request(2, &[("site_a", 6100, "/orders")]);
        let down = FakeStore::new(Mode::Down);
        prepare(&compiled(&request), &request, Some(&down), &path)
            .await
            .unwrap();
        assert_eq!(down.calls(), [] as [std::string::String; 0]);
        assert_eq!(leftovers(&directory), ["snapshot.json.pending"]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    // The wire format of every existing refusal is unchanged; only a
    // descriptor refusal names a site.
    #[tokio::test]
    async fn only_descriptor_refusals_name_a_site() {
        let body = |response: Response| async move {
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
        };
        let conflict = ApplyRefusal::descriptors(SupplyRefusal::Conflict {
            site_id: SiteId::parse("site_b").unwrap(),
            policy_revision: xshield_core::domain::PolicyRevision::parse("policy-r1").unwrap(),
        })
        .response();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(
            &body(conflict).await[..],
            br#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_DESCRIPTOR_CONFLICT","site_id":"site_b"}"#
        );
        let unavailable = ApplyRefusal::descriptors(SupplyRefusal::Unavailable {
            site_id: SiteId::parse("site_a").unwrap(),
        })
        .response();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            &body(unavailable).await[..],
            br#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_DESCRIPTOR_UNAVAILABLE","site_id":"site_a"}"#
        );
        assert_eq!(
            &body(error(StatusCode::CONFLICT, "EDGE_APPLY_STALE_REVISION")).await[..],
            br#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_STALE_REVISION"}"#
        );
    }

    // ---- The same paths against a real PostgreSQL -------------------------
    //
    // Run by scripts/test_postgres.sh against a throwaway database with every
    // migration applied. Each run uses its own tenant, so a database can be
    // reused without cleaning it.

    fn database_url() -> String {
        std::env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required")
    }

    /// The test database's URL with a database name that does not exist.
    fn missing_database_url() -> String {
        let url = database_url();
        match url.split_once('?') {
            Some((base, query)) => format!("{base}_missing?{query}"),
            None => format!("{url}_missing"),
        }
    }

    fn runtime(url: String) -> crate::PostgresRuntime {
        crate::PostgresRuntime::new(
            zeroize::Zeroizing::new(url),
            2,
            std::time::Duration::from_secs(3),
        )
    }

    fn fresh_tenant() -> String {
        format!("tenant_supply_{}", uuid::Uuid::now_v7().simple())
    }

    /// `page_request` for one tenant of its own.
    fn tenant_request(
        tenant: &str,
        revision: u64,
        sites: &[(&str, u16, &str)],
    ) -> GatewayApplyRequest {
        let mut request = page_request(revision, sites);
        request.tenant_id = tenant.to_owned();
        for site in &mut request.sites {
            site.gateway_config["tenant_id"] = serde_json::Value::from(tenant);
        }
        request
    }

    fn tenant_placeholder(tenant: &str) -> GatewaySnapshot {
        GatewaySnapshot::compile_for_tenant(
            1,
            xshield_core::domain::TenantId::parse(tenant).unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    /// `(status, content_digest, artifact_ref)` of one stored revision.
    async fn stored_revision(
        pool: &sqlx::PgPool,
        tenant: &str,
        site: &str,
    ) -> Option<(String, String, String)> {
        sqlx::query_as(
            "SELECT status, content_digest, artifact_ref FROM xshield.policy_revisions
             WHERE tenant_id = $1 AND site_id = $2 AND revision = 'policy-r1'",
        )
        .bind(tenant)
        .bind(site)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    /// `action_id@route_template` of every stored descriptor of one site.
    async fn stored_routes(pool: &sqlx::PgPool, tenant: &str, site: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT action_id || '@' || route_template FROM xshield.action_descriptors
             WHERE tenant_id = $1 AND site_id = $2 ORDER BY action_id",
        )
        .bind(tenant)
        .bind(site)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn descriptor_supply_postgres_backs_apply_and_restart() {
        let pool = sqlx::PgPool::connect(&database_url()).await.unwrap();
        let store = runtime(database_url());
        let tenant = fresh_tenant();
        let directory = scratch_directory("supply-postgres");
        let path = directory.join("snapshot.json");
        let sites = [("site_a", 6100, "/orders"), ("site_b", 6101, "/orders")];

        // Apply: both sites are created before the pending file exists.
        let first = tenant_request(&tenant, 1, &sites);
        prepare_switch(
            &tenant_placeholder(&tenant),
            &compiled(&first),
            &first,
            Some(&store),
            Some((&path, &KEY)),
            APPLY_SUPPLY_DEADLINE,
        )
        .await
        .unwrap();
        for (site, _, _) in sites {
            let digest = digest_of(&first, site);
            assert_eq!(
                stored_revision(&pool, &tenant, site).await,
                Some((
                    "active".to_owned(),
                    digest.clone(),
                    format!("edge.descriptors.sha256.{digest}")
                ))
            );
            assert_eq!(
                stored_routes(&pool, &tenant, site).await,
                ["app.orders.list@/orders"]
            );
        }
        assert_eq!(leftovers(&directory), ["snapshot.json.pending"]);
        promote_pending_snapshot(&path).await.unwrap();

        // Restart: the persisted snapshot is supplied again, idempotently.
        let (_, restored) = load_persisted_snapshot(&path, &KEY, &tenant)
            .unwrap()
            .unwrap();
        let supplied = crate::descriptor_supply::supply_before_serving(
            Some(&store),
            restored.sites(),
            crate::descriptor_supply::StartupSource::PersistedSnapshot,
        )
        .await
        .unwrap();
        assert_eq!(supplied.len(), 2);
        assert!(
            supplied
                .iter()
                .all(|site| site.outcome == xshield_postgres::EdgeDescriptorSyncOutcome::Existing)
        );

        // A newer snapshot that moves site_b's page action under the same
        // policy revision is refused as a whole and leaves every row and the
        // active file as they were.
        let serving = compiled(&first);
        let drift = tenant_request(
            &tenant,
            2,
            &[("site_a", 6100, "/orders"), ("site_b", 6101, "/orders-v2")],
        );
        assert_eq!(
            prepare_switch(
                &serving,
                &compiled(&drift),
                &drift,
                Some(&store),
                Some((&path, &KEY)),
                APPLY_SUPPLY_DEADLINE,
            )
            .await,
            Err(refused(
                StatusCode::CONFLICT,
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                "site_b"
            ))
        );
        assert_eq!(leftovers(&directory), ["snapshot.json"]);
        assert_eq!(
            stored_routes(&pool, &tenant, "site_b").await,
            ["app.orders.list@/orders"]
        );

        // A revision retired by an operator is never reactivated by an edge,
        // neither by an apply nor by a restart.
        sqlx::query(
            "UPDATE xshield.policy_revisions SET status = 'retired'
             WHERE tenant_id = $1 AND site_id = 'site_a'",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
        let retry = tenant_request(&tenant, 3, &sites);
        assert_eq!(
            prepare_switch(
                &serving,
                &compiled(&retry),
                &retry,
                Some(&store),
                Some((&path, &KEY)),
                APPLY_SUPPLY_DEADLINE,
            )
            .await,
            Err(refused(
                StatusCode::CONFLICT,
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                "site_a"
            ))
        );
        assert_eq!(
            crate::descriptor_supply::supply_before_serving(
                Some(&store),
                restored.sites(),
                crate::descriptor_supply::StartupSource::PersistedSnapshot,
            )
            .await
            .unwrap_err()
            .to_string(),
            "UI_DESCRIPTOR_CONFLICT: persisted snapshot site site_a policy revision policy-r1 \
             already binds other action descriptors"
        );
        assert_eq!(
            stored_revision(&pool, &tenant, "site_a")
                .await
                .map(|row| row.0),
            Some("retired".to_owned())
        );

        // No database: the apply is refused before anything is persisted and
        // a restart refuses to serve the snapshot.
        let down = runtime(missing_database_url());
        let other = fresh_tenant();
        let unreachable = tenant_request(&other, 1, &sites);
        let elsewhere = directory.join("unreachable");
        assert_eq!(
            prepare_switch(
                &tenant_placeholder(&other),
                &compiled(&unreachable),
                &unreachable,
                Some(&down),
                Some((&elsewhere.join("snapshot.json"), &KEY)),
                APPLY_SUPPLY_DEADLINE,
            )
            .await,
            Err(refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "EDGE_APPLY_DESCRIPTOR_UNAVAILABLE",
                "site_a"
            ))
        );
        nothing_persisted(&elsewhere);
        assert!(stored_revision(&pool, &other, "site_a").await.is_none());
        assert_eq!(
            crate::descriptor_supply::supply_before_serving(
                Some(&down),
                restored.sites(),
                crate::descriptor_supply::StartupSource::PersistedSnapshot,
            )
            .await
            .unwrap_err()
            .to_string(),
            "IDENTITY_STORE_UNAVAILABLE: persisted snapshot site site_a cannot supply its action \
             descriptors"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    // Two edges applying the same snapshot to one database converge: each
    // revision is created once and found by the other, and both succeed.
    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
    async fn descriptor_supply_postgres_concurrent_edges_converge() {
        let first_edge = runtime(database_url());
        let second_edge = runtime(database_url());
        let tenant = fresh_tenant();
        let request = tenant_request(
            &tenant,
            1,
            &[("site_a", 6100, "/orders"), ("site_b", 6101, "/orders")],
        );
        let snapshot = compiled(&request);
        let (left, right) = tokio::join!(
            supply_descriptors(Some(&first_edge), snapshot.sites(), APPLY_SUPPLY_DEADLINE),
            supply_descriptors(Some(&second_edge), snapshot.sites(), APPLY_SUPPLY_DEADLINE),
        );
        let outcomes = left
            .unwrap()
            .into_iter()
            .chain(right.unwrap())
            .map(|site| (site.site_id.as_str().to_owned(), site.outcome))
            .collect::<Vec<_>>();
        for site in ["site_a", "site_b"] {
            let mut created = outcomes
                .iter()
                .filter(|(id, _)| id == site)
                .map(|(_, outcome)| {
                    *outcome == xshield_postgres::EdgeDescriptorSyncOutcome::Created
                })
                .collect::<Vec<_>>();
            created.sort_unstable();
            assert_eq!(created, [false, true], "{site}: one creation, one reuse");
        }
    }
}
