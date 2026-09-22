//! HTTP boundary regressions for restricted calibration-report investigation.

use super::*;
use crate::calibration_report_inspection::PATH;

const REPORT: &str = "calr_018f2a3b-4c5d-7000-8000-000000000001";

fn request(suffix: &str) -> Request<Body> {
    Request::get(format!("/control/v1/calibration-reports/{suffix}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

fn audit(event: &Value, outcome: &str, reason: &str, target: Option<&str>) {
    assert_eq!(event["event_type"], "console.calibration.report.read");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], PATH);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], reason);
    assert_eq!(event["evidence_refs"], json!([]));
    match target {
        Some(target) => assert_eq!(
            event["payload"].get("target_calibration_report_id"),
            Some(&json!(target))
        ),
        None => assert!(
            event["payload"]
                .get("target_calibration_report_id")
                .is_none()
        ),
    }
    for (key, value) in event["payload"].as_object().unwrap() {
        if key.starts_with("target_") && key != "target_calibration_report_id" {
            assert!(value.is_null(), "{key}");
        }
    }
    for excluded in ["metric", "sample", "label", "probability", "read_url"] {
        assert!(!event.to_string().contains(excluded), "{excluded}");
    }
}

#[tokio::test]
async fn calibration_report_inspection_enforces_scope_shape_capacity_and_store_contracts() {
    for scenario in ["auth", "role", "id", "query", "body", "busy", "store"] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let mut fixture = Fixture::with_catalog(
            20,
            ManagementRole::AuditAdministrator,
            PostgresIdentityStore::from_pool(pool),
            1,
        );
        let mut input = request(REPORT);
        let mut permit = None;
        let (status, code, target) = match scenario {
            "auth" => {
                input.headers_mut().remove(AUTHORIZATION);
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED", None)
            }
            "role" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [ManagementRole::Observer],
                    [(
                        TenantId::parse("tenant_a").unwrap(),
                        SiteId::parse("site_a").unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED", None)
            }
            "id" => {
                input = request("calr_bad");
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CALIBRATION_REPORT_ID_INVALID",
                    None,
                )
            }
            "query" => {
                input = request(&format!("{REPORT}?cursor=opaque"));
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID",
                    Some(REPORT),
                )
            }
            "body" => {
                *input.body_mut() = Body::from("unexpected body");
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID",
                    Some(REPORT),
                )
            }
            "busy" => {
                permit = Some(
                    fixture
                        .control
                        .search_capacity
                        .clone()
                        .acquire_owned()
                        .await
                        .unwrap(),
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_CALIBRATION_REPORT_BUSY",
                    Some(REPORT),
                )
            }
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE",
                Some(REPORT),
            ),
        };
        let directory = fixture.access_directory.clone();
        let body = response_json(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(body["error_code"], code, "{scenario}");
        assert!(body.get("report").is_none());
        let events = read_access_events(&directory);
        assert_eq!(events.len(), 1);
        audit(
            &events[0],
            if status.is_server_error() {
                "ERROR"
            } else {
                "DENY"
            },
            code,
            target,
        );
        drop(permit);
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }
}

fn poison_audit(control: &ControlPlane) {
    std::thread::scope(|scope| {
        let journal = &control.access_journal;
        assert!(
            scope
                .spawn(move || {
                    let _guard = journal.lock().unwrap();
                    panic!("simulate calibration report audit failure");
                })
                .join()
                .is_err()
        );
    });
}

#[tokio::test]
async fn calibration_report_inspection_withholds_store_result_when_audit_fails() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
        .unwrap();
    pool.close().await;
    let fixture = Fixture::with_catalog(
        1,
        ManagementRole::AuditAdministrator,
        PostgresIdentityStore::from_pool(pool),
        1,
    );
    poison_audit(&fixture.control);
    let directory = fixture.access_directory.clone();
    let response = response_json(
        router(fixture.control)
            .oneshot(request(REPORT))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(response["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(response.get("report").is_none());
    assert!(read_access_events(&directory).is_empty());
    fs::remove_dir_all(directory.parent().unwrap()).unwrap();
}
