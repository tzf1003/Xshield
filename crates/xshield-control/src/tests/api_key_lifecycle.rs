//! Management API-key lifecycle: every administrative outcome is audited with
//! the key id (never the secret), a rotation is all-or-nothing, an audit
//! failure never leaves a half-applied change, and `last_used_at` is kept
//! without writing on every request.
//!
//! These tests need `PostgreSQL` and are ignored without `XSHIELD_TEST_DATABASE_URL`.

use super::api_key_harness::{Harness, ISSUER_ROLES};
use super::*;
use crate::management_api_key::{ADMIN_ACCESS as KEY_ADMIN, KeyAudit, LIST_ACCESS as KEY_LIST};
use xshield_core::domain::ManagementApiKeyId;
use xshield_worker::{PublisherConfig as WorkerPublisherConfig, publish_sealed_segments};

const ADMIN: &str = "console.agent_api_key.admin";
const LIST: &str = "console.agent_api_key.list";
const KEY_ROUTE: &str = "/control/v1/agent-api-keys";

fn admin_events(events: &[Value]) -> Vec<&Value> {
    events
        .iter()
        .filter(|event| event["event_type"] == ADMIN)
        .collect()
}

async fn post_key(
    harness: &Harness,
    scopes: &Value,
    subject: Value,
    label: Value,
) -> (StatusCode, Value) {
    let mut body = Harness::key_body(scopes);
    body["subject"] = subject;
    body["display_name"] = label;
    harness
        .browser(&ISSUER_ROLES, "POST", KEY_ROUTE, Some(&body))
        .await
}

fn summary(event: &Value) -> (String, String, Option<String>) {
    (
        event["payload"]["outcome"].as_str().unwrap().to_owned(),
        event["payload"]["reason_code"].as_str().unwrap().to_owned(),
        event["payload"]["target_api_key_id"]
            .as_str()
            .map(str::to_owned),
    )
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn every_key_administration_outcome_is_audited_with_the_key_id_and_never_the_secret() {
    let harness = Harness::new().await;
    harness.create_site("site_a").await;
    let scopes = json!([harness.scope("site_a", &["site.read"])]);
    let (id, secret) = harness.issue_with_id(&scopes).await;
    let (status, listing) = harness.list_keys().await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    let (status, rotated) = harness.rotate(&id, &Harness::key_body(&scopes)).await;
    assert_eq!(status, StatusCode::CREATED, "{rotated}");
    let new_id = rotated["api_key_id"].as_str().unwrap().to_owned();
    let new_secret = rotated["api_key"].as_str().unwrap().to_owned();
    let (status, body) = harness.revoke(&new_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness.revoke(&new_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error_code"], "CONTROL_API_KEY_NOT_FOUND");

    let events = harness.events();
    let admin = admin_events(&events);
    let observed: Vec<_> = admin.iter().map(|event| summary(event)).collect();
    assert_eq!(
        observed,
        [
            ("PASS", "CONTROL_API_KEY_CREATED", Some(id.as_str())),
            ("PASS", "CONTROL_API_KEY_ROTATED_OUT", Some(id.as_str())),
            ("PASS", "CONTROL_API_KEY_ROTATED_IN", Some(new_id.as_str())),
            ("PASS", "CONTROL_API_KEY_REVOKED", Some(new_id.as_str())),
            ("DENY", "CONTROL_API_KEY_NOT_FOUND", Some(new_id.as_str())),
        ]
        .map(|(outcome, reason, target)| (
            outcome.to_owned(),
            reason.to_owned(),
            target.map(str::to_owned)
        )),
        "{admin:#?}"
    );
    for event in &admin {
        assert_eq!(event["payload"]["subject_ref"], "human-key-admin");
        assert_eq!(event["payload"]["method"], "POST");
        assert_eq!(event["payload"]["path"], KEY_ROUTE);
    }
    // Rotation is one request: both halves share its request id.
    assert_eq!(admin[1]["request_id"], admin[2]["request_id"]);
    assert_ne!(admin[0]["request_id"], admin[1]["request_id"]);

    let list: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == LIST)
        .collect();
    assert_eq!(list.len(), 1, "{list:#?}");
    assert_eq!(list[0]["payload"]["outcome"], "PASS");
    assert_eq!(list[0]["payload"]["reason_code"], "CONTROL_API_KEYS_LISTED");
    assert!(list[0]["payload"]["target_api_key_id"].is_null());

    let everything = serde_json::to_string(&events).unwrap();
    for leaked in [&secret, &new_secret] {
        assert!(
            !everything.contains(leaked.as_str()),
            "secret reached the journal"
        );
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn subject_and_label_are_validated_and_never_silently_normalized() {
    let harness = Harness::new().await;
    let scopes = json!([harness.scope("site_a", &["site.read"])]);
    let long_subject = "a".repeat(129);
    let long_label = "l".repeat(129);
    for bad_subject in [
        "",
        " lead",
        "trail ",
        "inner space",
        "line\nbreak",
        "nul\u{0}byte",
        "tab\tchar",
        "\u{430}lice",
        "emoji\u{1F600}",
        "-leading-dash",
        long_subject.as_str(),
    ] {
        let (status, body) = post_key(&harness, &scopes, json!(bad_subject), json!("label")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad_subject:?}: {body}");
        assert_eq!(body["error_code"], "CONTROL_API_KEY_SCOPE_INVALID");
    }
    for bad_label in [
        "",
        "   ",
        " lead",
        "trail ",
        "line\nbreak",
        "bell\u{7}",
        long_label.as_str(),
    ] {
        let (status, body) = post_key(&harness, &scopes, json!("agent-ok"), json!(bad_label)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad_label:?}: {body}");
        assert_eq!(body["error_code"], "CONTROL_API_KEY_SCOPE_INVALID");
    }
    assert_eq!(
        harness.key_count().await,
        0,
        "a rejected request stores nothing"
    );
    for (subject, label) in [
        ("agent-juice-shop", "Juice Shop Agent"),
        ("agent.juice_shop:v1@tenant/a", "\u{6D4B}\u{8BD5} agent"),
    ] {
        let (status, body) = post_key(&harness, &scopes, json!(subject), json!(label)).await;
        assert_eq!(status, StatusCode::CREATED, "{subject}: {body}");
    }
    // Subjects are labels, not identities: two keys may share one (overlapping
    // rotation), and the key id keeps every credential distinct.
    let (status, body) = post_key(
        &harness,
        &scopes,
        json!("agent-juice-shop"),
        json!("second"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(harness.key_count().await, 3);
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_rejected_rotation_leaves_the_old_key_working_and_no_replacement() {
    let harness = Harness::new().await;
    harness.create_site("site_a").await;
    let scopes = json!([harness.scope("site_a", &["site.read"])]);
    let (id, secret) = harness.issue_with_id(&scopes).await;
    let status_path = "/control/v1/sites/site_a/status";

    let mut bad_expiry = Harness::key_body(&scopes);
    bad_expiry["expires_at"] = json!("not-a-date");
    let mut no_scopes = Harness::key_body(&scopes);
    no_scopes["scopes"] = json!([]);
    let mut bad_subject = Harness::key_body(&scopes);
    bad_subject["subject"] = json!("bad subject");
    let mut unknown_field = Harness::key_body(&scopes);
    unknown_field["unexpected"] = json!(true);
    for (name, body, expected) in [
        ("bad expiry", bad_expiry, StatusCode::BAD_REQUEST),
        ("empty scopes", no_scopes, StatusCode::BAD_REQUEST),
        ("bad subject", bad_subject, StatusCode::BAD_REQUEST),
        ("unknown field", unknown_field, StatusCode::BAD_REQUEST),
        ("not an object", json!("rotate"), StatusCode::BAD_REQUEST),
    ] {
        let (status, response) = harness.rotate(&id, &body).await;
        assert_eq!(status, expected, "{name}: {response}");
    }
    // A scope beyond the issuer's own authority is refused as a whole.
    let escalated = json!([harness.scope("site_a", &["site.config.apply_direct"])]);
    let (status, response) = harness
        .browser(
            &["key_administrator", "system_admin"],
            "POST",
            &format!("{KEY_ROUTE}/{id}/rotate"),
            Some(&Harness::key_body(&escalated)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(response["error_code"], "CONTROL_API_KEY_SCOPE_FORBIDDEN");

    // Nothing changed: the old key is active, still authenticates, no new key exists.
    let (row_status, _) = harness.key_row(&id).await.unwrap();
    assert_eq!(row_status, "active");
    assert_eq!(harness.key_count().await, 1);
    let (status, body) = harness.with_key(&secret, "GET", status_path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A valid rotation swaps atomically: one revoked, one new active key.
    let (status, rotated) = harness.rotate(&id, &Harness::key_body(&scopes)).await;
    assert_eq!(status, StatusCode::CREATED, "{rotated}");
    let new_id = rotated["api_key_id"].as_str().unwrap();
    let new_secret = rotated["api_key"].as_str().unwrap();
    assert_eq!(harness.key_count().await, 2);
    assert_eq!(harness.key_row(&id).await.unwrap().0, "revoked");
    assert_eq!(harness.key_row(new_id).await.unwrap().0, "active");
    let (status, _) = harness.with_key(&secret, "GET", status_path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = harness.with_key(new_secret, "GET", status_path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The old key cannot be rotated again, and that creates nothing.
    let (status, response) = harness.rotate(&id, &Harness::key_body(&scopes)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{response}");
    assert_eq!(harness.key_count().await, 2);
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn concurrent_rotations_of_one_key_yield_exactly_one_replacement() {
    let harness = Harness::new().await;
    let scopes = json!([harness.scope("site_a", &["site.read"])]);
    let (id, _) = harness.issue_with_id(&scopes).await;
    let body = Harness::key_body(&scopes);
    let (a, b, c, d) = tokio::join!(
        harness.rotate(&id, &body),
        harness.rotate(&id, &body),
        harness.rotate(&id, &body),
        harness.rotate(&id, &body),
    );
    let statuses: Vec<_> = [a, b, c, d].into_iter().map(|(status, _)| status).collect();
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|status| matches!(*status, StatusCode::CREATED | StatusCode::NOT_FOUND)),
        "{statuses:?}"
    );
    assert_eq!(harness.key_count().await, 2, "one replacement, no strays");
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn audit_failure_never_leaves_a_half_applied_key_change() {
    // A journal that holds a few dozen events: enough to set up, then filled.
    let harness = Harness::with_journal_capacity(48 * 1024).await;
    harness.create_site("site_a").await;
    let scopes = json!([harness.scope("site_a", &["site.read"])]);
    let (id, secret) = harness.issue_with_id(&scopes).await;
    let mut filled = false;
    for _ in 0..400 {
        let (status, body) = harness
            .operator("GET", "/control/v1/sites/site_a/status", None)
            .await;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(body["error_code"], "AUDIT_DURABILITY_FAILED");
            filled = true;
            break;
        }
    }
    assert!(filled, "the journal must fill up");
    let before = harness.key_count().await;

    // Create: no audit record, so no key.
    let (status, body) = harness.issue_as(&ISSUER_ROLES, &scopes).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(
        body.get("api_key").is_none(),
        "no secret may be returned: {body}"
    );
    assert_eq!(harness.key_count().await, before);
    // Revoke: the key stays active.
    let (status, body) = harness.revoke(&id).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(harness.key_row(&id).await.unwrap().0, "active");
    // Rotate: old key intact, no replacement, no secret returned.
    let (status, body) = harness.rotate(&id, &Harness::key_body(&scopes)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body.get("api_key").is_none(),
        "no secret may be returned: {body}"
    );
    assert_eq!(harness.key_row(&id).await.unwrap().0, "active");
    assert_eq!(harness.key_count().await, before);
    let _ = secret;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn last_use_is_recorded_without_writing_on_every_request() {
    let harness = Harness::new().await;
    harness.create_site("site_a").await;
    let (id, secret) = harness
        .issue_with_id(&json!([harness.scope("site_a", &["site.read"])]))
        .await;
    let path = "/control/v1/sites/site_a/status";
    assert!(
        harness.key_row(&id).await.unwrap().1.is_none(),
        "unused key"
    );

    let (status, body) = harness.with_key(&secret, "GET", path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let first = harness
        .key_row(&id)
        .await
        .unwrap()
        .1
        .expect("first use is recorded");
    assert!(Utc::now() - first < chrono::Duration::seconds(30));
    // Within the minute the row is not written again.
    for _ in 0..3 {
        let (status, _) = harness.with_key(&secret, "GET", path, None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(harness.key_row(&id).await.unwrap().1, Some(first));
    // After the minute has passed the next use updates it.
    harness.age_last_use(&id, 2).await;
    let aged = harness.key_row(&id).await.unwrap().1.unwrap();
    let (status, _) = harness.with_key(&secret, "GET", path, None).await;
    assert_eq!(status, StatusCode::OK);
    let refreshed = harness.key_row(&id).await.unwrap().1.unwrap();
    assert!(
        refreshed - aged > chrono::Duration::seconds(90),
        "{aged} -> {refreshed}"
    );
    // The listing exposes it.
    let (status, listing) = harness.list_keys().await;
    assert_eq!(status, StatusCode::OK);
    let row = listing["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["api_key_id"] == id)
        .unwrap();
    assert!(row["last_used_at"].is_string(), "{row}");
    // A failed authentication never touches a key.
    let (id_two, _) = harness
        .issue_with_id(&json!([harness.scope("site_a", &["site.read"])]))
        .await;
    let (status, _) = harness
        .with_key("xsk_not_a_real_key_at_all", "GET", path, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(harness.key_row(&id_two).await.unwrap().1.is_none());
}

/// The worker's publisher rejects an event it cannot parse and then stops
/// publishing the whole segment. Emit every shape the key endpoints and the
/// key authenticator can produce and publish them through the real publisher.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn key_administration_and_use_events_as_emitted_are_accepted_by_the_publisher() {
    let mock = test::Mock::new();
    let fixture = Fixture::with_index(
        10,
        ManagementRole::SystemAdmin,
        Client::default().with_mock(&mock),
    );
    let key = |n: u8| {
        ManagementApiKeyId::parse(format!("key_018f2a3b-4c5d-7000-8000-0000000000{n:02x}")).unwrap()
    };
    let admin = |outcome, reason, target| KeyAudit {
        subject: "human-key-admin".to_owned(),
        action: KEY_ADMIN,
        target,
        outcome,
        reason,
    };
    let single_events = [
        admin("PASS", "CONTROL_API_KEY_CREATED", Some(key(1))),
        admin("PASS", "CONTROL_API_KEY_REVOKED", Some(key(1))),
        admin("DENY", "CONTROL_API_KEY_NOT_FOUND", Some(key(4))),
        admin("DENY", "CONTROL_API_KEY_SCOPE_FORBIDDEN", None),
        admin("DENY", "CONTROL_API_KEY_SCOPE_INVALID", Some(key(5))),
        admin("ERROR", "CONTROL_API_KEY_UNAVAILABLE", Some(key(6))),
        KeyAudit {
            subject: "human-key-admin".to_owned(),
            action: KEY_LIST,
            target: None,
            outcome: "PASS",
            reason: "CONTROL_API_KEYS_LISTED",
        },
    ];
    for entry in &single_events {
        fixture
            .control
            .append_api_key_events(
                &format!("req_{}", Uuid::now_v7()),
                std::slice::from_ref(entry),
            )
            .unwrap();
    }
    // A rotation records both halves in one batch (one sealed segment).
    fixture
        .control
        .append_api_key_events(
            &format!("req_{}", Uuid::now_v7()),
            &[
                admin("PASS", "CONTROL_API_KEY_ROTATED_OUT", Some(key(2))),
                admin("PASS", "CONTROL_API_KEY_ROTATED_IN", Some(key(3))),
            ],
        )
        .unwrap();
    // Key use as written by the authenticator: success names the composite
    // principal, a refusal names nobody.
    fixture
        .control
        .append_access_event(
            &format!("req_{}", Uuid::now_v7()),
            Some("apikey:key_018f2a3b-4c5d-7000-8000-000000000001:agent-under-test"),
            crate::identity::API_KEY_ACCESS,
            None,
            "PASS",
            "CONTROL_API_KEY_AUTHENTICATED",
        )
        .unwrap();
    for (outcome, reason) in [
        ("DENY", "CONTROL_API_KEY_INVALID"),
        ("DENY", "CONTROL_AUTH_REQUIRED"),
        ("ERROR", "CONTROL_API_KEY_UNAVAILABLE"),
    ] {
        fixture
            .control
            .append_access_event(
                &format!("req_{}", Uuid::now_v7()),
                None,
                crate::identity::API_KEY_ACCESS,
                None,
                outcome,
                reason,
            )
            .unwrap();
    }
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), single_events.len() + 2 + 4);
    // Segments: one per single append, one for the rotation batch, one per use event.
    let segments = single_events.len() + 1 + 4;
    let root = fixture.access_directory.parent().unwrap().to_owned();
    let config = WorkerPublisherConfig::new(
        &fixture.access_directory,
        root.join("access-manifests"),
        root.join("access-checkpoints"),
        "control-index",
        "audit_events",
        30,
        1024 * 1024,
    )
    .unwrap();
    for _ in 0..(segments * 3) {
        mock.add(test::handlers::provide(Vec::<AuditEventSummary>::new()));
    }
    let published = publish_sealed_segments(
        &config,
        &Client::default().with_mock(&mock),
        "control-key-r1",
        &JournalKey::from_hex(JOURNAL_KEY).unwrap(),
        &test_seal_key(),
    )
    .await
    .expect("every emitted key event must be publishable");
    assert_eq!(published.published_segments, segments);
    assert_eq!(
        published.published_events,
        u64::try_from(events.len()).unwrap()
    );
    fs::remove_dir_all(&root).unwrap();
}
