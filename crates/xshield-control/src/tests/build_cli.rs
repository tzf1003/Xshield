//! `xshield-build` against the real control router over HTTP: an Agent API
//! Key with read and write stages a new page build beside the served one,
//! re-runs stage nothing, retiring promotes the next build, and nothing the
//! tool does approves or applies the revision.

use super::api_key_harness::Harness;
use super::*;
use crate::build_cli::run;

const PAGE: &str = "<!doctype html><html><head><title>r2</title></head><body></body></html>";

fn browser_loop(site: &str) -> Value {
    let mut config: Value = serde_json::from_str(include_str!(
        "../../../../tests/site-config/browser-loop.json"
    ))
    .unwrap();
    config["site_id"] = json!(site);
    config["upstream_address"] = json!("8.8.8.8:9000");
    config["public_origin"] = json!(format!("https://{}.example.test", site.replace('_', "-")));
    config
}

fn builds(config: &Value) -> Vec<String> {
    let route = config["config"]["policy"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["operation_id"] == "app.page")
        .unwrap();
    let sensor = &route["sensor_html"];
    std::iter::once(sensor["adapter_revision"].as_str().unwrap().to_owned())
        .chain(
            sensor["additional_adapters"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|adapter| adapter["adapter_revision"].as_str().unwrap().to_owned()),
        )
        .collect()
}

fn args(control: &str, page: &std::path::Path, extra: &[&str]) -> Vec<String> {
    [
        "register",
        "--control",
        control,
        "--site",
        "site_a",
        "--operation",
        "app.page",
        "--revision",
        "app-r2",
        "--page",
        page.to_str().unwrap(),
    ]
    .iter()
    .chain(extra)
    .map(|value| (*value).to_owned())
    .collect()
}

#[tokio::test]
async fn the_fingerprint_needs_no_control_plane() {
    let directory = std::env::temp_dir().join(format!("xshield-build-{}", Uuid::now_v7()));
    fs::create_dir_all(&directory).unwrap();
    let page = directory.join("index.html");
    fs::write(&page, PAGE).unwrap();
    let outcome = run(
        &["fingerprint".to_owned(), page.to_str().unwrap().to_owned()],
        None,
    )
    .await;
    assert_eq!(outcome.code, 0, "{outcome:?}");
    let report: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(report["injection_offset"], 44);
    assert_eq!(report["bytes"], PAGE.len());
    fs::write(&page, "<html><HEAD></HEAD></html>").unwrap();
    let outcome = run(
        &["fingerprint".to_owned(), page.to_str().unwrap().to_owned()],
        None,
    )
    .await;
    assert_eq!(outcome.code, 1);
    assert!(outcome.stderr.contains("</head>"), "{outcome:?}");
    let outcome = run(&args("http://example.test", &page, &[]), Some("k".into())).await;
    assert_eq!(outcome.code, 1, "plain http to a remote host: {outcome:?}");
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_release_stages_its_build_for_independent_approval() {
    let harness = Harness::new().await;
    let (status, body) = harness
        .operator(
            "PUT",
            "/control/v1/sites/site_a/config",
            Some(&browser_loop("site_a")),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
    let writer = harness
        .issue(&json!([
            harness.scope("site_a", &["site.read", "site.config.write"])
        ]))
        .await;
    let reader = harness
        .issue(&json!([harness.scope("site_a", &["site.read"])]))
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(axum::serve(listener, harness.app.clone()).into_future());
    let directory = std::env::temp_dir().join(format!("xshield-build-{}", Uuid::now_v7()));
    fs::create_dir_all(&directory).unwrap();
    let page = directory.join("index.html");
    fs::write(&page, PAGE).unwrap();

    let outcome = run(&args(&control, &page, &["--dry-run"]), Some(writer.clone())).await;
    assert_eq!(outcome.code, 0, "{outcome:?}");
    assert!(outcome.stdout.contains("\"dry_run\""), "{outcome:?}");

    // Read alone is not enough to stage.
    let outcome = run(&args(&control, &page, &[]), Some(reader)).await;
    assert_eq!(outcome.code, 2, "{outcome:?}");
    assert!(
        outcome.stderr.contains("CONTROL_SCOPE_DENIED"),
        "{outcome:?}"
    );

    let outcome = run(&args(&control, &page, &[]), Some(writer.clone())).await;
    assert_eq!(outcome.code, 0, "{outcome:?}");
    let report: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(report["state"], "staged");
    assert_eq!(report["requires_approval"], true, "{report}");
    let staged = report["desired_revision"].as_u64().unwrap();
    assert_ne!(report["active_revision"], json!(staged), "{report}");
    let (_, stored) = harness
        .operator("GET", "/control/v1/sites/site_a/config", None)
        .await;
    assert_eq!(builds(&stored), ["app-r1", "app-r2"]);

    // The same release again stages nothing.
    let outcome = run(&args(&control, &page, &[]), Some(writer.clone())).await;
    assert_eq!(outcome.code, 0, "{outcome:?}");
    assert!(outcome.stdout.contains("\"unchanged\""), "{outcome:?}");

    // After the release the old build is retired; the new one becomes primary.
    let outcome = run(
        &args(&control, &page, &["--retire", "app-r1"]),
        Some(writer.clone()),
    )
    .await;
    assert_eq!(outcome.code, 0, "{outcome:?}");
    let (_, stored) = harness
        .operator("GET", "/control/v1/sites/site_a/config", None)
        .await;
    assert_eq!(builds(&stored), ["app-r2"]);
    let (_, status) = harness
        .operator("GET", "/control/v1/sites/site_a/status", None)
        .await;
    assert_eq!(status["requires_approval"], true, "{status}");

    let events = harness.events();
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "console.site.config.write"
                && event["payload"]["outcome"] == "PASS"),
        "the save is audited under the key"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "console.site.config.approve"
                || event["event_type"] == "console.site.config.apply"),
        "the tool never approves or applies"
    );
    server.abort();
    fs::remove_dir_all(directory).unwrap();
}
