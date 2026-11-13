//! Contract tests (docs/07-console-architecture.md section 7.10.8). The fixtures in
//! `web/console/tests/fixtures` are the files the console's end-to-end tests serve.
//! Each one must read as the Rust type the control plane serializes, and write back
//! to the same JSON.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use xshield_core::context::{DecisionRecord, JevRecord, trace::Trace};

use crate::auth::SessionStateBody;
use crate::insights::{EvidenceBody, InsightsBody};
use crate::jev::{JevStatsBody, JevStatusBody, PromptBody};
use crate::object_functions::FunctionsBody;
use crate::preview::PreviewBody;
use crate::requests::{CountsBody, LookupBody, RequestDetailBody, RequestRow, RequestsPageBody};
use crate::sessions::{SessionDetailBody, SessionsBody};
use crate::sites::{SiteDetailBody, SitesBody, VersionsBody};
use crate::stats::{SummaryBody, TimeseriesBody};
use crate::status::StatusBody;
use crate::system::SystemBody;

const REQUESTS: &str = include_str!("../../../web/console/tests/fixtures/requests.json");
const LOOKUP: &str = include_str!("../../../web/console/tests/fixtures/lookup.json");
const COUNTS: &str = include_str!("../../../web/console/tests/fixtures/counts.json");
const SUMMARY: &str = include_str!("../../../web/console/tests/fixtures/summary.json");
const TIMESERIES: &str = include_str!("../../../web/console/tests/fixtures/timeseries.json");
const JEV_STATUS: &str = include_str!("../../../web/console/tests/fixtures/jev-status.json");
const JEV_STATS: &str = include_str!("../../../web/console/tests/fixtures/jev-stats.json");
const PROMPT: &str = include_str!("../../../web/console/tests/fixtures/prompt.json");
const STATUS: &str = include_str!("../../../web/console/tests/fixtures/status.json");
const STATUS_DOWN: &str = include_str!("../../../web/console/tests/fixtures/status-down.json");
const SYSTEM: &str = include_str!("../../../web/console/tests/fixtures/system.json");
const SESSION: &str = include_str!("../../../web/console/tests/fixtures/session.json");
const SESSIONS: &str = include_str!("../../../web/console/tests/fixtures/sessions.json");
const SITES: &str = include_str!("../../../web/console/tests/fixtures/sites.json");
const SITE_JUICE: &str = include_str!("../../../web/console/tests/fixtures/site-juice.json");
const SITE_EMR: &str = include_str!("../../../web/console/tests/fixtures/site-emr.json");
const VERSIONS_EMR: &str = include_str!("../../../web/console/tests/fixtures/versions-emr.json");
const INSIGHTS: &str = include_str!("../../../web/console/tests/fixtures/insights.json");
const EVIDENCE: &str = include_str!("../../../web/console/tests/fixtures/evidence.json");
const FUNCTIONS: &str = include_str!("../../../web/console/tests/fixtures/functions.json");
const PREVIEW: &str = include_str!("../../../web/console/tests/fixtures/preview.json");
const SESSION_TIMELINE: &str =
    include_str!("../../../web/console/tests/fixtures/session-timeline.json");
const DETAILS: [&str; 5] = [
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1971a07e079639a823d4257b43172.json"
    ),
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1973940107ebea1af2c54ce635f38.json"
    ),
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1973ed5c0732b8f29804d7fc746d3.json"
    ),
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1973f5b2c3d4e6f708192a3b4c5d6.json"
    ),
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_c0ffee00c0ffee00c0ffee00c0ffee00.json"
    ),
];

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("a fixture is JSON")
}

/// Reads `original` as `T`, writes it back through `normalize`, and asserts the JSON
/// is the same once both sides are normalized the same way.
fn assert_round_trips<T>(original: &Value, normalize: fn(&Value) -> Value)
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let typed: T = serde_json::from_value(original.clone()).expect("the fixture reads as the type");
    let written = serde_json::to_value(&typed).expect("the type writes JSON");
    assert_eq!(normalize(&written), normalize(original));
}

fn exactly(value: &Value) -> Value {
    value.clone()
}

/// The stored form of a trace. The gateway leaves out the keys that are null, the
/// `values` list when it is empty, and `values_truncated` when it is false. The
/// documented shape (docs/07 section 7.4.3) lists them, and the console reads an
/// absent key as null, so the comparison drops them from both sides.
fn as_stored(trace: &Value) -> Value {
    let mut stored = without_nulls(trace);
    if let Value::Object(map) = &mut stored {
        if map.get("values_truncated") == Some(&Value::Bool(false)) {
            map.remove("values_truncated");
        }
        if map
            .get("values")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            map.remove("values");
        }
    }
    stored
}

fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, member)| !member.is_null())
                .map(|(key, member)| (key.clone(), without_nulls(member)))
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

#[test]
fn list_rows_round_trip_through_the_row_type() {
    let page = fixture(REQUESTS);
    let rows = page["rows"].as_array().expect("the page has rows");
    assert!(!rows.is_empty());
    for row in rows {
        assert_round_trips::<RequestRow>(row, exactly);
    }
}

#[test]
fn request_page_round_trips_through_the_page_type() {
    assert_round_trips::<RequestsPageBody>(&fixture(REQUESTS), exactly);

    // A full page carries the cursor of the next one. The console treats it as opaque.
    let mut full = fixture(REQUESTS);
    full["next_cursor"] = json!("opaque-cursor");
    assert_round_trips::<RequestsPageBody>(&full, exactly);
}

#[test]
fn lookup_round_trips_through_the_lookup_type() {
    assert_round_trips::<LookupBody>(&fixture(LOOKUP), exactly);
}

#[test]
fn request_details_round_trip_through_the_detail_type() {
    for text in DETAILS {
        assert_round_trips::<RequestDetailBody>(&fixture(text), exactly);
    }
}

#[test]
fn found_lookup_summaries_round_trip_through_the_row_type() {
    let lookup = fixture(LOOKUP);
    let found: Vec<&Value> = lookup["rows"]
        .as_array()
        .expect("the lookup has rows")
        .iter()
        .filter(|row| row["found"] == true)
        .collect();
    assert!(!found.is_empty());
    for row in found {
        assert_round_trips::<RequestRow>(&row["summary"], exactly);
    }
}

#[test]
fn detail_summaries_round_trip_through_the_row_type() {
    for text in DETAILS {
        assert_round_trips::<RequestRow>(&fixture(text)["summary"], exactly);
    }
}

#[test]
fn detail_traces_round_trip_in_their_stored_form() {
    for text in DETAILS {
        assert_round_trips::<Trace>(&fixture(text)["trace"], as_stored);
    }
}

#[test]
fn detail_jev_documents_round_trip() {
    for text in DETAILS {
        let jev = &fixture(text)["jev"];
        if !jev.is_null() {
            assert_round_trips::<JevRecord>(jev, exactly);
        }
    }
}

#[test]
fn each_detail_rebuilds_as_a_decision_record() {
    for text in DETAILS {
        let detail = fixture(text);
        let summary = &detail["summary"];
        let record = json!({
            "at_millis": summary["at_millis"],
            "request_id": summary["request_id"],
            "site": summary["site"],
            "site_version": summary["site_version"],
            "edge": detail["edge"],
            "host": summary["host"],
            "client": summary["client"],
            "session": summary["session"],
            "context": summary["context"],
            "method": summary["method"],
            "path": summary["path"],
            "logical_path": summary["logical_path"],
            "api": summary["api"],
            "request_headers": detail["request_headers"],
            "query": summary["query"],
            "status": summary["status"],
            "decision_path": summary["decision_path"],
            "outcome": summary["outcome"],
            "trace": detail["trace"],
            "jev": detail["jev"],
        });
        assert_round_trips::<DecisionRecord>(&record, |value| {
            let mut normalized = value.clone();
            normalized["trace"] = as_stored(&value["trace"]);
            normalized
        });
    }
}

#[test]
fn counts_round_trip_through_the_counts_type() {
    let counts = fixture(COUNTS);
    assert_round_trips::<CountsBody>(&counts, exactly);

    // `scanned` is written only when the count is incomplete (docs/07 section 7.9.1).
    let mut partial = counts.clone();
    partial["complete"] = json!(false);
    partial["scanned"] = json!(57);
    assert_round_trips::<CountsBody>(&partial, exactly);
}

#[test]
fn timeseries_round_trips_through_the_timeseries_type() {
    assert_round_trips::<TimeseriesBody>(&fixture(TIMESERIES), exactly);
}

#[test]
fn summary_round_trips_through_the_summary_type() {
    let summary = fixture(SUMMARY);
    assert_round_trips::<SummaryBody>(&summary, exactly);

    // `scanned` is written only when the window was not read in full (docs/07 section 7.9.1).
    let mut partial = summary.clone();
    partial["complete"] = json!(false);
    partial["scanned"] = json!(18204);
    assert_round_trips::<SummaryBody>(&partial, exactly);
}

#[test]
fn jev_status_round_trips_through_the_status_type() {
    assert_round_trips::<JevStatusBody>(&fixture(JEV_STATUS), exactly);
}

#[test]
fn jev_stats_round_trips_through_the_stats_type() {
    assert_round_trips::<JevStatsBody>(&fixture(JEV_STATS), exactly);
}

#[test]
fn prompt_round_trips_through_the_prompt_type() {
    assert_round_trips::<PromptBody>(&fixture(PROMPT), exactly);
}

#[test]
fn status_fixtures_round_trip_through_the_status_type() {
    assert_round_trips::<StatusBody>(&fixture(STATUS), exactly);
    assert_round_trips::<StatusBody>(&fixture(STATUS_DOWN), exactly);
}

#[test]
fn system_round_trips_through_the_system_type() {
    assert_round_trips::<SystemBody>(&fixture(SYSTEM), exactly);
}

#[test]
fn session_round_trips_through_the_session_state_type() {
    assert_round_trips::<SessionStateBody>(&fixture(SESSION), exactly);

    // The sign-in check answers `false` with a 401 when no session is valid.
    let mut signed_out = fixture(SESSION);
    signed_out["authenticated"] = json!(false);
    assert_round_trips::<SessionStateBody>(&signed_out, exactly);
}

#[test]
fn sites_round_trip_through_the_sites_type() {
    assert_round_trips::<SitesBody>(&fixture(SITES), exactly);
}

#[test]
fn site_details_round_trip_through_the_detail_type() {
    assert_round_trips::<SiteDetailBody>(&fixture(SITE_JUICE), exactly);
    assert_round_trips::<SiteDetailBody>(&fixture(SITE_EMR), exactly);
}

#[test]
fn versions_round_trip_through_the_versions_type() {
    assert_round_trips::<VersionsBody>(&fixture(VERSIONS_EMR), exactly);
}

#[test]
fn insights_round_trip_through_the_insights_type() {
    assert_round_trips::<InsightsBody>(&fixture(INSIGHTS), exactly);

    // An enforce-mode site has no readiness check, so the field is null, not absent.
    let mut enforce = fixture(INSIGHTS);
    enforce["readiness"] = Value::Null;
    assert_round_trips::<InsightsBody>(&enforce, exactly);

    // Each kind of action a suggestion carries, and a suggestion about a setting
    // rather than about requests, which has no method or path.
    let mut every_kind = fixture(INSIGHTS);
    every_kind["suggestions"] = json!([
        {
            "id": "7f3a9c1e5b2d4a60",
            "kind": "raise_jev_timeout",
            "method": null,
            "path": null,
            "count": 3,
            "sample": null,
            "actions": [{ "set_advanced": { "jev_timeout_ms": 3000 } }],
            "reason": "timeouts",
        },
        {
            "id": "0c4e8b2a9f1d7360",
            "kind": "secret_field_candidate",
            "method": null,
            "path": null,
            "count": 2,
            "sample": "req_01a1973940107ebea1af2c54ce635f38",
            "actions": [{ "add_secret_field": "ssn" }],
            "reason": "unredacted",
        },
        {
            "id": "b1d5f0e8c3a72946",
            "kind": "hot_would_block",
            "method": "GET",
            "path": "/rest/products",
            "count": 5,
            "sample": "req_01a1973ed5c0732b8f29804d7fc746d3",
            "actions": [],
            "reason": "most refused",
        },
    ]);
    assert_round_trips::<InsightsBody>(&every_kind, exactly);
}

#[test]
fn evidence_round_trips_through_the_evidence_type() {
    assert_round_trips::<EvidenceBody>(&fixture(EVIDENCE), exactly);

    // A window with no Jev call has no latency percentiles.
    let mut quiet = fixture(EVIDENCE);
    quiet["jev"]["calls"] = json!(0);
    quiet["jev"]["p50_ms"] = Value::Null;
    quiet["jev"]["p95_ms"] = Value::Null;
    quiet["jev"]["p99_ms"] = Value::Null;
    assert_round_trips::<EvidenceBody>(&quiet, exactly);
}

#[test]
fn functions_round_trip_through_the_functions_type() {
    assert_round_trips::<FunctionsBody>(&fixture(FUNCTIONS), exactly);

    // The other two statuses: a window over the key limit has no candidates and reads the
    // table's evidence as none, and a site with learning off shows what the store holds.
    let mut over_limit = fixture(FUNCTIONS);
    over_limit["status"] = json!("over_limit");
    over_limit["candidates"] = json!([]);
    over_limit["functions"][1]["ordinary_units"] = json!(0);
    over_limit["functions"][1]["admin_units"] = json!(0);
    over_limit["functions"][1]["refused_units"] = json!(0);
    over_limit["functions"][1]["last_seen"] = Value::Null;
    assert_round_trips::<FunctionsBody>(&over_limit, exactly);

    let mut learning_off = fixture(FUNCTIONS);
    learning_off["status"] = json!("learning_off");
    assert_round_trips::<FunctionsBody>(&learning_off, exactly);
}

#[test]
fn preview_round_trips_through_the_preview_type() {
    assert_round_trips::<PreviewBody>(&fixture(PREVIEW), exactly);

    // Each kind of change the preview reports: a call limit that tightens, one that
    // loosens, the cache, a secret field, and an estimate, which carries its approximate
    // mark. A window not read in full says so, and a route that names requests warns.
    let mut every_kind = fixture(PREVIEW);
    every_kind["complete"] = json!(false);
    every_kind["warnings"] = json!(["SESSION_CHANGED", "INTERFACE_UNVERIFIED"]);
    every_kind["changes"] = json!([
        {
            "kind": "call_limit",
            "count": 4,
            "detail": { "scope": "session", "old": 60, "new": 30, "keys": 2 },
        },
        {
            "kind": "call_limit",
            "count": 9,
            "detail": { "scope": "address", "old": 30, "new": 60, "upper_bound": true },
        },
        {
            "kind": "cache",
            "count": 86,
            "top": [["GET", "/assets/app.js", 86]],
            "sample": "req_01a1973940107ebea1af2c54ce635f38",
        },
        {
            "kind": "secret_fields",
            "count": 5,
            "detail": { "values": 7, "fields": [["ssn", 7]] },
        },
        {
            "kind": "api_split",
            "count": 4,
            "top": [["POST", "/api/rpc", 4]],
            "sample": "req_01a19728dcc071aab225b9e0f5d7b63f",
            "detail": { "approximate": true },
        },
    ]);
    assert_round_trips::<PreviewBody>(&every_kind, exactly);
}

#[test]
fn sessions_round_trip_through_the_sessions_type() {
    assert_round_trips::<SessionsBody>(&fixture(SESSIONS), exactly);
}

#[test]
fn session_timeline_round_trips_through_the_detail_type() {
    assert_round_trips::<SessionDetailBody>(&fixture(SESSION_TIMELINE), exactly);
}
