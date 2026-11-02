//! Contract tests (docs/07-console-architecture.md section 7.10.8). The fixtures in
//! `web/console/tests/fixtures` are the files the console's end-to-end tests serve.
//! Each one must read as the Rust type the control plane serializes, and write back
//! to the same JSON.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use xshield_core::context::{DecisionRecord, JevRecord, trace::Trace};

use crate::jev::{JevStatsBody, JevStatusBody, PromptBody};
use crate::requests::{CountsBody, RequestRow};
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
const DETAILS: [&str; 3] = [
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1971a07e079639a823d4257b43172.json"
    ),
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1973940107ebea1af2c54ce635f38.json"
    ),
    include_str!(
        "../../../web/console/tests/fixtures/request-detail-req_01a1973ed5c0732b8f29804d7fc746d3.json"
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
