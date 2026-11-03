//! The v4 samples under `examples/` must load through the code that reads them:
//! `SiteSpec` for the site configuration and `DecisionRecord` for the decision
//! log. `scripts/validate_library.py` checks the same files against `schemas/`;
//! this test is the authority on what the gateway accepts.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;
use xshield_core::context::{DecisionRecord, SiteSpec};

fn example(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn dev_sites_file_loads_every_site() {
    let sites: Vec<Value> = serde_json::from_str(&example("sites-dev.json")).unwrap();
    assert!(!sites.is_empty());
    let mut names = HashSet::new();
    for site in &sites {
        let parsed = SiteSpec::from_value(site).unwrap_or_else(|error| panic!("{site}: {error}"));
        assert!(
            names.insert(parsed.name().to_owned()),
            "duplicate site name"
        );
    }
}

#[test]
fn decision_log_rows_load() {
    let text = example("decision-log.jsonl");
    let mut rows = 0;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let record: DecisionRecord =
            serde_json::from_str(line).unwrap_or_else(|error| panic!("{line}: {error}"));
        assert!(record.request_id.starts_with("req_"));
        if let Some(state) = record.jev.as_ref().and_then(|jev| jev.state.as_ref()) {
            let state: Value = serde_json::from_str(state).unwrap();
            assert!(state["request"]["values"].is_array());
        }
        rows += 1;
    }
    assert!(rows > 0);
}
