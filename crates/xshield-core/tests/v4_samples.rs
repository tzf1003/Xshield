//! The v4 samples under `examples/` must load through the code that reads them:
//! `SiteSpec` for the site configuration and `DecisionRecord` for the decision
//! log. `scripts/validate_library.py` checks the same files against `schemas/`;
//! this test is the authority on what the gateway accepts.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{Value, json};
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

/// A site with one object position, on the sample site of `scripts/validate_library.py`.
fn site_with_slot(slot: &Value) -> Value {
    json!({
        "name": "emr",
        "hosts": ["emr.example.com"],
        "origin": "http://10.0.0.5:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login"],
        "objects": {"classes": [{"id": "patient", "name": "患者"}], "slots": [slot]}
    })
}

#[test]
fn object_judgements_load_and_the_refused_forms_do_not() {
    let judged = json!({
        "name": "emr",
        "hosts": ["emr.example.com"],
        "origin": "http://10.0.0.5:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login"],
        "objects": {
            "classes": [{"id": "doctor", "name": "医生"}, {"id": "patient", "name": "患者"}],
            "slots": [
                {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin", "identity": "user"},
                {"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "rule", "tier": "admin", "reliability": "high"},
                {"key": "GET /api/search q", "class": "patient", "source": "agent", "tier": "public", "reliability": "medium"},
                {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin", "accepts_public": false, "reliability": "high", "paused": true}
            ]
        }
    });
    SiteSpec::from_value(&judged).unwrap_or_else(|error| panic!("{judged}: {error}"));

    let refused = [
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "tier": "admin", "accepts_public": false, "reliability": "high"}),
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "reliability": "high"}),
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "tier": "everyone", "reliability": "high"}),
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "tier": "public", "reliability": "certain"}),
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "identity": "tenant"}),
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "tier": "public", "reliability": "high", "paused": "yes"}),
        json!({"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin", "accepts_public": "no", "reliability": "high"}),
    ];
    for slot in refused {
        let site = site_with_slot(&slot);
        assert!(
            SiteSpec::from_value(&site).is_err(),
            "{slot} should be refused"
        );
    }
}
