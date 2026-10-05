//! Reads the encrypted journal of a finished browser-loop run back and proves
//! every request the browser observed was audited with its decision, reason
//! code and terminal event, that page issuance and bootstrap delivery left
//! their stages, and that the audit publisher's parser accepts every record.
//! Run by `scripts/test_browser_loop.sh`; ignored otherwise.

use serde::Deserialize;
use std::{collections::BTreeMap, env, fs, path::PathBuf};
use xshield_audit::{JournalError, JournalKey, JournalLimits, LocalJournal};

#[derive(Deserialize)]
struct Expectations {
    decisions: Vec<ExpectedDecision>,
    stages: Vec<ExpectedStage>,
}

#[derive(Deserialize)]
struct ExpectedDecision {
    request_id: String,
    decision: String,
    reason_code: String,
}

#[derive(Deserialize)]
struct ExpectedStage {
    request_id: String,
    stage: String,
    outcome: String,
    reason_code: String,
}

#[derive(Default)]
struct Observed {
    decisions: Vec<(String, String)>,
    stages: Vec<(String, String, String)>,
    terminal: bool,
}

#[test]
#[ignore = "run by scripts/test_browser_loop.sh after the edge stopped"]
fn every_browser_loop_request_is_audited_with_its_reason() {
    let expectations: Expectations = serde_json::from_slice(
        &fs::read(env::var("XSHIELD_BROWSER_LOOP_AUDIT").expect("expectations path")).unwrap(),
    )
    .unwrap();
    let directory = PathBuf::from(env::var("XSHIELD_BROWSER_LOOP_JOURNAL").expect("journal"));
    let key =
        JournalKey::from_hex(&env::var("XSHIELD_BROWSER_LOOP_JOURNAL_KEY_HEX").unwrap()).unwrap();
    let limits = JournalLimits::new(16_777_216, 12_582_912, 1_048_576).unwrap();
    let (journal, _) = LocalJournal::open(&directory, "journal-loop-r1", key, limits).unwrap();
    let mut requests = BTreeMap::<String, Observed>::new();
    let mut rejected = Vec::new();
    journal
        .visit_closed_records(1_000_000, |record| {
            let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                .map_err(|_| JournalError::InvalidEvent)?;
            // Whatever the real edge wrote must be publishable: the publisher
            // parses a whole sealed segment before it indexes any row.
            if let Err(error) = xshield_worker::check_journal_record(record) {
                rejected.push(format!(
                    "{} {} -> {error}",
                    event["event_type"], event["payload"]["stage"]
                ));
            }
            let Some(request_id) = event["request_id"].as_str() else {
                return Ok(());
            };
            let observed = requests.entry(request_id.to_owned()).or_default();
            let payload = &event["payload"];
            match event["event_type"].as_str() {
                Some("decision.composed") => observed.decisions.push((
                    payload["decision"].as_str().unwrap_or_default().to_owned(),
                    payload["reason_code"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )),
                Some("stage.completed" | "stage.skipped") => observed.stages.push((
                    payload["stage"].as_str().unwrap_or_default().to_owned(),
                    payload["outcome"].as_str().unwrap_or_default().to_owned(),
                    payload["reason_code"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )),
                Some("request.completed" | "request.aborted") => observed.terminal = true,
                _ => {}
            }
            Ok(())
        })
        .unwrap();
    assert!(
        rejected.is_empty(),
        "the publisher rejects what the edge wrote: {rejected:#?}"
    );
    assert!(!expectations.decisions.is_empty());
    for expected in &expectations.decisions {
        let observed = requests
            .get(&expected.request_id)
            .unwrap_or_else(|| panic!("{} missing from the journal", expected.request_id));
        assert_eq!(
            observed.decisions,
            [(expected.decision.clone(), expected.reason_code.clone())],
            "{}",
            expected.request_id
        );
        assert!(
            observed.terminal,
            "{} has no terminal event",
            expected.request_id
        );
    }
    for expected in &expectations.stages {
        let observed = requests
            .get(&expected.request_id)
            .unwrap_or_else(|| panic!("{} missing from the journal", expected.request_id));
        assert!(
            observed.stages.contains(&(
                expected.stage.clone(),
                expected.outcome.clone(),
                expected.reason_code.clone()
            )),
            "{}: {:?}",
            expected.request_id,
            observed.stages
        );
    }
    // References never enter the journal, only counts and reason codes.
    journal
        .visit_closed_records(1_000_000, |record| {
            assert!(
                !String::from_utf8_lossy(record.plaintext()).contains("\"action."),
                "a journal record carries an action reference"
            );
            Ok(())
        })
        .unwrap();
}
