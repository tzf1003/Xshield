//! Explicit local-lab scoring of encrypted Jev records from synthetic order cases.

use std::{collections::BTreeMap, env, fs, path::Path};
use xshield_audit::{JournalKey, JournalLimits, LocalJournal};
use xshield_core::domain::{SiteId, TenantId};
use xshield_evidence::{EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};

fn verify_model_record(
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    report: &serde_json::Value,
    label: &serde_json::Value,
    source_request_id: &str,
) {
    let input_artifact = report["input_artifact_id"]
        .as_str()
        .expect("provider input artifact");
    let input_manifest = vault
        .read_manifest(tenant, site, input_artifact)
        .expect("authenticated provider input manifest");
    assert_eq!(input_manifest.manifest().kind, "model_input");
    let input_bytes = vault
        .read_content_matching_manifest(tenant, site, &input_manifest)
        .expect("authenticated provider input body");
    let sent: serde_json::Value =
        serde_json::from_slice(&input_bytes).expect("provider input JSON");
    assert_eq!(
        sent["state"]["auth_facts"]["attempt_request_id"],
        label["attempt_request_id"]
    );
    assert_eq!(
        sent["state"]["auth_facts"]["source_request_id"],
        source_request_id
    );
    assert_eq!(
        sent["state"]["auth_facts"]["requested_resource_ref"],
        label["requested_resource_ref"]
    );
    assert_eq!(sent["state"]["coverage"]["auth_facts"], "operator_supplied");
    let artifact = report["call_artifact_id"].as_str().expect("call artifact");
    let manifest = vault
        .read_manifest(tenant, site, artifact)
        .expect("authenticated model-call manifest");
    assert_eq!(manifest.manifest().kind, "model_call");
    assert_eq!(manifest.manifest().request_id, report["request_id"]);
    let content = vault
        .read_content_matching_manifest(tenant, site, &manifest)
        .expect("authenticated model-call body");
    let call: serde_json::Value = serde_json::from_slice(&content).expect("model-call JSON");
    assert_eq!(call["model_call_id"], report["model_call_id"]);
    let gateway =
        env::var("XSHIELD_JEV_ROUTE").unwrap_or_else(|_| "direct".to_owned()) == "gateway";
    assert_eq!(
        call["provider"],
        if gateway {
            "vercel_ai_gateway"
        } else {
            "typesafe"
        }
    );
    assert_eq!(
        call["provider_model_id"],
        if gateway {
            "typesafe-ai/jev"
        } else {
            "jev-1.13.0"
        }
    );
    assert_eq!(call["schema_validation"], "valid");
    assert_eq!(call["capture_status"], "complete");
    let actual = call["result"].as_str().expect("Choice result");
    let expected = label["expected_choice"].as_str().expect("expected Choice");
    assert!(matches!(actual, "ALLOW" | "DENY" | "NONE" | "UNKNOWN"));
    assert!(matches!(expected, "ALLOW" | "DENY"));
    assert!(call["duration_ms"].is_u64());
    assert!(call["usage"].is_object());
    println!(
        "JEV_LAB_SCORE {}",
        serde_json::json!({"case": label["case"], "actual": actual, "expected": expected,
            "model_call_id": call["model_call_id"],
            "duration_ms": call["duration_ms"], "usage": call["usage"]})
    );
}

#[test]
#[ignore = "requires the temporary IDOR lab's successful real-provider receipts"]
fn score_real_jev_idor_lab() {
    let reports_file = env::var("XSHIELD_LAB_REPORTS_FILE").expect("lab reports path");
    let labels_file = env::var("XSHIELD_LAB_LABELS_FILE").expect("lab labels path");
    let root = env::var("XSHIELD_EVIDENCE_ROOT").expect("lab evidence path");
    let key_id = env::var("XSHIELD_EVIDENCE_KEY_ID").expect("lab evidence key id");
    let key = env::var("XSHIELD_EVIDENCE_KEY_HEX").expect("lab evidence key");
    let tenant = TenantId::parse("tenant_lab").expect("fixed lab tenant");
    let site_id = env::var("XSHIELD_LAB_SITE_ID").expect("lab site id");
    let site = SiteId::parse(&site_id).expect("fixed lab site");
    let config = EvidenceVaultConfig::new(Path::new(&root), &key_id, 512 * 1024, 1)
        .expect("lab evidence configuration");
    let vault = LocalEvidenceVault::open(config, EvidenceKey::from_hex(&key).expect("lab key"))
        .expect("lab evidence vault");
    let reports: serde_json::Value =
        serde_json::from_slice(&fs::read(reports_file).expect("lab receipts"))
            .expect("receipts JSON");
    let labels: serde_json::Value =
        serde_json::from_slice(&fs::read(labels_file).expect("lab labels")).expect("labels JSON");
    let source_request_id = labels["source_request_id"]
        .as_str()
        .expect("source request identity")
        .to_owned();
    let reports = reports.as_array().expect("receipt list");
    let labels = labels["labels"].as_array().expect("label list");
    assert_eq!(reports.len(), 2);
    assert_eq!(labels.len(), 2);
    for (receipt, label) in reports.iter().zip(labels) {
        let case = receipt["case"].as_str().expect("case name");
        assert_eq!(case, label["case"].as_str().expect("label case"));
        let report = &receipt["report"];
        assert_eq!(report["status"], "success");
        assert_eq!(report["reason_code"], "MODEL_EVALUATED");
        verify_model_record(&vault, &tenant, &site, report, label, &source_request_id);
    }
    let journal_root = env::var("XSHIELD_MODEL_JOURNAL_DIRECTORY").expect("lab journal path");
    let journal_key_id = env::var("XSHIELD_JOURNAL_KEY_ID").expect("lab journal key id");
    let journal_key = env::var("XSHIELD_JOURNAL_KEY_HEX").expect("lab journal key");
    let bytes = 16 * 1024 * 1024;
    let (journal, _) = LocalJournal::open(
        journal_root,
        journal_key_id,
        JournalKey::from_hex(&journal_key).expect("lab journal key format"),
        JournalLimits::new(bytes, bytes * 9 / 10, 1).expect("lab journal budget"),
    )
    .expect("lab journal");
    let mut lifecycles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    journal
        .visit_closed_records(100, |record| {
            let event: serde_json::Value =
                serde_json::from_slice(record.plaintext()).expect("journal envelope JSON");
            let call_id = event["payload"]["model_call_id"]
                .as_str()
                .expect("journal model-call identity");
            let event_type = event["event_type"].as_str().expect("journal event type");
            lifecycles
                .entry(call_id.to_owned())
                .or_default()
                .push(event_type.to_owned());
            Ok(())
        })
        .expect("authenticated journal scan");
    assert_eq!(lifecycles.len(), 2);
    for receipt in reports {
        let call_id = receipt["report"]["model_call_id"]
            .as_str()
            .expect("model call identity");
        assert_eq!(
            lifecycles.get(call_id).expect("journal call"),
            &vec!["model.started", "model.requested", "model.responded"]
        );
    }
}
