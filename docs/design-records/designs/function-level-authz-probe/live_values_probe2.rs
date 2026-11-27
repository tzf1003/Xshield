// Appended after live_values_probe.rs (its helpers up to the test function) on PR 227 head f81a099.
fn base64_text(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

fn base64_part(boundary: &str, text: &str) -> Vec<u8> {
    format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--{boundary}--\r\n",
        base64_text(text)
    )
    .into_bytes()
}

#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_values_probe2() {
    let site = site();
    const FORM: &str = "application/x-www-form-urlencoded";
    const MIXED: &str = "multipart/mixed; boundary=----probe7d1";
    const FORM_DATA: &str = "multipart/form-data; boundary=----probe7d1";
    let probes = vec![
        ValuesProbe { name: "V4 120-field Chinese form, id route", method: "POST", path: "/api/patients/PT-7001/survey", query: None, content_type: Some(FORM), body: zh_form(120).into_bytes(), expect_block: Some(false) },
        ValuesProbe { name: "V6 no content type, form unseen id", method: "POST", path: "/api/appointments", query: None, content_type: None, body: b"patient_id=PT-7004&note=routine".to_vec(), expect_block: Some(true) },
        ValuesProbe { name: "V6c no content type, form own id", method: "POST", path: "/api/appointments", query: None, content_type: None, body: b"patient_id=PT-7001&note=routine".to_vec(), expect_block: Some(false) },
        ValuesProbe { name: "V7 multipart/mixed unseen id", method: "POST", path: "/api/appointments", query: None, content_type: Some(MIXED), body: multipart("----probe7d1", &[("patient_id", "PT-7004"), ("note", "routine follow-up")]), expect_block: Some(true) },
        ValuesProbe { name: "V7c multipart/mixed own id", method: "POST", path: "/api/appointments", query: None, content_type: Some(MIXED), body: multipart("----probe7d1", &[("patient_id", "PT-7001"), ("note", "routine follow-up")]), expect_block: Some(false) },
        ValuesProbe { name: "W1 form-typed JSON wrap, unseen id", method: "POST", path: "/api/appointments", query: None, content_type: Some(FORM), body: br#"{"a":"&note=x&patient_id=PT-7004&b="}"#.to_vec(), expect_block: Some(true) },
        ValuesProbe { name: "W1c form-typed JSON wrap, own id", method: "POST", path: "/api/appointments", query: None, content_type: Some(FORM), body: br#"{"a":"&note=x&patient_id=PT-7001&b="}"#.to_vec(), expect_block: Some(false) },
        ValuesProbe { name: "W2 base64 part, decoded SQLi", method: "POST", path: "/api/patients/PT-7001/notes", query: None, content_type: Some(FORM_DATA), body: base64_part("----probe7d1", "' OR 1=1 --"), expect_block: Some(true) },
        ValuesProbe { name: "W2c base64 part, decoded plain text", method: "POST", path: "/api/patients/PT-7001/notes", query: None, content_type: Some(FORM_DATA), body: base64_part("----probe7d1", "blood pressure stable, follow-up in two weeks"), expect_block: Some(false) },
    ];
    for round in 0..2u64 {
        let judge = Judge::new(
            ContextKey::new(vec![8; 32]),
            JevClient::from_environment().expect("Jev configuration"),
        );
        see(&judge, &site, DOCTOR, "GET", "/api/home", br#"{"doctor":{"id":"DR-A"}}"#, 1_000);
        see(
            &judge,
            &site,
            DOCTOR,
            "GET",
            "/api/patients",
            br#"{"patients":[{"patient_id":"PT-7001","name":"Zhang Wei","age":54},{"patient_id":"PT-7002","name":"Li Na","age":31},{"patient_id":"PT-7003","name":"Wang Fang","age":47}]}"#,
            1_001,
        );
        see(
            &judge,
            &site,
            DOCTOR,
            "GET",
            "/api/patients/PT-7001",
            br#"{"patient":{"patient_id":"PT-7001","name":"Zhang Wei","age":54}}"#,
            1_002,
        );
        see(
            &judge,
            &site,
            DOCTOR,
            "GET",
            "/api/patients/PT-7001/notes",
            br#"{"notes":[{"id":"n-100","text":"blood pressure stable"}]}"#,
            1_003,
        );
        for (index, probe) in probes.iter().enumerate() {
            let now_ms = 10_000 + u64::try_from(index).unwrap_or(0) * 5_000;
            let request_id = format!("req_{:032x}", round * 1_000_000 + now_ms);
            let judgement = judge
                .judge(
                    &site,
                    &RequestFacts {
                        route: None,
                        request_headers: &[],
                        method_overrides: &[],
                        request_id: &request_id,
                        method: probe.method,
                        path: probe.path,
                        query: probe.query.as_deref(),
                        content_type: probe.content_type,
                        body: &probe.body,
                        credential: Some(DOCTOR),
                        client: "10.0.0.1",
                        now_ms,
                    },
                )
                .await;
            let record = &judgement.record;
            let blocked = !judgement.forward;
            let detail = record.jev.as_ref().map_or_else(
                || "no model call".to_owned(),
                |jev| {
                    format!(
                        "batches={:?} batch={:?} left_out={:?} bytes={:?} {}ms failure={:?} access[{}] attack[{}]",
                        jev.batches,
                        jev.batch,
                        jev.left_out,
                        jev.request_bytes,
                        jev.millis,
                        jev.failure,
                        probabilities(&jev.access, ACCESS),
                        probabilities(&jev.attack, ATTACK)
                    )
                },
            );
            println!(
                "VPROBE2 r{round} {:<40} blocked={:<5} expected={:?} {:?}/{:?} truncated={:?} status={} {}",
                probe.name,
                blocked,
                probe.expect_block,
                record.decision_path,
                record.outcome,
                record.trace.values_truncated,
                judgement.refuse_status,
                detail
            );
        }
    }
}
