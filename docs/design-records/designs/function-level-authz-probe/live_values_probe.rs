fn filler(chars: usize, offset: usize) -> String {
    const SENTENCES: [&str; 8] = [
        "Patient reports mild headache in the morning that eases after breakfast. ",
        "Blood pressure measured twice today and both readings were within the normal range. ",
        "No fever, no cough, appetite is good and sleep has improved since the last visit. ",
        "Advised to continue the current dose and to drink more water during the day. ",
        "Follow-up appointment suggested in two weeks, earlier if the dizziness returns. ",
        "Family history discussed again, nothing new to add to the existing record. ",
        "Walks thirty minutes every evening and has reduced salt as recommended. ",
        "Asked about travel next month, no objection as long as medication is carried. ",
    ];
    let mut text = String::new();
    let mut index = offset;
    while text.chars().count() < chars {
        text.push_str(SENTENCES[index % SENTENCES.len()]);
        index += 1;
    }
    text.chars().take(chars).collect()
}

// ---- local probe of the request values read whole (not committed) ----

struct ValuesProbe {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    query: Option<String>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
    expect_block: Option<bool>,
}

fn zh_form(fields: usize) -> String {
    const ANSWERS: [&str; 6] = [
        "每天早晚各测一次血压，数值都在正常范围内",
        "最近睡眠比上个月好，夜里基本不醒",
        "饮食清淡，已经按医生建议少放盐",
        "每天傍晚散步半小时，周末去公园",
        "没有头晕，也没有胸闷的感觉",
        "按时服药，没有漏服",
    ];
    (0..fields)
        .map(|index| {
            let text = ANSWERS[index % ANSWERS.len()];
            let encoded: String = text.bytes().map(|byte| format!("%{byte:02X}")).collect();
            format!("answer_{index}={encoded}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn multipart(kind_boundary: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{kind_boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{kind_boundary}--\r\n"));
    body.into_bytes()
}

#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_values_probe() {
    let site = site();
    let pads = |tail: &str| {
        let mut query: Vec<String> = (0..200).map(|index| format!("pad{index}=x")).collect();
        query.push(tail.to_owned());
        query.join("&")
    };
    let injection = {
        let mut text = filler(600, 0);
        text.push_str("' OR 1=1 --");
        text
    };
    let injection_query = injection.replace(' ', "+").replace('\'', "%27");
    let probes = vec![
        ValuesProbe { name: "V1 200 pads then unseen patient_id", method: "GET", path: "/api/appointments", query: Some(pads("patient_id=PT-7004")), content_type: None, body: Vec::new(), expect_block: Some(true) },
        ValuesProbe { name: "V1c 200 pads then own patient_id", method: "GET", path: "/api/appointments", query: Some(pads("patient_id=PT-7001")), content_type: None, body: Vec::new(), expect_block: Some(false) },
        ValuesProbe { name: "V2 multipart unseen patient_id", method: "POST", path: "/api/appointments", query: None, content_type: Some("multipart/form-data; boundary=----probe7d1"), body: multipart("----probe7d1", &[("patient_id", "PT-7004"), ("note", "routine follow-up")]), expect_block: Some(true) },
        ValuesProbe { name: "V2c multipart own patient_id", method: "POST", path: "/api/appointments", query: None, content_type: Some("multipart/form-data; boundary=----probe7d1"), body: multipart("----probe7d1", &[("patient_id", "PT-7001"), ("note", "routine follow-up")]), expect_block: Some(false) },
        ValuesProbe { name: "V3 json 600 filler then SQLi", method: "POST", path: "/api/patients/PT-7001/notes", query: None, content_type: Some("application/json"), body: format!(r#"{{"text":"{injection}"}}"#).into_bytes(), expect_block: Some(true) },
        ValuesProbe { name: "V3q 200 pads then 600 filler SQLi", method: "GET", path: "/api/patients/PT-7001/notes", query: Some(pads(&format!("q={injection_query}"))), content_type: None, body: Vec::new(), expect_block: Some(true) },
        ValuesProbe { name: "V4 120-field Chinese form", method: "POST", path: "/api/patients/PT-7001/survey", query: None, content_type: Some("application/x-www-form-urlencoded"), body: zh_form(120).into_bytes(), expect_block: Some(false) },
        ValuesProbe { name: "V4b 120-field Chinese form, no id path", method: "POST", path: "/api/surveys", query: None, content_type: Some("application/x-www-form-urlencoded"), body: zh_form(120).into_bytes(), expect_block: Some(false) },
        ValuesProbe { name: "V5 text/plain JSON unseen patient_id", method: "POST", path: "/api/appointments", query: None, content_type: Some("text/plain"), body: br#"{"patient_id":"PT-7004"}"#.to_vec(), expect_block: Some(true) },
        ValuesProbe { name: "V6 no content type, form unseen id", method: "POST", path: "/api/appointments", query: None, content_type: None, body: b"patient_id=PT-7004&note=routine".to_vec(), expect_block: None },
        ValuesProbe { name: "V7 multipart/mixed unseen id", method: "POST", path: "/api/appointments", query: None, content_type: Some("multipart/mixed; boundary=----probe7d1"), body: multipart("----probe7d1", &[("patient_id", "PT-7004"), ("note", "routine follow-up")]), expect_block: None },
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
                "VPROBE r{round} {:<40} blocked={:<5} expected={:?} {:?}/{:?} truncated={:?} status={} {}",
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
