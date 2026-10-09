//! PostgreSQL wire regression for owner-scoped job listing.

use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{CaseId, JobId, SiteId, TenantId};
use xshield_postgres::{
    CaseAnalysisJobCreate, ControlJobListQuery, ControlJobWriteOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn owner_pages_are_descending_keyset_ordered_and_owner_scoped() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPool::connect(&url).await.expect("test database connects");
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("database name is queryable");
    assert!(
        database.starts_with("xshield_test_"),
        "requires script-owned test database"
    );
    let store = PostgresIdentityStore::connect(&url, 3, Duration::from_secs(5))
        .await
        .expect("job store connects");
    let suffix = Uuid::now_v7().simple().to_string();
    let tenant = TenantId::parse(format!("tenant_jobs_{suffix}")).expect("tenant is valid");
    let site = SiteId::parse(format!("site_jobs_{suffix}")).expect("site is valid");
    let case_id = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    let owner = "investigator-jobs";
    let other = "investigator-other";
    let other_case = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    seed_case(&pool, &tenant, &site, &case_id, owner).await;
    seed_case(&pool, &tenant, &site, &other_case, other).await;

    // Three jobs for the owner and one for another subject on that subject's own
    // case. The list must return the owner's identities in bytewise descending
    // order regardless of insert order.
    let mut mine = Vec::new();
    for nonce in 1_u8..=3 {
        let job = job_id();
        create(&store, &tenant, &site, &case_id, owner, &job, nonce).await;
        mine.push(job);
    }
    let foreign = job_id();
    create(&store, &tenant, &site, &other_case, other, &foreign, 9).await;
    mine.sort_by(|a, b| b.as_str().cmp(a.as_str()));

    // Page size two: the first page holds the two largest identities.
    let first = store
        .list_control_jobs(
            ControlJobListQuery::new(&tenant, &site, owner, None, 2).expect("query is valid"),
        )
        .await
        .expect("first page reads");
    let ids: Vec<&str> = first.items().iter().map(|r| r.job_id().as_str()).collect();
    assert_eq!(ids, [mine[0].as_str(), mine[1].as_str()]);
    let next = first.next_job_id().expect("a lookahead row exists").clone();
    assert_eq!(next, mine[1]);

    // The continuation starts strictly below the cursor and ends the walk.
    let second = store
        .list_control_jobs(
            ControlJobListQuery::new(&tenant, &site, owner, Some(&next), 2)
                .expect("query is valid"),
        )
        .await
        .expect("second page reads");
    assert_eq!(second.items().len(), 1);
    assert_eq!(second.items()[0].job_id(), &mine[2]);
    assert!(second.next_job_id().is_none());

    // Another subject never sees these jobs, and a subject with no jobs gets an
    // empty page that still carries the database observation time.
    let foreign_page = store
        .list_control_jobs(
            ControlJobListQuery::new(&tenant, &site, other, None, 10).expect("query is valid"),
        )
        .await
        .expect("foreign page reads");
    assert_eq!(foreign_page.items().len(), 1);
    assert_eq!(foreign_page.items()[0].job_id(), &foreign);
    let nobody = store
        .list_control_jobs(
            ControlJobListQuery::new(&tenant, &site, "investigator-none", None, 10)
                .expect("query is valid"),
        )
        .await
        .expect("empty page reads");
    assert!(nobody.items().is_empty());
    assert!(nobody.next_job_id().is_none());
    assert!(nobody.as_of() <= chrono::Utc::now() + chrono::Duration::seconds(60));

    // Every ignored PostgreSQL test shares one database per CI run, and others
    // count whole tables. Remove this test's rows: jobs first, since they reference cases.
    sqlx::query("DELETE FROM xshield.control_jobs WHERE tenant_id = $1")
        .bind(tenant.as_str())
        .execute(&pool)
        .await
        .expect("job cleanup succeeds");
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE tenant_id = $1")
        .bind(tenant.as_str())
        .execute(&pool)
        .await
        .expect("case cleanup succeeds");
}

fn job_id() -> JobId {
    JobId::parse(format!("job_{}", Uuid::now_v7())).expect("job is valid")
}

async fn create(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    case_id: &CaseId,
    owner: &str,
    job: &JobId,
    nonce: u8,
) {
    let idempotency = [nonce; 32];
    let request = [nonce.wrapping_add(100); 32];
    let command =
        CaseAnalysisJobCreate::new(tenant, site, case_id, owner, job, &idempotency, &request)
            .expect("analysis command is valid");
    match store
        .create_case_analysis_job(command)
        .await
        .expect("job write succeeds")
    {
        ControlJobWriteOutcome::Created(_) => {}
        other => panic!("expected created job, got {other:?}"),
    }
}

async fn seed_case(pool: &PgPool, tenant: &TenantId, site: &SiteId, case_id: &CaseId, owner: &str) {
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ($1, $2, $3, $4, 'Durable job list regression', 'open', $5, $6, $7)",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(case_id.as_str())
    .bind(owner)
    .bind([1_u8; 32])
    .bind([2_u8; 32])
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .expect("case seed succeeds");
}
