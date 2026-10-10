//! PostgreSQL wire regression for the site-wide job listing used by audit administrators.

use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{CaseId, JobId, SiteId, TenantId};
use xshield_postgres::{
    CaseAnalysisJobCreate, ControlJobAdminListQuery, ControlJobWriteOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn site_listing_covers_every_owner_in_order_with_owner_references() {
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
    let tenant = TenantId::parse(format!("tenant_admin_jobs_{suffix}")).expect("tenant is valid");
    let site = SiteId::parse(format!("site_admin_jobs_{suffix}")).expect("site is valid");
    let first_owner = "investigator-admin-a";
    let second_owner = "investigator-admin-b";
    let first_case = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    let second_case = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    seed_case(&pool, &tenant, &site, &first_case, first_owner).await;
    seed_case(&pool, &tenant, &site, &second_case, second_owner).await;

    let mut created = Vec::new();
    for (nonce, (owner, case)) in [
        (first_owner, &first_case),
        (second_owner, &second_case),
        (first_owner, &first_case),
    ]
    .into_iter()
    .enumerate()
    {
        let job = JobId::parse(format!("job_{}", Uuid::now_v7())).expect("job is valid");
        let nonce = u8::try_from(nonce + 1).expect("nonce fits");
        create(&store, &tenant, &site, case, owner, &job, nonce).await;
        created.push((job, owner));
    }
    created.sort_by(|a, b| b.0.as_str().cmp(a.0.as_str()));

    // Page size two covers the two largest identities, whoever submitted them.
    let first = store
        .list_control_jobs_for_site(
            ControlJobAdminListQuery::new(&tenant, &site, None, 2).expect("query is valid"),
        )
        .await
        .expect("first page reads");
    let ids: Vec<&JobId> = first
        .items()
        .iter()
        .map(|item| item.record().job_id())
        .collect();
    assert_eq!(ids, [&created[0].0, &created[1].0]);
    let owners: Vec<&str> = first
        .items()
        .iter()
        .map(xshield_postgres::ControlJobAdminListItem::owner_ref)
        .collect();
    assert_eq!(owners, [created[0].1, created[1].1]);
    let next = first.next_job_id().expect("a lookahead row exists").clone();

    // The continuation starts strictly below the cursor and ends the walk.
    let second = store
        .list_control_jobs_for_site(
            ControlJobAdminListQuery::new(&tenant, &site, Some(&next), 2).expect("query is valid"),
        )
        .await
        .expect("second page reads");
    assert_eq!(second.items().len(), 1);
    assert_eq!(second.items()[0].record().job_id(), &created[2].0);
    assert_eq!(second.items()[0].owner_ref(), created[2].1);
    assert!(second.next_job_id().is_none());

    // Every ignored PostgreSQL test shares one database per CI run, and others count
    // whole tables. Remove this test's rows, jobs first since they reference cases.
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
         ) VALUES ($1, $2, $3, $4, 'Admin job list regression', 'open', $5, $6, $7)",
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
