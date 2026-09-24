//! `PostgreSQL` wire regression for metadata-only investigation exports.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::{
    domain::{ArtifactId, CaseId, ExportId, RequestId, SiteId, TenantId},
    investigation::InvestigationExportDraft,
};
use xshield_postgres::{
    InvestigationExportCreate, InvestigationExportDecision, InvestigationExportDecisionOutcome,
    InvestigationExportPackage, InvestigationExportPackageClaim,
    InvestigationExportPackageClaimOutcome, InvestigationExportPackageOutcome,
    InvestigationExportWriteOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn investigation_export_is_scoped_idempotent_independent_and_download_bounded() {
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
        .expect("export store connects");
    let suffix = Uuid::now_v7().simple().to_string();
    let tenant = TenantId::parse(format!("tenant_export_{suffix}")).expect("tenant is valid");
    let site = SiteId::parse(format!("site_export_{suffix}")).expect("site is valid");
    let owner = "investigator-export";
    let approver = "approver-export";
    let case_id = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    let export_id = ExportId::parse(format!("export_{}", Uuid::now_v7())).expect("export is valid");
    seed_case(&pool, &tenant, &site, &case_id, owner).await;

    let draft = InvestigationExportDraft::new(
        export_id.clone(),
        tenant.clone(),
        site.clone(),
        case_id.clone(),
        owner,
        "metadata-only regression",
    )
    .expect("draft is valid");
    let created = store
        .create_investigation_export(
            InvestigationExportCreate::new(&draft, &[11; 32], &[12; 32])
                .expect("create command is valid"),
        )
        .await
        .expect("export create succeeds");
    let pending = match created {
        InvestigationExportWriteOutcome::Created(record) => record,
        other => panic!("expected created export, got {other:?}"),
    };
    assert_eq!(pending.status(), "pending_approval");
    assert_eq!(pending.requested_by(), owner);

    let replay = store
        .create_investigation_export(
            InvestigationExportCreate::new(&draft, &[11; 32], &[12; 32])
                .expect("replay command is valid"),
        )
        .await
        .expect("export replay succeeds");
    assert_eq!(
        replay,
        InvestigationExportWriteOutcome::Existing(pending.clone())
    );

    let conflict = store
        .create_investigation_export(
            InvestigationExportCreate::new(&draft, &[11; 32], &[13; 32])
                .expect("conflict command is valid"),
        )
        .await
        .expect("export conflict lookup succeeds");
    assert_eq!(conflict, InvestigationExportWriteOutcome::Conflict);

    let approval = InvestigationExportDecision::new(
        &export_id,
        approver,
        "independent metadata review",
        &[21; 32],
        &[22; 32],
        true,
        900,
    )
    .expect("approval command is valid");
    let decided = store
        .decide_investigation_export(approval, &tenant, &site)
        .await
        .expect("approval succeeds");
    let (approved_record, snapshot) = match decided {
        InvestigationExportDecisionOutcome::Decided(record, Some(snapshot)) => (record, snapshot),
        other => panic!("expected approved export, got {other:?}"),
    };
    assert_eq!(approved_record.status(), "approved");
    assert_eq!(approved_record.decided_by(), Some(approver));
    assert!(snapshot.artifacts().is_empty());

    let self_approval = store
        .decide_investigation_export(
            InvestigationExportDecision::new(
                &export_id,
                owner,
                "self approval must fail",
                &[23; 32],
                &[24; 32],
                true,
                900,
            )
            .expect("self-approval command is valid"),
            &tenant,
            &site,
        )
        .await
        .expect("self-approval check succeeds");
    assert_eq!(
        self_approval,
        InvestigationExportDecisionOutcome::SelfApproval
    );

    let package_request =
        RequestId::parse(format!("req_{}", Uuid::now_v7())).expect("request is valid");
    let package_expires_at = approved_record
        .expires_at()
        .expect("approved export has an expiry");
    let parent_refs_digest = [31_u8; 32];
    let first_lease = match store
        .claim_investigation_export_package(
            package_claim(
                &export_id,
                &package_request,
                &parent_refs_digest,
                package_expires_at,
            ),
            &tenant,
            &site,
        )
        .await
        .expect("first package claim succeeds")
    {
        InvestigationExportPackageClaimOutcome::Claimed { lease_until } => lease_until,
        other => panic!("expected first package claim, got {other:?}"),
    };
    assert!(matches!(
        store
            .claim_investigation_export_package(
                package_claim(
                    &export_id,
                    &package_request,
                    &parent_refs_digest,
                    package_expires_at,
                ),
                &tenant,
                &site
            )
            .await
            .expect("busy claim lookup succeeds"),
        InvestigationExportPackageClaimOutcome::Busy
    ));
    let conflicting_parent_refs_digest = [32_u8; 32];
    assert!(matches!(
        store
            .claim_investigation_export_package(
                package_claim(
                    &export_id,
                    &package_request,
                    &conflicting_parent_refs_digest,
                    package_expires_at,
                ),
                &tenant,
                &site
            )
            .await
            .expect("claim conflict lookup succeeds"),
        InvestigationExportPackageClaimOutcome::Conflict
    ));

    sqlx::query(
        "UPDATE xshield.investigation_export_package_claims
         SET lease_until = created_at
         WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(export_id.as_str())
    .execute(&pool)
    .await
    .expect("claim expiry simulation succeeds");
    let successor_lease = match store
        .claim_investigation_export_package(
            package_claim(
                &export_id,
                &package_request,
                &parent_refs_digest,
                package_expires_at,
            ),
            &tenant,
            &site,
        )
        .await
        .expect("expired claim reclaim succeeds")
    {
        InvestigationExportPackageClaimOutcome::Claimed { lease_until } => lease_until,
        other => panic!("expected reclaimed package claim, got {other:?}"),
    };
    assert_ne!(first_lease, successor_lease);

    let stale_artifact =
        ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).expect("artifact is valid");
    let stale_result = store
        .complete_investigation_export_claimed(
            InvestigationExportPackage::new(
                &export_id,
                &stale_artifact,
                &package_request,
                &"a".repeat(64),
                128,
            )
            .expect("stale package command is valid"),
            &tenant,
            &site,
            first_lease,
        )
        .await
        .expect("stale writer outcome is observable");
    assert!(matches!(
        stale_result,
        InvestigationExportPackageOutcome::Unavailable
    ));

    let package_artifact =
        ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).expect("artifact is valid");
    let completed = store
        .complete_investigation_export_claimed(
            InvestigationExportPackage::new(
                &export_id,
                &package_artifact,
                &package_request,
                &"a".repeat(64),
                128,
            )
            .expect("package command is valid"),
            &tenant,
            &site,
            successor_lease,
        )
        .await
        .expect("package completion succeeds");
    let ready = match completed {
        InvestigationExportPackageOutcome::Completed(record) => record,
        other => panic!("expected completed export, got {other:?}"),
    };
    assert_eq!(ready.status(), "ready");
    assert_eq!(ready.package_bytes(), Some(128));

    let package_replay = store
        .complete_investigation_export(
            InvestigationExportPackage::new(
                &export_id,
                &package_artifact,
                &package_request,
                &"a".repeat(64),
                128,
            )
            .expect("package replay command is valid"),
            &tenant,
            &site,
        )
        .await
        .expect("package replay succeeds");
    assert!(matches!(
        package_replay,
        InvestigationExportPackageOutcome::Existing(_)
    ));

    let package_conflict = store
        .complete_investigation_export(
            InvestigationExportPackage::new(
                &export_id,
                &package_artifact,
                &package_request,
                &"b".repeat(64),
                128,
            )
            .expect("conflicting package command is valid"),
            &tenant,
            &site,
        )
        .await
        .expect("package conflict is observable");
    assert!(matches!(
        package_conflict,
        InvestigationExportPackageOutcome::Conflict
    ));

    let first = store
        .claim_investigation_export_download(&tenant, &site, &export_id)
        .await
        .expect("first claim succeeds")
        .expect("first claim is available");
    assert_eq!(first.download_count(), 1);
    let second = store
        .claim_investigation_export_download(&tenant, &site, &export_id)
        .await
        .expect("second claim succeeds")
        .expect("second claim is available");
    assert_eq!(second.download_count(), 2);
    assert!(
        store
            .claim_investigation_export_download(&tenant, &site, &export_id)
            .await
            .expect("third claim succeeds")
            .is_none()
    );

    let foreign = TenantId::parse(format!("tenant_foreign_{suffix}")).expect("tenant is valid");
    assert!(
        store
            .read_investigation_export(&foreign, &site, &export_id)
            .await
            .expect("foreign read is scoped")
            .is_none()
    );

    sqlx::query("DELETE FROM xshield.investigation_exports WHERE tenant_id = $1 AND site_id = $2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("export cleanup succeeds");
    let remaining_claims: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.investigation_export_package_claims
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .expect("claim cleanup is queryable");
    assert_eq!(remaining_claims, 0);
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE tenant_id = $1 AND site_id = $2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("case cleanup succeeds");
    pool.close().await;
}

async fn seed_case(pool: &PgPool, tenant: &TenantId, site: &SiteId, case_id: &CaseId, owner: &str) {
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ($1, $2, $3, $4, 'Export regression', 'open', $5, $6, $7)",
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

fn package_claim<'a>(
    export_id: &'a ExportId,
    request_id: &'a RequestId,
    parent_refs_digest: &'a [u8; 32],
    package_expires_at: DateTime<Utc>,
) -> InvestigationExportPackageClaim<'a> {
    InvestigationExportPackageClaim::new(
        export_id,
        request_id,
        parent_refs_digest,
        package_expires_at,
    )
    .expect("package claim command is valid")
}
