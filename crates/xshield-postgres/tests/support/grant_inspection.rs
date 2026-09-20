//! Shared synthetic qualification graph for store and control integration tests.

use sqlx::PgPool;

pub const GRANT: &str = "grant_018f2a3b-4c5d-7000-8000-00000000e101";
pub const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-00000000e102";
pub const SOURCE_REQUEST: &str = "req_018f2a3b-4c5d-7000-8000-00000000e103";
pub const SOURCE_EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-00000000e104";

pub async fn seed(pool: &PgPool, tenant: &str, site: &str) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO xshield.policy_revisions
            (tenant_id, site_id, revision, status, content_digest, artifact_ref)
         VALUES ($1, $2, 'inspection-r1', 'active', repeat('a', 64), 'inspection-policy')",
    )
    .bind(tenant)
    .bind(site)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.auth_bindings
            (tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
             authorization_context_ref, auth_epoch, credential_generation, status,
             absolute_expires_at)
         VALUES ($1, $2, $3, decode(repeat('e1', 32), 'hex'), 'inspection-principal',
                 'inspection-context', 4, 2, 'active', now() + interval '900 seconds')",
    )
    .bind(tenant)
    .bind(site)
    .bind(BINDING)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.page_evidence
            (tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
             source_request_id, response_artifact_ref, page_template, build_fingerprint,
             policy_revision, mapping_revision, status, verified_at, expires_at)
         VALUES ($1, $2, 'page_018f2a3b-4c5d-7000-8000-00000000e105', $3, 4, $4,
                 'inspection-artifact', 'inspection-page', decode(repeat('e2', 32), 'hex'),
                 'inspection-r1', 'inspection-mapping', 'verified',
                 now() - interval '120 seconds', now() + interval '1000 seconds')",
    )
    .bind(tenant)
    .bind(site)
    .bind(BINDING)
    .bind(SOURCE_REQUEST)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.action_descriptors
            (tenant_id, site_id, action_id, page_template, operation_id, method,
             route_template, target_rule, allowed_fields, field_profile,
             policy_revision, mapping_revision, status)
         VALUES ($1, $2, 'inspection.open', 'inspection-page', 'orders.read', 'GET',
                 '/orders/{id}', '{\"kind\":\"resource\",\"resource_type\":\"order\"}',
                 '[]', 'customer_detail', 'inspection-r1', 'inspection-mapping', 'approved')",
    )
    .bind(tenant)
    .bind(site)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.ui_actions
            (tenant_id, site_id, action_ref, binding_id, auth_epoch, source_request_id,
             page_evidence_id, operation_id, target_constraints, field_profile, source_rule,
             policy_revision, status, issued_at, expires_at, source_action_ref,
             mapping_revision, method, route_template, allowed_fields)
         VALUES ($1, $2, 'inspection-action', $3, 4, $4,
                 'page_018f2a3b-4c5d-7000-8000-00000000e105', 'orders.read',
                 '{\"secret\":\"inspection-target\"}', 'customer_detail', 'inspection-source',
                 'inspection-r1', 'active', now() - interval '110 seconds',
                 now() + interval '800 seconds', 'inspection.open',
                 'inspection-mapping', 'GET', '/orders/{id}', '[]')",
    )
    .bind(tenant)
    .bind(site)
    .bind(BINDING)
    .bind(SOURCE_REQUEST)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.resource_grants
            (tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref, resource_type,
             resource_key_hmac, operation_id, view_id, constraints, source_event_id,
             issuance_key, policy_revision, status, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, 4, 'inspection-action', 'order',
                 decode(repeat('e3', 32), 'hex'), 'orders.read', 'customer_detail',
                 '{\"secret\":\"inspection-constraints\"}', $5, 'inspection-issuance',
                 'inspection-r1', 'active', now() - interval '100 seconds',
                 now() + interval '600 seconds')",
    )
    .bind(tenant)
    .bind(site)
    .bind(GRANT)
    .bind(BINDING)
    .bind(SOURCE_EVENT)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

pub async fn cleanup(pool: &PgPool, tenant: &str, site: &str) {
    // Delete only the fixed graph belonging to this fixture in the requested scope.
    for statement in [
        "DELETE FROM xshield.resource_grants WHERE tenant_id = $1 AND site_id = $2
          AND grant_id = 'grant_018f2a3b-4c5d-7000-8000-00000000e101'",
        "DELETE FROM xshield.ui_actions WHERE tenant_id = $1 AND site_id = $2
          AND action_ref = 'inspection-action'",
        "DELETE FROM xshield.action_descriptors WHERE tenant_id = $1 AND site_id = $2
          AND action_id = 'inspection.open' AND policy_revision = 'inspection-r1'
          AND mapping_revision = 'inspection-mapping'",
        "DELETE FROM xshield.page_evidence WHERE tenant_id = $1 AND site_id = $2
          AND page_evidence_id = 'page_018f2a3b-4c5d-7000-8000-00000000e105'",
        "DELETE FROM xshield.auth_bindings WHERE tenant_id = $1 AND site_id = $2
          AND binding_id = 'auth_018f2a3b-4c5d-7000-8000-00000000e102'",
        "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1 AND site_id = $2
          AND revision = 'inspection-r1'",
    ] {
        sqlx::query(statement)
            .bind(tenant)
            .bind(site)
            .execute(pool)
            .await
            .unwrap();
    }
}
