-- Xshield v3 完整数据模型草案；M1 已实现部分以 migrations/*.sql 为准。
-- 本文件没有执行数据库集成测试。角色、RLS、分区、备份及迁移回滚另行配置。
-- 所有跨表引用包含tenant/site；生产查询仍需应用层授权。
BEGIN;
CREATE SCHEMA IF NOT EXISTS xshield;
CREATE TABLE xshield.policy_revisions (
 tenant_id text NOT NULL, site_id text NOT NULL, revision text NOT NULL,
 status text NOT NULL CHECK (status IN ('draft','tested','approved','active','retired')),
 content_digest text NOT NULL, artifact_ref text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), approved_by text,
 PRIMARY KEY (tenant_id,site_id,revision)
);
CREATE TABLE xshield.auth_bindings (
 tenant_id text NOT NULL, site_id text NOT NULL, binding_id text NOT NULL,
 waf_sid_fingerprint bytea NOT NULL, principal_ref text NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>=0), credential_generation bigint NOT NULL,
 status text NOT NULL CHECK(status IN ('anonymous','active','revoked','expired')),
 expires_at timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,site_id,binding_id),
 UNIQUE(tenant_id,site_id,binding_id,auth_epoch)
);
CREATE INDEX binding_cookie_lookup ON xshield.auth_bindings
 (tenant_id,site_id,waf_sid_fingerprint) WHERE status IN ('active','anonymous');
CREATE TABLE xshield.credential_bindings (
 tenant_id text NOT NULL, site_id text NOT NULL, binding_id text NOT NULL,
 generation bigint NOT NULL, credential_kind text NOT NULL, fingerprint bytea NOT NULL,
 predecessor_generation bigint, expires_at timestamptz NOT NULL,
 status text NOT NULL CHECK(status IN ('active','transition','revoked')),
 PRIMARY KEY(tenant_id,site_id,binding_id,generation,credential_kind),
 FOREIGN KEY(tenant_id,site_id,binding_id)
 REFERENCES xshield.auth_bindings(tenant_id,site_id,binding_id)
);
CREATE INDEX credential_exact_lookup ON xshield.credential_bindings
 (tenant_id,site_id,credential_kind,fingerprint);
-- 资格保留历史epoch以供审计；不对可变auth_epoch做级联更新。
CREATE TABLE xshield.ui_actions (
 tenant_id text NOT NULL, site_id text NOT NULL, action_ref text NOT NULL,
 binding_id text NOT NULL, auth_epoch bigint NOT NULL,
 source_request_id text NOT NULL, page_evidence_id text NOT NULL,
 source_action_ref text, operation_id text NOT NULL,
 target_constraints jsonb NOT NULL, field_profile text NOT NULL,
 source_rule text NOT NULL, policy_revision text NOT NULL,
 status text NOT NULL CHECK(status IN ('active','revoked','expired')),
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,site_id,action_ref),
 FOREIGN KEY(tenant_id,site_id,binding_id)
 REFERENCES xshield.auth_bindings(tenant_id,site_id,binding_id),
 FOREIGN KEY(tenant_id,site_id,policy_revision)
 REFERENCES xshield.policy_revisions(tenant_id,site_id,revision)
);
CREATE INDEX action_eligibility ON xshield.ui_actions
 (tenant_id,site_id,binding_id,auth_epoch,operation_id,expires_at) WHERE status='active';
CREATE TABLE xshield.resource_grants (
 tenant_id text NOT NULL, site_id text NOT NULL, grant_id text NOT NULL,
 binding_id text NOT NULL, auth_epoch bigint NOT NULL, action_ref text NOT NULL,
 resource_type text NOT NULL, resource_key_hmac bytea NOT NULL,
 operation_id text NOT NULL, view_id text NOT NULL, constraints jsonb NOT NULL,
 source_event_id text NOT NULL, issuance_key text NOT NULL,
 policy_revision text NOT NULL, status text NOT NULL,
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,site_id,grant_id),
 UNIQUE(tenant_id,site_id,issuance_key),
 CHECK(status IN ('active','revoked','expired')),
 FOREIGN KEY(tenant_id,site_id,binding_id)
 REFERENCES xshield.auth_bindings(tenant_id,site_id,binding_id),
 FOREIGN KEY(tenant_id,site_id,action_ref)
 REFERENCES xshield.ui_actions(tenant_id,site_id,action_ref)
);
CREATE INDEX grant_exact_lookup ON xshield.resource_grants
 (tenant_id,site_id,binding_id,auth_epoch,resource_type,resource_key_hmac,operation_id,view_id,expires_at)
 WHERE status='active';
CREATE TABLE xshield.service_identities (
 tenant_id text NOT NULL, site_id text NOT NULL, service_id text NOT NULL,
 credential_fingerprint bytea NOT NULL, operation_ids text[] NOT NULL,
 status text NOT NULL CHECK(status IN ('active','revoked','expired')),
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,site_id,service_id),
 CHECK(octet_length(credential_fingerprint)=32),
 CHECK(cardinality(operation_ids) BETWEEN 1 AND 256),
 CHECK(expires_at>issued_at)
);
CREATE UNIQUE INDEX service_identity_active_credential ON xshield.service_identities
 (tenant_id,site_id,credential_fingerprint) WHERE status='active';
CREATE TABLE xshield.share_issuance_rules (
 tenant_id text NOT NULL, site_id text NOT NULL, policy_revision text NOT NULL,
 rule_id text NOT NULL, issuer_operation_id text NOT NULL, issuer_view_id text NOT NULL,
 share_operation_id text NOT NULL, share_view_id text NOT NULL,
 max_ttl_seconds bigint NOT NULL CHECK(max_ttl_seconds BETWEEN 1 AND 86400),
 status text NOT NULL CHECK(status IN ('active','retired')),
 CHECK(issuer_operation_id<>share_operation_id),
 PRIMARY KEY(tenant_id,site_id,policy_revision,rule_id),
 FOREIGN KEY(tenant_id,site_id,policy_revision)
 REFERENCES xshield.policy_revisions(tenant_id,site_id,revision)
);
CREATE TABLE xshield.share_grants (
 tenant_id text NOT NULL, site_id text NOT NULL, share_id text NOT NULL,
 issuer_binding_id text NOT NULL, issuer_auth_epoch bigint,
 issuer_grant_id text, issuance_rule_id text, issuance_key text,
 token_fingerprint bytea NOT NULL,
 resource_type text NOT NULL, resource_key_hmac bytea NOT NULL,
 operation_id text NOT NULL, view_id text NOT NULL,
 use_policy text NOT NULL CHECK(use_policy='reusable_read'),
 source_event_id text NOT NULL, policy_revision text NOT NULL,
 status text NOT NULL CHECK(status IN ('active','revoked','expired')),
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,site_id,share_id),
 CHECK(octet_length(token_fingerprint)=32),
 CHECK(octet_length(resource_key_hmac)=32), CHECK(expires_at>issued_at),
 CHECK((issuer_auth_epoch IS NULL AND issuer_grant_id IS NULL AND issuance_rule_id IS NULL AND issuance_key IS NULL)
    OR (issuer_auth_epoch IS NOT NULL AND issuer_grant_id IS NOT NULL AND issuance_rule_id IS NOT NULL AND issuance_key IS NOT NULL)),
 FOREIGN KEY(tenant_id,site_id,issuer_binding_id)
 REFERENCES xshield.auth_bindings(tenant_id,site_id,binding_id),
 FOREIGN KEY(tenant_id,site_id,issuer_grant_id)
 REFERENCES xshield.resource_grants(tenant_id,site_id,grant_id),
 FOREIGN KEY(tenant_id,site_id,policy_revision,issuance_rule_id)
 REFERENCES xshield.share_issuance_rules(tenant_id,site_id,policy_revision,rule_id),
 FOREIGN KEY(tenant_id,site_id,policy_revision)
 REFERENCES xshield.policy_revisions(tenant_id,site_id,revision)
);
CREATE UNIQUE INDEX share_grant_active_token ON xshield.share_grants
 (tenant_id,site_id,token_fingerprint) WHERE status='active';
CREATE UNIQUE INDEX share_grant_qualified_issuance ON xshield.share_grants
 (tenant_id,site_id,issuance_key) WHERE issuance_key IS NOT NULL;
CREATE INDEX share_grant_exact_lookup ON xshield.share_grants
 (tenant_id,site_id,token_fingerprint,resource_type,resource_key_hmac,operation_id,view_id,expires_at)
 WHERE status='active';
CREATE INDEX share_grant_issuer_capacity ON xshield.share_grants
 (tenant_id,site_id,issuer_binding_id,issuer_auth_epoch,expires_at)
 WHERE status='active' AND issuer_auth_epoch IS NOT NULL;
-- 与认证/资格事务一起写入；传输可至少一次，消费者按event_id去重。
CREATE TABLE xshield.audit_outbox (
 event_id text PRIMARY KEY, tenant_id text NOT NULL, site_id text NOT NULL,
 aggregate_ref text NOT NULL, event_type text NOT NULL, envelope jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz,
 lease_until timestamptz, delivery_attempts integer NOT NULL DEFAULT 0
);
CREATE INDEX outbox_pending ON xshield.audit_outbox(created_at,event_id)
 WHERE published_at IS NULL;
CREATE TABLE xshield.artifact_catalog (
 tenant_id text NOT NULL, site_id text NOT NULL, artifact_id text NOT NULL,
 request_id text, manifest jsonb NOT NULL, classification text NOT NULL,
 capture_status text NOT NULL, fidelity text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
 legal_hold boolean NOT NULL DEFAULT false, deleted_at timestamptz,
 PRIMARY KEY(tenant_id,site_id,artifact_id)
);
CREATE INDEX artifact_request_lookup ON xshield.artifact_catalog
 (tenant_id,site_id,request_id,created_at);
CREATE TABLE xshield.investigation_cases (
 tenant_id text NOT NULL, case_id text NOT NULL, owner_ref text NOT NULL,
 status text NOT NULL, purpose text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,case_id)
);
CREATE TABLE xshield.case_items (
 tenant_id text NOT NULL, case_id text NOT NULL, site_id text NOT NULL,
 artifact_id text NOT NULL, added_by text NOT NULL, added_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,case_id,site_id,artifact_id),
 FOREIGN KEY(tenant_id,case_id) REFERENCES xshield.investigation_cases(tenant_id,case_id),
 FOREIGN KEY(tenant_id,site_id,artifact_id)
 REFERENCES xshield.artifact_catalog(tenant_id,site_id,artifact_id)
);
COMMIT;
-- 发行资格用例（应用事务逻辑，不是单靠这些表获得正确性）：
-- 1. SELECT ... FROM auth_bindings WHERE tenant/site/binding 匹配 FOR UPDATE;
-- 2. 核对原请求epoch、status、expires_at、批准的action及来源。
-- 3. INSERT resource_grants，以issuance_key去重；同事务INSERT audit_outbox。
-- 4. COMMIT成功后才向客户端释放支撑下一步访问的数据。
-- 5. 发布器重发同event_id；不可把日志索引成功当作事务提交前提。
-- 重要：这只能约束WAF状态，不能与源站数据库副作用形成跨系统原子事务。
