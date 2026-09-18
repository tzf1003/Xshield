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
 authorization_context_ref text NOT NULL,
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
 request_id text NOT NULL, schema_version smallint NOT NULL CHECK(schema_version=3),
 kind text NOT NULL, content_type text NOT NULL,
 classification text NOT NULL CHECK(classification IN ('INTERNAL','SENSITIVE','RESTRICTED')),
 capture_status text NOT NULL CHECK(capture_status='complete'),
 fidelity text NOT NULL CHECK(fidelity IN ('entity_exact','semantic','redacted')),
 bytes_observed bigint NOT NULL CHECK(bytes_observed BETWEEN 0 AND 67108864),
 bytes_saved bigint NOT NULL CHECK(bytes_saved=bytes_observed),
 example_only boolean NOT NULL CHECK(NOT example_only),
 storage_profile text NOT NULL CHECK(storage_profile='aead_envelope_v1'),
 storage_locator text NOT NULL, key_ref text NOT NULL,
 integrity_algorithm text NOT NULL CHECK(integrity_algorithm='sha256_ciphertext'),
 integrity_digest text NOT NULL, parent_refs text[] NOT NULL,
 recorded_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 catalog_event_id text NOT NULL UNIQUE,
 status text NOT NULL CHECK(status IN ('active','deleted')), deleted_at timestamptz,
 CHECK(storage_locator=artifact_id||'.xev'), CHECK(expires_at>recorded_at),
 CHECK((status='active' AND deleted_at IS NULL) OR (status='deleted' AND deleted_at IS NOT NULL)),
 PRIMARY KEY(tenant_id,site_id,artifact_id)
);
CREATE INDEX artifact_request_lookup ON xshield.artifact_catalog
 (tenant_id,site_id,request_id,recorded_at,artifact_id)
 WHERE status='active' AND deleted_at IS NULL;
CREATE INDEX artifact_request_page ON xshield.artifact_catalog
 (tenant_id,site_id,request_id,artifact_id)
 WHERE status='active' AND deleted_at IS NULL;
CREATE TABLE xshield.investigation_cases (
 tenant_id text NOT NULL CHECK(tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
 site_id text NOT NULL CHECK(site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
 case_id text NOT NULL CHECK(case_id ~ '^case_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 owner_ref text NOT NULL CHECK(octet_length(owner_ref) BETWEEN 1 AND 256 AND owner_ref !~ '[[:cntrl:]]'),
 purpose text NOT NULL CHECK(octet_length(purpose) BETWEEN 1 AND 512 AND purpose !~ '[[:cntrl:]]' AND purpose=btrim(purpose)),
 status text NOT NULL CHECK(status IN ('open','closed')),
 idempotency_digest bytea NOT NULL CHECK(octet_length(idempotency_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 created_event_id text NOT NULL UNIQUE CHECK(created_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,site_id,case_id),
 UNIQUE(tenant_id,site_id,owner_ref,idempotency_digest)
);
CREATE INDEX investigation_case_open_lookup ON xshield.investigation_cases
 (tenant_id,site_id,owner_ref,created_at,case_id) WHERE status='open';
CREATE TABLE xshield.case_items (
 tenant_id text NOT NULL, case_id text NOT NULL, site_id text NOT NULL,
 artifact_id text NOT NULL, added_by text NOT NULL, added_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,case_id,site_id,artifact_id),
 FOREIGN KEY(tenant_id,site_id,case_id)
 REFERENCES xshield.investigation_cases(tenant_id,site_id,case_id),
 FOREIGN KEY(tenant_id,site_id,artifact_id)
 REFERENCES xshield.artifact_catalog(tenant_id,site_id,artifact_id)
);
CREATE TABLE xshield.evidence_access_requests (
 tenant_id text NOT NULL, site_id text NOT NULL,
 access_request_id text NOT NULL CHECK(access_request_id ~ '^access_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 case_id text NOT NULL, artifact_id text NOT NULL,
 requested_by text NOT NULL CHECK(octet_length(requested_by) BETWEEN 1 AND 256 AND requested_by !~ '[[:cntrl:]]'),
 access_kind text NOT NULL CHECK(access_kind='sensitive_raw'),
 justification text NOT NULL CHECK(octet_length(justification) BETWEEN 1 AND 512 AND justification !~ '[[:cntrl:]]' AND justification=btrim(justification)),
 status text NOT NULL CHECK(status IN ('pending','approved','denied','expired','revoked')),
 idempotency_digest bytea NOT NULL CHECK(octet_length(idempotency_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 requested_event_id text NOT NULL UNIQUE CHECK(requested_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 decided_by text CHECK(decided_by IS NULL OR (octet_length(decided_by) BETWEEN 1 AND 256 AND decided_by !~ '[[:cntrl:]]')),
 decision_reason text CHECK(decision_reason IS NULL OR (octet_length(decision_reason) BETWEEN 1 AND 512 AND decision_reason !~ '[[:cntrl:]]' AND decision_reason=btrim(decision_reason))),
 decision_ttl_seconds integer CHECK(decision_ttl_seconds IS NULL OR decision_ttl_seconds>0),
 decision_idempotency_digest bytea CHECK(decision_idempotency_digest IS NULL OR octet_length(decision_idempotency_digest)=32),
 decision_request_digest bytea CHECK(decision_request_digest IS NULL OR octet_length(decision_request_digest)=32),
 decision_event_id text CHECK(decision_event_id IS NULL OR decision_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 decided_at timestamptz,
 access_expires_at timestamptz,
 PRIMARY KEY(tenant_id,site_id,access_request_id),
 UNIQUE(tenant_id,site_id,requested_by,idempotency_digest),
 FOREIGN KEY(tenant_id,site_id,case_id)
 REFERENCES xshield.investigation_cases(tenant_id,site_id,case_id),
 FOREIGN KEY(tenant_id,site_id,artifact_id)
 REFERENCES xshield.artifact_catalog(tenant_id,site_id,artifact_id),
 CHECK(
  (status='pending' AND decided_by IS NULL AND decision_reason IS NULL AND decision_ttl_seconds IS NULL AND decision_idempotency_digest IS NULL AND decision_request_digest IS NULL AND decision_event_id IS NULL AND decided_at IS NULL AND access_expires_at IS NULL)
  OR (status='denied' AND decided_by IS NOT NULL AND decided_by<>requested_by AND decision_reason IS NOT NULL AND decision_ttl_seconds IS NULL AND decision_idempotency_digest IS NOT NULL AND decision_request_digest IS NOT NULL AND decision_event_id IS NOT NULL AND decided_at IS NOT NULL AND access_expires_at IS NULL)
  OR (status IN ('approved','expired','revoked') AND decided_by IS NOT NULL AND decided_by<>requested_by AND decision_reason IS NOT NULL AND decision_ttl_seconds IS NOT NULL AND decision_idempotency_digest IS NOT NULL AND decision_request_digest IS NOT NULL AND decision_event_id IS NOT NULL AND decided_at IS NOT NULL AND access_expires_at>decided_at)
 )
);
CREATE INDEX evidence_access_pending_lookup ON xshield.evidence_access_requests
 (tenant_id,site_id,requested_by,requested_at,access_request_id)
 WHERE status='pending';
CREATE UNIQUE INDEX evidence_access_decision_idempotency ON xshield.evidence_access_requests
 (tenant_id,site_id,decided_by,decision_idempotency_digest)
 WHERE decision_idempotency_digest IS NOT NULL;
CREATE UNIQUE INDEX evidence_access_decision_event ON xshield.evidence_access_requests(decision_event_id)
 WHERE decision_event_id IS NOT NULL;
CREATE INDEX evidence_access_capability_lookup ON xshield.evidence_access_requests
 (tenant_id,site_id,requested_by,access_request_id,access_expires_at)
 WHERE status='approved';
COMMIT;
-- 发行资格用例（应用事务逻辑，不是单靠这些表获得正确性）：
-- 1. SELECT ... FROM auth_bindings WHERE tenant/site/binding 匹配 FOR UPDATE;
-- 2. 核对原请求epoch、status、expires_at、批准的action及来源。
-- 3. INSERT resource_grants，以issuance_key去重；同事务INSERT audit_outbox。
-- 4. COMMIT成功后才向客户端释放支撑下一步访问的数据。
-- 5. 发布器重发同event_id；不可把日志索引成功当作事务提交前提。
-- 重要：这只能约束WAF状态，不能与源站数据库副作用形成跨系统原子事务。
