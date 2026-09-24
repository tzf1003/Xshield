-- Xshield v3 分析索引。MergeTree主键不唯一；发布器执行摘要冲突检查，
-- 查询仍须按event_id去重，并监控audit_event_conflicts应始终为空。
-- ClickHouse不是资格账本/认证真值。TTL后台执行，不承诺即时删除。
CREATE DATABASE IF NOT EXISTS xshield;
-- ClickHouse 24.x accepts DateTime/Date TTL expressions. Keep the stored
-- deadline at microsecond precision for active views and cast only for the
-- asynchronous physical cleanup pass.
CREATE TABLE IF NOT EXISTS xshield.audit_events (
 tenant_id String, site_id String,
 request_id String, trace_id FixedString(32),
 event_id String, event_type LowCardinality(String),
 stage LowCardinality(String), outcome LowCardinality(String),
 reason_code LowCardinality(String), proof_kind LowCardinality(String),
 confidence Nullable(Float64), confidence_status LowCardinality(String),
 occurred_at DateTime64(6,'UTC'), observed_at DateTime64(6,'UTC'),
 retention_expires_at DateTime64(6,'UTC'),
 producer_id String, producer_boot_id String, producer_seq UInt64,
 request_seq UInt32, method String, operation_id String,
 origin_state LowCardinality(String), http_status Nullable(UInt16),
 is_terminal UInt8, duration_us UInt64,
 policy_revision String, model_revision String, model_call_id String,
 evidence_refs Array(String), cause_event_ids Array(String),
 sensitivity LowCardinality(String), payload_json String,
 event_hash String, content_digest FixedString(64), ingest_revision UInt64
) ENGINE=MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id,site_id,request_id,request_seq,event_id)
TTL toDateTime(retention_expires_at) DELETE;
-- 热门按时间/原因分析的第二物理排序。生产大流量需评估存储放大，非强制双写。
CREATE TABLE IF NOT EXISTS xshield.events_by_time AS xshield.audit_events
ENGINE=MergeTree PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id,site_id,toDate(occurred_at),reason_code,occurred_at,event_id)
TTL toDateTime(retention_expires_at) DELETE;
-- Expand-contract migration for an existing fixed-30-day index. Upgrade the
-- materialized-view target before its source so inserts remain compatible.
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS
 retention_expires_at DateTime64(6,'UTC') DEFAULT occurred_at + INTERVAL 30 DAY
 AFTER observed_at;
ALTER TABLE xshield.events_by_time MODIFY TTL toDateTime(retention_expires_at) DELETE;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS
 retention_expires_at DateTime64(6,'UTC') DEFAULT occurred_at + INTERVAL 30 DAY
 AFTER observed_at;
ALTER TABLE xshield.audit_events MODIFY TTL toDateTime(retention_expires_at) DELETE;
-- Expand redacted request facts before deploying a publisher that emits them.
-- Upgrade the materialized-view target first so SELECT * remains insertable.
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS method String DEFAULT '' AFTER request_seq;
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS operation_id String DEFAULT '' AFTER method;
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS origin_state LowCardinality(String) DEFAULT '' AFTER operation_id;
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS http_status Nullable(UInt16) DEFAULT NULL AFTER origin_state;
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS is_terminal UInt8 DEFAULT 0 AFTER http_status;
ALTER TABLE xshield.events_by_time ADD COLUMN IF NOT EXISTS model_call_id String DEFAULT '' AFTER model_revision;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS method String DEFAULT '' AFTER request_seq;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS operation_id String DEFAULT '' AFTER method;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS origin_state LowCardinality(String) DEFAULT '' AFTER operation_id;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS http_status Nullable(UInt16) DEFAULT NULL AFTER origin_state;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS is_terminal UInt8 DEFAULT 0 AFTER http_status;
ALTER TABLE xshield.audit_events ADD COLUMN IF NOT EXISTS model_call_id String DEFAULT '' AFTER model_revision;
CREATE MATERIALIZED VIEW IF NOT EXISTS xshield.mv_events_by_time
TO xshield.events_by_time AS SELECT * FROM xshield.audit_events;
ALTER TABLE xshield.mv_events_by_time MODIFY QUERY
SELECT * FROM xshield.audit_events;
-- APIs query these views so retries collapse by event_id and an expired row is
-- hidden before asynchronous TTL merges physically remove it. The earliest
-- deadline wins, so replay after a policy change cannot extend visibility.
-- Ordinary views use CREATE OR REPLACE for repeatable definition upgrades.
-- The deployment identity retains source SELECT; readers receive only view SELECT.
CREATE OR REPLACE VIEW xshield.audit_events_active
DEFINER = CURRENT_USER SQL SECURITY DEFINER AS
SELECT * FROM (
 SELECT * FROM xshield.audit_events
 ORDER BY retention_expires_at,event_id LIMIT 1 BY event_id
) WHERE retention_expires_at > now64(6);
CREATE OR REPLACE VIEW xshield.events_by_time_active
DEFINER = CURRENT_USER SQL SECURITY DEFINER AS
SELECT * FROM (
 SELECT * FROM xshield.events_by_time
 ORDER BY retention_expires_at,event_id LIMIT 1 BY event_id
) WHERE retention_expires_at > now64(6);
-- 同一event_id出现不同正文即审计完整性事故；物理重复但摘要相同不进入此视图。
CREATE VIEW IF NOT EXISTS xshield.audit_event_conflicts AS
SELECT event_id, groupUniqArray(content_digest) AS content_digests, count() AS deliveries
FROM xshield.audit_events
GROUP BY event_id
HAVING uniqExact(content_digest) > 1;
-- 实际查询API必须加入授权的tenant/site，参数绑定，行数/时间/字节上限。
-- 聚合必须采用已去重视图或由消费者保证逻辑幂等，不直接把重复行COUNT作请求数。
-- 例：单请求按阶段顺序读取，exact-result层仍以event_id去重。
-- SELECT * FROM xshield.audit_events_active
-- WHERE tenant_id={tenant:String} AND site_id={site:String}
--   AND request_id={request_id:String}
-- ORDER BY request_seq,event_id LIMIT 10000;
-- 例：时间范围原因码计数（uniqExact按event_id避免重复投递放大）。
-- SELECT reason_code, uniqExact(event_id) AS events
-- FROM xshield.events_by_time_active
-- WHERE tenant_id={tenant:String} AND site_id={site:String}
--   AND occurred_at>={start:DateTime64(6)} AND occurred_at<{end:DateTime64(6)}
-- GROUP BY reason_code ORDER BY events DESC LIMIT 100;
