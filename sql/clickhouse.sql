-- Xshield v3 分析索引。MergeTree主键不唯一；发布器执行摘要冲突检查，
-- 查询仍须按event_id去重，并监控audit_event_conflicts应始终为空。
-- ClickHouse不是资格账本/认证真值。TTL后台执行，不承诺即时删除。
CREATE DATABASE IF NOT EXISTS xshield;
CREATE TABLE IF NOT EXISTS xshield.audit_events (
 tenant_id String, site_id String,
 request_id String, trace_id FixedString(32),
 event_id String, event_type LowCardinality(String),
 stage LowCardinality(String), outcome LowCardinality(String),
 reason_code LowCardinality(String), proof_kind LowCardinality(String),
 confidence Nullable(Float64), confidence_status LowCardinality(String),
 occurred_at DateTime64(6,'UTC'), observed_at DateTime64(6,'UTC'),
 producer_id String, producer_boot_id String, producer_seq UInt64,
 request_seq UInt32, duration_us UInt64,
 policy_revision String, model_revision String,
 evidence_refs Array(String), cause_event_ids Array(String),
 sensitivity LowCardinality(String), payload_json String,
 event_hash String, content_digest FixedString(64), ingest_revision UInt64
) ENGINE=MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id,site_id,request_id,request_seq,event_id)
TTL occurred_at + INTERVAL 30 DAY DELETE;
-- 热门按时间/原因分析的第二物理排序。生产大流量需评估存储放大，非强制双写。
CREATE TABLE IF NOT EXISTS xshield.events_by_time AS xshield.audit_events
ENGINE=MergeTree PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id,site_id,toDate(occurred_at),reason_code,occurred_at,event_id)
TTL occurred_at + INTERVAL 30 DAY DELETE;
CREATE MATERIALIZED VIEW IF NOT EXISTS xshield.mv_events_by_time
TO xshield.events_by_time AS SELECT * FROM xshield.audit_events;
-- 同一event_id出现不同正文即审计完整性事故；物理重复但摘要相同不进入此视图。
CREATE VIEW IF NOT EXISTS xshield.audit_event_conflicts AS
SELECT event_id, groupUniqArray(content_digest) AS content_digests, count() AS deliveries
FROM xshield.audit_events
GROUP BY event_id
HAVING uniqExact(content_digest) > 1;
-- 实际查询API必须加入授权的tenant/site，参数绑定，行数/时间/字节上限。
-- 聚合必须采用已去重视图或由消费者保证逻辑幂等，不直接把重复行COUNT作请求数。
-- 例：单请求按阶段顺序读取，exact-result层仍以event_id去重。
-- SELECT * FROM xshield.audit_events
-- WHERE tenant_id={tenant:String} AND site_id={site:String}
--   AND request_id={request_id:String}
-- ORDER BY request_seq,event_id LIMIT 10000;
-- 例：时间范围原因码计数（uniqExact按event_id避免重复投递放大）。
-- SELECT reason_code, uniqExact(event_id) AS events
-- FROM xshield.events_by_time
-- WHERE tenant_id={tenant:String} AND site_id={site:String}
--   AND occurred_at>={start:DateTime64(6)} AND occurred_at<{end:DateTime64(6)}
-- GROUP BY reason_code ORDER BY events DESC LIMIT 100;
