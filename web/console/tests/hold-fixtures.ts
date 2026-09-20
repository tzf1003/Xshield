/** Synthetic retention metadata; no credentials or object storage locators. */
import type { HoldRecord, HoldMutation, HoldCollection } from "../src/evidence-holds.ts";
import { ARTIFACT_ID } from "./fixtures.ts";
export const HOLD_ID = "ev_018f2a3b-4c5d-7000-8000-000000000061";
export const HOLD_CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
export const HOLD_KEY = "synthetic-hold-operation-key-0001";
export const HOLD_UNTIL = "2026-09-25T08:00:00.000Z";
const base = { request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo", site_id: "site_demo" };
export function holdRecordFixture(released = false): HoldRecord {
  return { hold_id: HOLD_ID, case_id: HOLD_CASE_ID, artifact_id: ARTIFACT_ID,
    created_by: "synthetic-audit-administrator", reason: "保留调查证据",
    created_at: "2026-09-20T08:00:00.000Z", hold_until: HOLD_UNTIL,
    released_event_id: released ? "ev_018f2a3b-4c5d-7000-8000-000000000062" : null,
    released_by: released ? "synthetic-audit-administrator" : null,
    released_reason: released ? "调查已完成" : null,
    released_at: released ? "2026-09-20T08:01:00.000Z" : null };
}
export function holdMutationFixture(released = false, replayed = false): HoldMutation {
  return { ...base, schema_version: 3, ...holdRecordFixture(released), replayed };
}
export function holdCollectionFixture(): HoldCollection {
  return { ...base, schema_version: 3, case_id: HOLD_CASE_ID, case_status: "open",
    as_of: "2026-09-20T08:02:00.000000Z", items: [holdRecordFixture()],
    truncated: false, next_cursor: null };
}
