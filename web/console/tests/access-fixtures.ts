/** Synthetic contract fixtures for access workflow and binary transport tests. */
import type {
  AccessRequested,
  AccessInspection,
  AccessDecision,
  AccessStatus,
  AccessList,
  AccessListView,
} from "../src/evidence-access.ts";
import { ARTIFACT_ID } from "./fixtures.ts";

export const ACCESS_ID = "access_018f2a3b-4c5d-7000-8000-000000000041";
export const ACCESS_CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
export const ACCESS_KEY = "synthetic-access-operation-key-0001";
const base = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};
export function accessListFixture(view: AccessListView = "mine"): AccessList {
  const detail = accessInspectionFixture().access_request;
  return {
    ...base,
    schema_version: 3,
    view,
    as_of: "2026-09-20T08:01:00.000000Z",
    items: [
      {
        access_request_id: detail.access_request_id,
        case_id: detail.case_id,
        artifact_id: detail.artifact_id,
        requested_by: detail.requested_by,
        access_kind: detail.access_kind,
        stored_status: detail.stored_status,
        requested_at: detail.requested_at,
        requested_event_id: detail.requested_event_id,
      },
    ],
    truncated: false,
    next_cursor: null,
  };
}
export function accessRequestedFixture(): AccessRequested {
  return {
    ...base,
    access_request_id: ACCESS_ID,
    case_id: ACCESS_CASE_ID,
    artifact_id: ARTIFACT_ID,
    access_kind: "sensitive_raw",
    status: "pending",
    requested_at: "2026-09-20T08:00:00.000Z",
    replayed: false,
  };
}
export function accessDecisionFixture(
  decision: AccessDecision["status"] = "approved",
  replayed = false,
): AccessDecision {
  return {
    ...base,
    access_request_id: ACCESS_ID,
    case_id: ACCESS_CASE_ID,
    artifact_id: ARTIFACT_ID,
    requested_by: "synthetic-investigator",
    decided_by: "synthetic-approver",
    status: decision,
    decided_at: "2026-09-20T08:00:01.000Z",
    access_expires_at: decision === "denied" ? null : "2026-09-20T08:10:01.000Z",
    replayed,
  };
}
export function accessInspectionFixture(status: AccessStatus = "pending"): AccessInspection {
  const pending = status === "pending";
  const approved = !pending && status !== "denied";
  return {
    ...base,
    schema_version: 3,
    as_of: "2026-09-20T08:01:00.000000Z",
    max_approval_ttl_seconds: 3600,
    access_request: {
      access_request_id: ACCESS_ID,
      case_id: ACCESS_CASE_ID,
      artifact_id: ARTIFACT_ID,
      requested_by: "synthetic-investigator",
      access_kind: "sensitive_raw",
      justification: "核查证据内容",
      stored_status: status,
      requested_at: "2026-09-20T08:00:00.000000Z",
      requested_event_id: "ev_018f2a3b-4c5d-7000-8000-000000000051",
      decided_by: pending ? null : "synthetic-approver",
      decision_reason: pending ? null : "已核对案件用途",
      decision_ttl_seconds: approved ? 600 : null,
      decision_event_id: pending ? null : "ev_018f2a3b-4c5d-7000-8000-000000000052",
      decided_at: pending ? null : "2026-09-20T08:00:01.000000Z",
      access_expires_at: approved ? "2026-09-20T08:10:01.000000Z" : null,
      case_status: "open",
      artifact_status: "active",
      artifact_expires_at: "2026-09-21T08:00:00.000000Z",
      artifact_time_expired: false,
      capability_time_expired: approved ? false : null,
    },
  };
}
export function downloadHeaders(bytes = 3): Record<string, string> {
  return {
    "Content-Type": "application/octet-stream",
    "Content-Length": String(bytes),
    "Content-Disposition": 'attachment; filename="evidence.bin"',
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Xshield-Request-Id": base.request_id,
    "X-Xshield-Tenant-Id": base.tenant_id,
    "X-Xshield-Site-Id": base.site_id,
    "X-Xshield-Artifact-Id": ARTIFACT_ID,
    "X-Xshield-Evidence-Access-Request": ACCESS_ID,
  };
}
