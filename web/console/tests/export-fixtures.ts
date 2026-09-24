import type { InvestigationExport } from "../src/exports.ts";

export const EXPORT_ID = "export_018f2a3b-4c5d-7000-8000-000000000071";
export const EXPORT_CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
export const EXPORT_KEY = "synthetic-export-operation-key-0001";
export const EXPORT_ARTIFACT_ID = "artifact_018f2a3b-4c5d-7000-8000-000000000072";
const envelope = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};

export function exportFixture(
  status: InvestigationExport["status"] = "pending_approval",
  replayed = false,
): InvestigationExport {
  const decided = status !== "pending_approval";
  const ready = status === "ready";
  return {
    ...envelope,
    export_id: EXPORT_ID,
    case_id: EXPORT_CASE_ID,
    requested_by: "synthetic-investigator",
    purpose: "核对案件元数据",
    kind: "metadata_only",
    status,
    decided_by: decided ? "synthetic-approver" : null,
    decided_at: decided ? "2026-09-20T08:10:00.000Z" : null,
    decision_reason: decided ? "独立复核通过" : null,
    expires_at: ["approved", "ready"].includes(status)
      ? "2026-09-20T08:25:00.000Z"
      : null,
    package_artifact_id: ready ? EXPORT_ARTIFACT_ID : null,
    package_request_id: ready ? envelope.request_id : null,
    package_digest: ready ? "a".repeat(64) : null,
    package_bytes: ready ? 17 : null,
    download_count: 0,
    created_at: "2026-09-20T08:00:00.000Z",
    updated_at: "2026-09-20T08:10:00.000Z",
    replayed,
  };
}

export function exportDownloadHeaders(bytes = 17): Record<string, string> {
  return {
    "X-Xshield-Request-Id": envelope.request_id,
    "X-Xshield-Tenant-Id": envelope.tenant_id,
    "X-Xshield-Site-Id": envelope.site_id,
    "X-Xshield-Export-Id": EXPORT_ID,
    "X-Xshield-Package-Artifact-Id": EXPORT_ARTIFACT_ID,
    "Content-Length": String(bytes),
    "Content-Type": "application/json",
    "Content-Disposition": 'attachment; filename="investigation-export.json"',
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, no-store",
  };
}
