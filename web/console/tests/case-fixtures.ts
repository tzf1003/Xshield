/** Synthetic case observations; no production identities, evidence or secrets. */
import type {
  CaseCollection,
  CaseCreated,
  CaseItemAdded,
  CaseClosed,
} from "../src/cases";
import { ARTIFACT_ID, OTHER_ARTIFACT_ID } from "./fixtures";

export const CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000031";
export const OTHER_CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000032";
export const CASE_KEY = "synthetic-case-operation-key-0001";
export const CASE_PURPOSE = "核对合成请求的证据引用";
export const CASE_CURSOR = `v1.${ARTIFACT_ID}.${"a".repeat(64)}`;
const envelope = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};
export function caseCreatedFixture(
  purpose = CASE_PURPOSE,
  replayed = false,
): CaseCreated {
  return {
    ...envelope,
    case_id: CASE_ID,
    status: "open",
    purpose,
    created_at: "2026-09-20T08:00:00.000Z",
    replayed,
  };
}
export function caseCollectionFixture(caseId = CASE_ID): CaseCollection {
  const {
    request_id: _request,
    tenant_id: _tenant,
    site_id: _site,
    replayed: _replayed,
    ...facts
  } = caseCreatedFixture();
  return {
    ...envelope,
    schema_version: 3,
    case: { ...facts, case_id: caseId },
    as_of: "2026-09-20T08:10:30.123456Z",
    items: [],
    truncated: false,
    next_cursor: null,
  };
}
export function caseItemAddedFixture(
  artifact = ARTIFACT_ID,
  replayed = false,
): CaseItemAdded {
  return {
    ...envelope,
    schema_version: 3,
    case_id: CASE_ID,
    artifact_id: artifact,
    added_by: "synthetic_investigator",
    added_at: "2026-09-20T08:05:00.000Z",
    replayed,
  };
}
export function caseClosedFixture(replayed = false): CaseClosed {
  return {
    ...envelope,
    schema_version: 3,
    case_id: CASE_ID,
    status: "closed",
    closed_at: "2026-09-20T08:20:00.000Z",
    replayed,
  };
}
export function caseItemFixture(
  status: "active" | "expired" | "deleted" | "unavailable" = "active",
  artifact = OTHER_ARTIFACT_ID,
) {
  return {
    artifact_id: artifact,
    added_by: "synthetic_investigator",
    added_at: "2026-09-20T08:05:00.000Z",
    catalog_status: status,
  };
}
