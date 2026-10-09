/**
 * Query keys and read specs for the case and approval pages. Every read is audited by the
 * server, so each spec is `MANUAL_REFRESH`: it loads when its view opens and again only when the
 * operator asks (or after the operator's own confirmed write). The session epoch is prefixed by
 * the guarded-query layer; the cursor is part of the key, so a page is never mistaken for another.
 */
import type { ArtifactResponse, JobResponse, SiteListResponse } from "../api.ts";
import type { CaseCollection, CaseList } from "../cases.ts";
import type { AccessInspection, AccessList, AccessListView } from "../evidence-access.ts";
import type { HoldCollection } from "../evidence-holds.ts";
import type { ExportList, ExportListView, InvestigationExport } from "../exports.ts";
import type { GuardedQuerySpec } from "../security/guarded-query.ts";
import { MANUAL_REFRESH } from "../security/query-client.ts";

export const keys = {
  caseList: (cursor?: string) => ["cases", "list", cursor ?? ""] as const,
  caseItems: (caseId: string, cursor?: string) => ["cases", "items", caseId, cursor ?? ""] as const,
  holds: (caseId: string, cursor?: string) => ["cases", "holds", caseId, cursor ?? ""] as const,
  job: (jobId: string) => ["cases", "job", jobId] as const,
  artifact: (artifactId: string) => ["cases", "artifact", artifactId] as const,
  accessList: (view: AccessListView, cursor?: string) =>
    ["evidence", "access-list", view, cursor ?? ""] as const,
  accessDetail: (accessId: string) => ["evidence", "access", accessId] as const,
  exportList: (view: ExportListView, cursor?: string) =>
    ["evidence", "export-list", view, cursor ?? ""] as const,
  exportDetail: (exportId: string) => ["evidence", "export", exportId] as const,
  siteApprovals: () => ["sites", "approvals"] as const,
};

/** Key prefixes, for invalidating everything a write may have changed. */
export const domains = {
  cases: ["cases"] as const,
  evidence: ["evidence"] as const,
  holds: ["cases", "holds"] as const,
  caseItems: ["cases", "items"] as const,
  accessLists: ["evidence", "access-list"] as const,
  exportLists: ["evidence", "export-list"] as const,
};

export const specs = {
  caseList: (cursor?: string): GuardedQuerySpec<CaseList> => ({
    key: keys.caseList(cursor),
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.cases(cursor, signal),
  }),
  caseItems: (
    caseId: string,
    cursor?: string,
    enabled = true,
  ): GuardedQuerySpec<CaseCollection> => ({
    key: keys.caseItems(caseId, cursor),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.caseItems(caseId, cursor, signal),
  }),
  holds: (caseId: string, cursor?: string, enabled = true): GuardedQuerySpec<HoldCollection> => ({
    key: keys.holds(caseId, cursor),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.evidenceHolds(caseId, cursor, signal),
  }),
  job: (jobId: string, enabled = true): GuardedQuerySpec<JobResponse> => ({
    key: keys.job(jobId),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.job(jobId, signal),
  }),
  artifact: (artifactId: string, enabled = true): GuardedQuerySpec<ArtifactResponse> => ({
    key: keys.artifact(artifactId),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.artifact(artifactId, signal),
  }),
  accessList: (
    view: AccessListView,
    cursor?: string,
    enabled = true,
  ): GuardedQuerySpec<AccessList> => ({
    key: keys.accessList(view, cursor),
    staleTime: MANUAL_REFRESH,
    enabled,
    oneAtATime: true,
    fetch: (client, signal) => client.evidenceAccessList(view, cursor, signal),
  }),
  accessDetail: (accessId: string, enabled = true): GuardedQuerySpec<AccessInspection> => ({
    key: keys.accessDetail(accessId),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.evidenceAccess(accessId, signal),
  }),
  exportList: (
    view: ExportListView,
    cursor?: string,
    enabled = true,
  ): GuardedQuerySpec<ExportList> => ({
    key: keys.exportList(view, cursor),
    staleTime: MANUAL_REFRESH,
    enabled,
    oneAtATime: true,
    fetch: (client, signal) => client.exportList(view, cursor, signal),
  }),
  exportDetail: (exportId: string, enabled = true): GuardedQuerySpec<InvestigationExport> => ({
    key: keys.exportDetail(exportId),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.exportStatus(exportId, signal),
  }),
  /** The first page of the site list, read only to find revisions that await a decision. */
  siteApprovals: (enabled = true): GuardedQuerySpec<SiteListResponse> => ({
    key: keys.siteApprovals(),
    staleTime: MANUAL_REFRESH,
    enabled,
    fetch: (client, signal) => client.siteList(signal),
  }),
};
