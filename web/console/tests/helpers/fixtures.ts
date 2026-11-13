// Typed access to the JSON samples in tests/fixtures. Each file is the wire shape of one endpoint
// (src/api/types.ts). The Rust side round-trips the same files (docs/07 7.10.8), and the Playwright
// specs serve them through mock-api.ts. This module imports nothing but JSON and types, so unit
// tests can load it under plain node.
//
// A sample is annotated with its type wherever TypeScript can match the two, so a renamed field fails
// tsc. A JSON import widens literal types (`"ok"` reads as `string`) and tuples (`[string, number]`
// reads as an array), so the other samples go through wire<T>(), the one cast in this module. The
// samples are written from typed objects, which check every field name and enum value against
// types.ts when the files are made.

import type {
  BootstrapResponse,
  Evidence,
  ImpactPreview,
  ObjectSlotDetail,
  ObjectsResponse,
  Insights,
  JevPrompt,
  JevStats,
  JevStatus,
  LookupResponse,
  ModelsState,
  ModelVersionWire,
  RequestCounts,
  RequestDetail,
  RequestListResponse,
  SessionListResponse,
  SessionState,
  SessionTimeline,
  SiteDetail,
  SiteFunctions,
  SiteListResponse,
  SiteVersionsResponse,
  StatsSummary,
  StatusResponse,
  SystemInfo,
  Timeseries,
} from "../../src/api/types.ts";
import countsJson from "../fixtures/counts.json" with { type: "json" };
import evidenceJson from "../fixtures/evidence.json" with { type: "json" };
import functionsJson from "../fixtures/functions.json" with { type: "json" };
import insightsJson from "../fixtures/insights.json" with { type: "json" };
import jevStatsJson from "../fixtures/jev-stats.json" with { type: "json" };
import jevStatusJson from "../fixtures/jev-status.json" with { type: "json" };
import lookupJson from "../fixtures/lookup.json" with { type: "json" };
import modelHistoryJson from "../fixtures/model-history.json" with { type: "json" };
import previewJson from "../fixtures/preview.json" with { type: "json" };
import promptJson from "../fixtures/prompt.json" with { type: "json" };
import requestDetailBasketJson from "../fixtures/request-detail-req_01a1973940107ebea1af2c54ce635f38.json" with {
  type: "json",
};
import requestDetailLoginJson from "../fixtures/request-detail-req_01a1971a07e079639a823d4257b43172.json" with {
  type: "json",
};
import requestDetailSearchJson from "../fixtures/request-detail-req_01a1973ed5c0732b8f29804d7fc746d3.json" with {
  type: "json",
};
import requestDetailFunctionJson from "../fixtures/request-detail-req_c0ffee00c0ffee00c0ffee00c0ffee00.json" with {
  type: "json",
};
import requestsJson from "../fixtures/requests.json" with { type: "json" };
import sessionTimelineJson from "../fixtures/session-timeline.json" with { type: "json" };
import sessionJson from "../fixtures/session.json" with { type: "json" };
import sessionsJson from "../fixtures/sessions.json" with { type: "json" };
import siteEmrJson from "../fixtures/site-emr.json" with { type: "json" };
import siteJuiceJson from "../fixtures/site-juice.json" with { type: "json" };
import sitesJson from "../fixtures/sites.json" with { type: "json" };
import statusDownJson from "../fixtures/status-down.json" with { type: "json" };
import statusJson from "../fixtures/status.json" with { type: "json" };
import summaryJson from "../fixtures/summary.json" with { type: "json" };
import systemJson from "../fixtures/system.json" with { type: "json" };
import systemModelsJson from "../fixtures/system-models.json" with { type: "json" };
import timeseriesJson from "../fixtures/timeseries.json" with { type: "json" };
import objectSlotS2Json from "../fixtures/object-slot-s2.json" with { type: "json" };
import objectSlotS8Json from "../fixtures/object-slot-s8.json" with { type: "json" };
import objectsBootstrapJson from "../fixtures/objects-bootstrap.json" with { type: "json" };
import objectsRunsJson from "../fixtures/objects-runs.json" with { type: "json" };
import objectsEmptyJson from "../fixtures/objects-empty.json" with { type: "json" };
import objectsEmrJson from "../fixtures/objects-emr.json" with { type: "json" };
import versionsEmrJson from "../fixtures/versions-emr.json" with { type: "json" };

/**
 * The clock the samples are written around: 2026-11-01T13:20:00Z. Specs freeze the browser clock
 * here (`page.clock.setFixedTime(FIXTURE_NOW_MS)`), because the console builds its windows from the
 * current time and the rows are only inside the 24-hour window ending at this instant.
 */
export const FIXTURE_NOW_MS = 1793539200000;
export const DAY_MS = 24 * 60 * 60 * 1000;

/** Narrows a sample to the type it was written as (see the header for why the compiler cannot). */
function wire<T>(sample: unknown): T {
  return sample as T;
}

export const sitesList: SiteListResponse = wire(sitesJson);
export const siteEmr: SiteDetail = wire(siteEmrJson);
export const siteJuice: SiteDetail = wire(siteJuiceJson);
export const versionsEmr: SiteVersionsResponse = wire(versionsEmrJson);
export const requestList: RequestListResponse = wire(requestsJson);
export const requestDetails: RequestDetail[] = [
  wire(requestDetailLoginJson),
  wire(requestDetailBasketJson),
  wire(requestDetailSearchJson),
  wire(requestDetailFunctionJson),
];
export const sessionList: SessionListResponse = wire(sessionsJson);
export const sessionTimeline: SessionTimeline = wire(sessionTimelineJson);
export const jevStatus: JevStatus = wire(jevStatusJson);
export const jevStats: JevStats = jevStatsJson;
export const system: SystemInfo = wire(systemJson);
/** Both model configurations as GET /api/system/models answers them (系统 · 模型, design 5.1). */
export const systemModels: ModelsState = wire(systemModelsJson);
/** The saved versions of each configuration, newest first (design 2.6, 5.1). */
export const modelHistory: { jev: ModelVersionWire[]; agent: ModelVersionWire[] } =
  wire(modelHistoryJson);
export const insights: Insights = wire(insightsJson);
export const evidence: Evidence = evidenceJson;
export const summary: StatsSummary = summaryJson;
export const timeseries: Timeseries = timeseriesJson;
export const counts: RequestCounts = countsJson;
export const prompt: JevPrompt = wire(promptJson);
export const preview: ImpactPreview = wire(previewJson);
export const lookup: LookupResponse = wire(lookupJson);
export const status: StatusResponse = wire(statusJson);
export const statusDown: StatusResponse = wire(statusDownJson);
export const session: SessionState = sessionJson;
/** The object map of emr (console design 7): counts, classes, positions and events. */
export const objectsEmr: ObjectsResponse = wire(objectsEmrJson);
/** The function table of emr (console design 7, docs/07 7.9.20): two functions, three candidates, two proposals. */
export const siteFunctions: SiteFunctions = wire(functionsJson);
/** The map of a site that has none yet (juice): empty, so the cold start shows. */
export const objectsEmpty: ObjectsResponse = wire(objectsEmptyJson);
/** The drawer of position s2 of emr: a proposal with its flows, examples, shape and impact. */
export const objectSlotS2: ObjectSlotDetail = wire(objectSlotS2Json);
/** The drawer of position s8 of emr: an agent answer that disagrees with the rule, so the position is ambiguous. */
export const objectSlotS8: ObjectSlotDetail = wire(objectSlotS8Json);
/** The learning runs of emr, and the run 40 with its calls: one answered, one failed (console design 3.3). */
export const objectRuns: { runs: unknown[]; detail: unknown } = wire(objectsRunsJson);
/** The cold start candidates read from the last 24 hours of juice's requests. */
export const bootstrapCandidates: BootstrapResponse = wire(objectsBootstrapJson);
