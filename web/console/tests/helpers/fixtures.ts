// Typed access to the JSON samples in tests/fixtures. Each file is the wire shape of one endpoint
// (src/api/types.ts). The Rust side round-trips the same files (docs/07 7.10.8), and the Playwright
// specs serve them through mock-api.ts. This module imports nothing but JSON and types, so unit
// tests can load it under plain node.

import type {
  Evidence,
  ImpactPreview,
  Insights,
  JevPrompt,
  JevStats,
  JevStatus,
  LookupResponse,
  RequestCounts,
  RequestDetail,
  RequestListResponse,
  SessionListResponse,
  SessionState,
  SessionTimeline,
  SiteDetail,
  SiteListResponse,
  SiteVersionsResponse,
  StatsSummary,
  StatusResponse,
  SystemInfo,
  Timeseries,
} from "../../src/api/types.ts";
import countsJson from "../fixtures/counts.json" with { type: "json" };
import evidenceJson from "../fixtures/evidence.json" with { type: "json" };
import insightsJson from "../fixtures/insights.json" with { type: "json" };
import jevStatsJson from "../fixtures/jev-stats.json" with { type: "json" };
import jevStatusJson from "../fixtures/jev-status.json" with { type: "json" };
import lookupJson from "../fixtures/lookup.json" with { type: "json" };
import previewJson from "../fixtures/preview.json" with { type: "json" };
import promptJson from "../fixtures/prompt.json" with { type: "json" };
import requestDetailBasketJson from "../fixtures/request-detail-req_01a1973940107ebea1af2c54ce635f38.json" with { type: "json" };
import requestDetailLoginJson from "../fixtures/request-detail-req_01a1971a07e079639a823d4257b43172.json" with { type: "json" };
import requestDetailSearchJson from "../fixtures/request-detail-req_01a1973ed5c0732b8f29804d7fc746d3.json" with { type: "json" };
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
import timeseriesJson from "../fixtures/timeseries.json" with { type: "json" };
import versionsEmrJson from "../fixtures/versions-emr.json" with { type: "json" };

/**
 * The clock the samples are written around: 2026-11-01T13:20:00Z. Specs freeze the browser clock
 * here (`page.clock.setFixedTime(FIXTURE_NOW_MS)`), because the console builds its windows from the
 * current time and the rows are only inside the 24-hour window ending at this instant.
 */
export const FIXTURE_NOW_MS = 1793539200000;
export const DAY_MS = 24 * 60 * 60 * 1000;

// The JSON import types are widened (strings, not unions), so each sample is cast to its wire type.
// The files are generated from typed objects, which is what keeps them in step with types.ts.

export const sitesList = sitesJson as SiteListResponse;
export const siteEmr = siteEmrJson as SiteDetail;
export const siteJuice = siteJuiceJson as SiteDetail;
export const versionsEmr = versionsEmrJson as SiteVersionsResponse;
export const requestList = requestsJson as RequestListResponse;
export const requestDetails: RequestDetail[] = [
  requestDetailLoginJson as RequestDetail,
  requestDetailBasketJson as RequestDetail,
  requestDetailSearchJson as RequestDetail,
];
export const sessionList = sessionsJson as SessionListResponse;
export const sessionTimeline = sessionTimelineJson as SessionTimeline;
export const jevStatus = jevStatusJson as JevStatus;
export const jevStats = jevStatsJson as JevStats;
export const system = systemJson as SystemInfo;
export const insights = insightsJson as Insights;
export const evidence = evidenceJson as Evidence;
export const summary = summaryJson as StatsSummary;
export const timeseries = timeseriesJson as Timeseries;
export const counts = countsJson as RequestCounts;
export const prompt = promptJson as JevPrompt;
export const preview = previewJson as ImpactPreview;
export const lookup = lookupJson as LookupResponse;
export const status = statusJson as StatusResponse;
export const statusDown = statusDownJson as StatusResponse;
export const session = sessionJson as SessionState;
