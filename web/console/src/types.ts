/** Shared wire types for the v4 control API. Keep these in sync with docs/03-admin-config-audit.md. */

export type SessionCredential = { cookie: string } | { header: string };

export type SiteMode = "observe" | "enforce";
export type OnJevUnavailable = "deny" | "allow";

export interface SiteSpecJson {
  name: string;
  hosts: string[];
  origin: string;
  session: SessionCredential;
  entries: string[];
  bypass: string[];
  mode: SiteMode;
  on_jev_unavailable: OnJevUnavailable;
}

export interface SiteRecord extends SiteSpecJson {
  created_at: string;
  updated_at: string;
}

export interface HistoryEntry {
  id: number;
  before: SiteSpecJson | null;
  after: SiteSpecJson | null;
  changed_at: string;
}

export type DecisionPath =
  | "fast_allow"
  | "cached_allow"
  | "jev_allow"
  | "jev_deny"
  | "jev_unavailable"
  | "no_session";

export type DecisionOutcome = "allowed" | "blocked" | "would_block" | "unjudged";

export interface JevInfo {
  state: string;
  access: Record<string, number>;
  attack: Record<string, number>;
  millis: number;
}

export interface DecisionLogRow {
  id: number;
  at_millis: number;
  site: string;
  request_id: string;
  session: string;
  method: string;
  path: string;
  status: number | null;
  decision_path: DecisionPath;
  outcome: DecisionOutcome;
  jev: JevInfo | null;
}

export interface JevStatus {
  status: string;
}

export interface ApiErrorBody {
  error: string;
}
