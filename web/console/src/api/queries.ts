// TanStack Query hooks over the API (docs/07 7.10.4). Records never change once written, so their
// detail is cached forever; counters and statistics refresh every thirty seconds.

import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "./client.ts";
import type {
  AgentModelValues,
  JevModelValues,
  ModelKind,
  ModelsState,
  ModelWrite,
  ObjectsFilter,
  SiteSpec,
  SiteWriteBody,
} from "./types.ts";

export const keys = {
  session: ["session"] as const,
  sites: ["sites"] as const,
  site: (name: string) => ["site", name] as const,
  versions: (name: string) => ["versions", name] as const,
  requests: (query: string) => ["requests", query] as const,
  requestPages: (query: string) => ["requests-pages", query] as const,
  counts: (query: string) => ["counts", query] as const,
  detail: (id: string) => ["request", id] as const,
  system: ["system"] as const,
  models: ["system", "models"] as const,
  modelHistory: (kind: ModelKind) => ["system", "models", "history", kind] as const,
  jevStatus: ["jev-status"] as const,
  status: ["status"] as const,
  jevStats: (query: string) => ["jev-stats", query] as const,
  prompt: (id: string) => ["prompt", id] as const,
  sessions: (query: string) => ["sessions", query] as const,
  timeline: (label: string, query: string) => ["timeline", label, query] as const,
  timelinePages: (label: string, query: string) => ["timeline-pages", label, query] as const,
  summary: (query: string) => ["summary", query] as const,
  timeseries: (query: string) => ["timeseries", query] as const,
  insights: (name: string) => ["insights", name] as const,
  evidence: (name: string) => ["evidence", name] as const,
  preview: (name: string, spec: string) => ["preview", name, spec] as const,
};

/** Adds a cursor to a query string built by `qs`, which may be empty. */
function withCursor(query: string, cursor: string | null): string {
  if (cursor === null) return query;
  const separator = query.length === 0 ? "?" : "&";
  return `${query}${separator}cursor=${encodeURIComponent(cursor)}`;
}

export function useSession() {
  return useQuery({ queryKey: keys.session, queryFn: api.session, retry: false });
}

export function useSites(enabled = true) {
  return useQuery({
    queryKey: keys.sites,
    queryFn: api.sites,
    staleTime: 10_000,
    refetchInterval: 30_000,
    enabled,
  });
}

/** One site. `refetchInterval` lets the page poll until a saved version has loaded (docs/06 6.4.9). */
export function useSite(name: string | null, options: { refetchInterval?: number | false } = {}) {
  return useQuery({
    queryKey: keys.site(name ?? ""),
    queryFn: () => api.site(name ?? ""),
    enabled: name !== null,
    staleTime: 5_000,
    refetchInterval: options.refetchInterval ?? false,
  });
}

export function useVersions(name: string | null) {
  return useQuery({
    queryKey: keys.versions(name ?? ""),
    queryFn: () => api.versions(name ?? ""),
    enabled: name !== null,
  });
}

export function useSystem() {
  return useQuery({ queryKey: keys.system, queryFn: api.system });
}

export function useJevStatus() {
  return useQuery({ queryKey: keys.jevStatus, queryFn: api.jevStatus, refetchInterval: 15_000 });
}

/** The gateway and Jev status behind the top bar lights and the overview (docs/07 7.9.13). */
export function useStatus() {
  return useQuery({ queryKey: keys.status, queryFn: api.status, refetchInterval: 15_000 });
}

export function useRequests(query: string) {
  return useQuery({
    queryKey: keys.requests(query),
    queryFn: () => api.requests(query),
    placeholderData: keepPreviousData,
    staleTime: 10_000,
  });
}

/** The request list, one page at a time (cursor paging, docs/06 6.4.3). */
export function useRequestPages(query: string) {
  return useInfiniteQuery({
    queryKey: keys.requestPages(query),
    queryFn: ({ pageParam }) => api.requests(withCursor(query, pageParam)),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor,
    staleTime: 10_000,
  });
}

export function useRequestCounts(query: string) {
  return useQuery({
    queryKey: keys.counts(query),
    queryFn: () => api.requestCounts(query),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function useRequestDetail(id: string | null) {
  return useQuery({
    queryKey: keys.detail(id ?? ""),
    queryFn: () => api.requestDetail(id ?? ""),
    enabled: id !== null,
    staleTime: Number.POSITIVE_INFINITY,
    retry: (count, error) => !(error instanceof Error && error.name === "ApiError") && count < 1,
  });
}

export function useSummary(query: string) {
  return useQuery({
    queryKey: keys.summary(query),
    queryFn: () => api.summary(query),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function useTimeseries(query: string) {
  return useQuery({
    queryKey: keys.timeseries(query),
    queryFn: () => api.timeseries(query),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function useSessions(query: string) {
  return useQuery({
    queryKey: keys.sessions(query),
    queryFn: () => api.sessions(query),
    staleTime: 10_000,
  });
}

export function useTimeline(label: string, query: string) {
  return useInfiniteQuery({
    queryKey: keys.timelinePages(label, query),
    queryFn: ({ pageParam }) => api.sessionTimeline(label, withCursor(query, pageParam)),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor,
    staleTime: 10_000,
  });
}

export function useJevStats(query: string) {
  return useQuery({
    queryKey: keys.jevStats(query),
    queryFn: () => api.jevStats(query),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
}

export function usePrompt(id: string | null) {
  return useQuery({
    queryKey: keys.prompt(id ?? ""),
    queryFn: () => api.prompt(id ?? ""),
    enabled: id !== null,
    staleTime: Number.POSITIVE_INFINITY,
  });
}

export function useInsights(name: string | null) {
  return useQuery({
    queryKey: keys.insights(name ?? ""),
    queryFn: () => api.insights(name ?? ""),
    enabled: name !== null,
    staleTime: 30_000,
  });
}

export function useEvidence(name: string | null, enabled = true) {
  return useQuery({
    queryKey: keys.evidence(name ?? ""),
    queryFn: () => api.evidence(name ?? ""),
    enabled: name !== null && enabled,
    staleTime: 60_000,
  });
}

/** The impact of a draft on the last 24 hours (docs/07 7.9.10). The caller debounces the spec. */
export function usePreview(name: string | null, spec: SiteSpec | null) {
  const key = spec === null ? "" : JSON.stringify(spec);
  return useQuery({
    queryKey: keys.preview(name ?? "", key),
    queryFn: () => api.preview(name ?? "", spec as SiteSpec),
    enabled: name !== null && spec !== null,
    staleTime: 60_000,
    placeholderData: keepPreviousData,
  });
}

export function useValidate() {
  return useMutation({ mutationFn: (spec: SiteSpec) => api.validate(spec) });
}

export function useLogin() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (password: string) => api.login(password),
    onSuccess: () => {
      // Set before any refetch, so a redirect right after sign-in sees the new session at once.
      client.setQueryData(keys.session, { authenticated: true });
      void client.invalidateQueries({ queryKey: keys.session });
    },
  });
}

export function useLogout() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api.logout(),
    onSettled: () => client.setQueryData(keys.session, { authenticated: false }),
  });
}

/** Saves a configuration as a new version. `expected_version` makes a stale save fail (409). */
export function useSaveSite() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async (args: { name: string | null; spec: SiteSpec; body?: SiteWriteBody }) => {
      if (args.name === null) return api.createSite(args.spec, args.body?.note);
      return api.updateSite(args.name, {
        spec: args.spec,
        expected_version: args.body?.expected_version,
        note: args.body?.note,
      });
    },
    onSuccess: (site) => {
      client.setQueryData(keys.site(site.name), site);
      void client.invalidateQueries({ queryKey: keys.sites });
      void client.invalidateQueries({ queryKey: keys.versions(site.name) });
      void client.invalidateQueries({ queryKey: keys.insights(site.name) });
    },
  });
}

export function useDeleteSite() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.deleteSite(name),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.sites }),
  });
}

export function useRollback() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (args: {
      name: string;
      toVersion: number;
      expectedVersion: number;
      note?: string;
    }) =>
      api.rollback(args.name, {
        to_version: args.toVersion,
        expected_version: args.expectedVersion,
        note: args.note,
      }),
    onSuccess: (site) => {
      client.setQueryData(keys.site(site.name), site);
      void client.invalidateQueries({ queryKey: keys.versions(site.name) });
      void client.invalidateQueries({ queryKey: keys.sites });
    },
  });
}

export function useLookup() {
  return useMutation({ mutationFn: (ids: string[]) => api.lookup(ids) });
}

export function useImport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (text: string) => api.importLog(text),
    onSuccess: () => client.invalidateQueries({ queryKey: ["requests"] }),
  });
}

// ------------------------------------------------------------------ the object map (console design 7)

/** The map of a site, filtered by state and search text. Counts and classes are always the whole map. */
export function useSiteObjects(
  name: string | null,
  filter: ObjectsFilter = {},
  options: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: ["objects", name ?? "", filter] as const,
    queryFn: () => api.objects(name ?? "", filter),
    enabled: name !== null && (options.enabled ?? true),
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  });
}

export function useObjectSlot(name: string | null, id: string | null) {
  return useQuery({
    queryKey: ["object-slot", name ?? "", id ?? ""] as const,
    queryFn: () => api.objectSlot(name ?? "", id ?? ""),
    enabled: name !== null && id !== null,
    staleTime: 30_000,
  });
}

/** The cold start candidates of a site (object-map design 3): read once, the list is shown until confirmed. */
export function useBootstrap(name: string | null) {
  return useQuery({
    queryKey: ["bootstrap", name ?? ""] as const,
    queryFn: () => api.bootstrap(name ?? ""),
    enabled: name !== null,
    staleTime: 60_000,
  });
}

/** Ignores a proposal or marks a position ambiguous. Learning state only: no site version is written. */
export function useSlotLearning() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (args: { name: string; id: string; action: "dismiss" | "ambiguous" }) =>
      args.action === "dismiss"
        ? api.dismissSlot(args.name, args.id)
        : api.ambiguousSlot(args.name, args.id),
    onSuccess: (_result, args) => {
      void client.invalidateQueries({ queryKey: ["objects", args.name] });
      void client.invalidateQueries({ queryKey: ["object-slot", args.name] });
    },
  });
}

// ------------------------------------------------------------------ models (系统 · 模型, design 2, 5.1)

/**
 * Both model configurations. `poll` decides the refresh from the data already read: the card asks every five
 * seconds while a saved version is still on its way to the gateways (design 2.5).
 */
export function useSystemModels(poll?: (data: ModelsState | undefined) => number | false) {
  return useQuery({
    queryKey: keys.models,
    queryFn: api.systemModels,
    refetchInterval: poll ? (query) => poll(query.state.data) : false,
  });
}

/** Saves the Jev configuration as a new version. The version list and the gateway status are re-read. */
export function useSaveJevModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ModelWrite<JevModelValues>) => api.saveJevModel(body),
    // A save answers with the version only, so the configuration is read again rather than patched in.
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.models });
    },
  });
}

/** Saves the learning agent's configuration as a new version. */
export function useSaveAgentModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ModelWrite<AgentModelValues>) => api.saveAgentModel(body),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.models });
    },
  });
}

/** Switches Jev back to the environment's configuration. */
export function useDeleteJevModel() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (expectedVersion: number) => api.deleteJevModel(expectedVersion),
    onSuccess: (jev) => {
      client.setQueryData<ModelsState>(keys.models, (old) => (old ? { ...old, jev } : old));
      void client.invalidateQueries({ queryKey: keys.models });
    },
  });
}

/** The last twenty versions of one configuration; read only when the card opens its history. */
export function useModelHistory(kind: ModelKind, enabled: boolean) {
  return useQuery({
    queryKey: keys.modelHistory(kind),
    queryFn: () => api.modelHistory(kind),
    enabled,
  });
}
