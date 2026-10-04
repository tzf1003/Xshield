import { useBlocker, useRouter } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { siteRoute } from "../../../admin-routes.ts";
import type {
  SiteApplyResponse,
  SiteConfigResponse,
  SiteDeleteResponse,
  SitePolicyConfig,
  SiteRevision,
  SiteValidationResponse,
} from "../../../api.ts";
import { type SafeError, safeError } from "../../../security/errors.ts";
import { runFrozenWrite, type WriteResult } from "../../../security/guarded.ts";
import { usePendingOperations } from "../../../security/hooks.ts";
import type { OperationSnapshot } from "../../../security/pending-operations.ts";
import type { ScopedResponse } from "../../../security/scope.ts";
import { useSession } from "../../../security/SessionProvider.tsx";
import { usePageTitle } from "../../../shell/page-title.tsx";
import { siteAccess } from "../../../sites/access.ts";
import {
  configFromStored,
  draftFromConfig,
  emptyDraft,
  type SiteConfigDraft,
  withEntry,
} from "../../../sites/model/config.ts";
import { diffConfigs, type FieldChange } from "../../../sites/model/diff.ts";
import { type Issue, issuesByPath, validateDraft } from "../../../sites/model/validation.ts";
import {
  describeApply,
  describeDelete,
  describeSave,
  describeValidation,
  type Outcome,
  writeFailureTitle,
} from "../../../sites/outcome.ts";
import {
  useSiteCache,
  useSiteConfig,
  useSiteRevisions,
  useSiteStatus,
} from "../../../sites/state/detail-queries.ts";
import {
  operationKind,
  operationsOfSite,
  type WriteKind,
} from "../../../sites/state/write-kinds.ts";
import { useCreateSite, useSiteWrites } from "../../../sites/state/writes.ts";
import type { ApplyStateValue, ConfigStatusValue } from "../../../ui/state-model.ts";

/** What the operator sees after a write: a confirmed outcome, or a refusal with its diagnostics. */
export type Notice =
  | (Outcome & { kind: "outcome" })
  | { kind: "problem"; title: string; problem: SafeError };

/** The server's facts about the site, from whichever read the roles allow. */
export type SiteView = Readonly<{
  source: "config" | "status" | "none";
  desired_revision: number | null;
  active_revision: number | null;
  apply_state: ApplyStateValue | null;
  requires_approval: boolean | null;
  reason_code: string | null;
  config_digest: string | null;
  apply_id: string | null;
  /** The configured status of the staged revision (from the config or the stored revision). */
  status: ConfigStatusValue | null;
}>;

const NO_VIEW: SiteView = {
  source: "none",
  desired_revision: null,
  active_revision: null,
  apply_state: null,
  requires_approval: null,
  reason_code: null,
  config_digest: null,
  apply_id: null,
  status: null,
};

/** A notice that must survive the navigation after "create" (memory only, consumed once). */
let flash: { siteId: string; notice: Notice } | null = null;
const takeFlash = (siteId: string | null): Notice | null => {
  if (flash && flash.siteId === siteId) {
    const notice = flash.notice;
    flash = null;
    return notice;
  }
  return null;
};

export const LEAVE_PROMPT = "当前站点有未保存草稿或待确认操作。确定离开？";

function storedConfig(revisions: readonly SiteRevision[], revision: number | null) {
  const stored =
    revision === null ? undefined : revisions.find((item) => item.revision === revision);
  return stored ? configFromStored(stored.config, stored.policy_revision) : null;
}

/**
 * Everything one site's pages share: the reads its roles allow, the draft and its unsaved-change
 * summary, the validation findings, the leave guard, and the writes with their outcome. A site
 * is `siteId`; `null` is the transitional "create" flow (the wizard replaces it).
 */
export function useSiteWorkspace(siteId: string | null) {
  const creating = siteId === null;
  const id = siteId ?? "";
  const router = useRouter();
  const { runtime, state } = useSession();
  const access = siteAccess(state.roles);

  const configQuery = useSiteConfig(id, !creating && access.canConfigure);
  const statusQuery = useSiteStatus(id, !creating && !access.canConfigure && access.canObserve);
  const revisionsQuery = useSiteRevisions(id, !creating && access.canObserve);
  const cache = useSiteCache(id);
  const writes = useSiteWrites(id);
  const createWrite = useCreateSite();

  const operations = usePendingOperations();
  const own = useMemo(
    () => operationsOfSite(operations, siteId, creating),
    [operations, siteId, creating],
  );
  const unresolved = own.some((operation) => operation.phase !== "step_up");

  // ---- server facts ----
  const configResponse: SiteConfigResponse | null = configQuery.data ?? null;
  const found = configResponse === null ? null : configResponse.found;
  const revisions: SiteRevision[] = revisionsQuery.data?.revisions ?? [];
  const saved = useMemo(
    () =>
      configResponse?.found && configResponse.config
        ? draftFromConfig(configResponse.config)
        : null,
    [configResponse],
  );
  const blank = useMemo(emptyDraft, []);
  const baseline = creating ? blank : saved;

  const view: SiteView = useMemo(() => {
    const status = statusQuery.data ?? null;
    const source = configResponse?.found ? configResponse : status;
    if (source === null) return NO_VIEW;
    const desired = source.desired_revision;
    const stored =
      desired === null ? undefined : revisions.find((revision) => revision.revision === desired);
    return {
      source: configResponse?.found ? "config" : "status",
      desired_revision: desired,
      active_revision: source.active_revision,
      apply_state: source.apply_state,
      requires_approval: source.requires_approval,
      reason_code: source.reason_code,
      config_digest: source.config_digest,
      apply_id: source.apply_id,
      status:
        configResponse?.config?.status ??
        configFromStored(stored?.config, stored?.policy_revision)?.status ??
        null,
    };
  }, [configResponse, statusQuery.data, revisions]);

  /** The stored configuration of a revision, read tolerantly (for headers and approval reasons). */
  const stagedConfig = useMemo(
    () => storedConfig(revisions, view.desired_revision),
    [revisions, view.desired_revision],
  );
  const activeConfig = useMemo(
    () => storedConfig(revisions, view.active_revision),
    [revisions, view.active_revision],
  );

  // ---- the draft ----
  const [draft, setDraft] = useState<SiteConfigDraft | null>(creating ? emptyDraft() : null);
  const [newSiteId, setNewSiteId] = useState("");
  const seededAt = useRef(0);
  useEffect(() => {
    // Every successful read of the configuration (including an explicit refresh that returns
    // equal data) restarts the draft from the server; nothing else ever overwrites it.
    if (creating || saved === null || seededAt.current === configQuery.dataUpdatedAt) return;
    seededAt.current = configQuery.dataUpdatedAt;
    setDraft(structuredClone(saved));
  }, [creating, saved, configQuery.dataUpdatedAt]);

  const changes: FieldChange[] = useMemo(
    () => (draft && baseline ? diffConfigs(baseline, draft) : []),
    [baseline, draft],
  );
  const issues: Issue[] = useMemo(
    () => (draft ? validateDraft(draft, { creating, siteId: newSiteId }) : []),
    [draft, creating, newSiteId],
  );
  const issueMap = useMemo(() => issuesByPath(issues), [issues]);
  const dirty = changes.length > 0 || (creating && newSiteId !== "");
  const errors = issues.filter((issue) => issue.severity === "error");

  const update = useCallback(
    (change: (current: SiteConfigDraft) => SiteConfigDraft) =>
      setDraft((current) => (current ? change(current) : current)),
    [],
  );
  const set = useCallback(
    <K extends keyof SiteConfigDraft>(key: K, value: SiteConfigDraft[K]) =>
      update((current) => ({ ...current, [key]: value })),
    [update],
  );
  const setPolicy = useCallback(
    <K extends keyof SitePolicyConfig>(key: K, value: SitePolicyConfig[K]) =>
      update((current) => ({ ...current, policy: { ...current.policy, [key]: value } })),
    [update],
  );
  const setEntry = useCallback(
    (entry: Partial<Pick<SiteConfigDraft, "entry_path" | "security_entry">>) =>
      update((current) => withEntry(current, entry)),
    [update],
  );
  const discard = useCallback(() => {
    setDraft(baseline ? structuredClone(baseline) : null);
    setNewSiteId("");
  }, [baseline]);

  // ---- leaving the site ----
  const guard = useRef({ dirty: false, unresolved: false });
  guard.current = { dirty, unresolved };
  useBlocker({
    shouldBlockFn: ({ current, next }) => {
      if (!guard.current.dirty && !guard.current.unresolved) return false;
      const before = siteRoute(current.pathname);
      const after = siteRoute(next.pathname);
      if (before && after && before.siteId === after.siteId) return false;
      return !window.confirm(LEAVE_PROMPT);
    },
    // Unresolved writes are covered by the session-wide registry guard; this one is for drafts.
    enableBeforeUnload: () => guard.current.dirty,
  });

  // ---- writes ----
  const [notice, setNotice] = useState<Notice | null>(() => takeFlash(siteId));
  const [running, setRunning] = useState(false);
  const goTo = useCallback(
    (to: string) => void router.navigate({ to, ignoreBlocker: true } as never),
    [router],
  );

  const confirmed = useCallback(
    (kind: WriteKind, response: ScopedResponse) => {
      switch (kind) {
        case "create": {
          const config = response as SiteConfigResponse;
          cache.setConfig(config, config.site_id);
          cache.refreshDetail();
          flash = {
            siteId: config.site_id,
            notice: { kind: "outcome", ...describeSave(config, true) },
          };
          goTo(`/sites/${config.site_id}/overview`);
          break;
        }
        case "save":
          cache.setConfig(response);
          cache.refreshDetail();
          setNotice({ kind: "outcome", ...describeSave(response as SiteConfigResponse, false) });
          break;
        case "validate":
          setNotice({ kind: "outcome", ...describeValidation(response as SiteValidationResponse) });
          break;
        case "delete":
          cache.dropSite();
          setNotice({ kind: "outcome", ...describeDelete(response as SiteDeleteResponse) });
          goTo("/sites");
          break;
        default:
          cache.refreshDetail();
          setNotice({ kind: "outcome", ...describeApply(kind, response as SiteApplyResponse) });
      }
    },
    [cache, goTo],
  );

  const report = useCallback(
    (kind: WriteKind, result: WriteResult<ScopedResponse>) => {
      if (result.kind === "confirmed") confirmed(kind, result.response);
      else if (result.kind === "rejected" || result.kind === "step_up") {
        setNotice({
          kind: "problem",
          title: writeFailureTitle[kind],
          problem: safeError(result.error),
        });
      }
      // `unknown` lives in the registry (the pending banner offers the exact retry); `stale`
      // means the session ended and everything was cleared.
    },
    [confirmed],
  );

  /** Runs one write through `useGuardedMutation` and reports what the server answered. */
  const run = useCallback(
    async <T extends ScopedResponse>(kind: WriteKind, submit: () => Promise<WriteResult<T>>) => {
      setRunning(true);
      setNotice(null);
      try {
        const result = await submit();
        report(kind, result as WriteResult<ScopedResponse>);
        return result;
      } finally {
        setRunning(false);
      }
    },
    [report],
  );

  const save = useCallback(async () => {
    if (!draft) return;
    if (creating)
      await run("create", () => createWrite.submit({ siteId: newSiteId, config: draft }));
    else await run("save", () => writes.save.submit({ config: draft }));
  }, [draft, creating, newSiteId, run, createWrite, writes.save]);

  /** Repeats an unresolved write exactly: same method, path, body and idempotency key. */
  const retry = useCallback(
    async (operation: OperationSnapshot) => {
      const kind = operationKind(operation);
      if (kind === null) return;
      setRunning(true);
      setNotice(null);
      try {
        report(
          kind,
          await runFrozenWrite<ScopedResponse>(runtime.store, runtime.pending, operation.id),
        );
      } finally {
        setRunning(false);
      }
    },
    [runtime, report],
  );

  /** The operator gives up on an unresolved write and re-reads the server's state instead. */
  const abandon = useCallback(
    (operation: OperationSnapshot) => {
      runtime.pending.abandon(operation.id);
      cache.refreshDetail();
    },
    [runtime, cache],
  );

  const refresh = useCallback(() => {
    if (dirty && !window.confirm("放弃当前草稿并重新读取服务端状态？")) return;
    setNotice(null);
    if (creating) {
      discard();
      return;
    }
    if (access.canConfigure) void configQuery.refetch();
    else setDraft(null);
    if (!access.canConfigure && access.canObserve) void statusQuery.refetch();
    if (access.canObserve) void revisionsQuery.refetch();
  }, [dirty, creating, discard, access, configQuery, statusQuery, revisionsQuery]);

  usePageTitle(creating ? "新建站点" : saved?.display_name || siteId);

  return {
    siteId,
    creating,
    access,
    // reads
    configQuery,
    statusQuery,
    revisionsQuery,
    found,
    view,
    revisions,
    saved,
    stagedConfig,
    activeConfig,
    // draft
    draft,
    newSiteId,
    setNewSiteId,
    changes,
    issues,
    errors,
    issueFor: (path: string) => issueMap.get(path),
    dirty,
    update,
    set,
    setPolicy,
    setEntry,
    discard,
    // writes
    writes,
    own,
    unresolved,
    running,
    locked: running || unresolved,
    notice,
    setNotice,
    run,
    save,
    retry,
    abandon,
    refresh,
    cache,
  };
}

export type WorkspaceApi = ReturnType<typeof useSiteWorkspace>;
