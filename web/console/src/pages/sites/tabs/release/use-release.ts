import { useMemo } from "react";
import type { SiteRevision } from "../../../../api.ts";
import { emptyDraft, type SiteConfigDraft } from "../../../../sites/model/config.ts";
import { diffConfigs, type FieldChange } from "../../../../sites/model/diff.ts";
import {
  type ApprovalNeed,
  approvalNeed,
  planRollback,
  type ReleaseGates,
  type RollbackPlan,
  releaseGates,
  reviewDigest,
} from "../../../../sites/model/release.ts";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";

/** What the release page derives once from the server's facts and the revisions it could read. */
export type Release = Readonly<{
  /** The server's facts were read (a role without Observer or SystemAdmin has none). */
  known: boolean;
  /** A change is staged that the edge does not serve. */
  pending: boolean;
  serving: SiteRevision | null;
  staged: SiteRevision | null;
  servingConfig: SiteConfigDraft | null;
  stagedConfig: SiteConfigDraft | null;
  /** What replacing the served configuration with the staged one changes; `null` if unreadable. */
  changes: readonly FieldChange[] | null;
  /** The comparison is against a served revision (risk reasons apply), not the defaults. */
  comparesServed: boolean;
  /** Why there is no comparison to show; `null` when `changes` is available. */
  diffNote: string | null;
  /** The facts or the revisions this role reads are still on their way: nothing to act on yet. */
  loading: boolean;
  gates: ReleaseGates;
  plan: RollbackPlan;
  need: ApprovalNeed;
  /** The digest an approval is pinned to, and whether the page's two sources disagree about it. */
  review: Readonly<{ digest: string | null; stale: boolean }>;
}>;

export function useRelease(ws: WorkspaceApi): Release {
  const { view, revisions, access, stagedConfig, activeConfig } = ws;
  const known = view.source !== "none";
  const serving = useMemo(
    () => revisions.find((item) => item.revision === view.active_revision) ?? null,
    [revisions, view.active_revision],
  );
  const staged = useMemo(
    () => revisions.find((item) => item.revision === view.desired_revision) ?? null,
    [revisions, view.desired_revision],
  );
  const pending =
    known && view.desired_revision !== null && view.desired_revision !== view.active_revision;
  // Only a role that can read them waits for the facts and the revisions; a disabled query
  // that never runs also reports "pending", so the role decides, not the query alone.
  const loading = access.canObserve && (!known || ws.revisionsQuery.isPending);

  // Never served: the staged configuration is compared with what a new site starts from.
  const neverServed = known && view.active_revision === null;
  const changes = useMemo(() => {
    if (!stagedConfig) return null;
    const baseline = activeConfig ?? (neverServed ? emptyDraft() : null);
    return baseline ? diffConfigs(baseline, stagedConfig) : null;
  }, [stagedConfig, activeConfig, neverServed]);

  return {
    known,
    pending,
    serving,
    staged,
    servingConfig: activeConfig,
    stagedConfig,
    changes,
    comparesServed: activeConfig !== null,
    diffNote:
      changes !== null
        ? null
        : loading
          ? "正在读取修订历史…"
          : access.canObserve
            ? "修订历史里没有读到暂存或在用的修订，无法显示差异；刷新站点后再看。"
            : "当前角色无法读取修订内容，无法显示差异。",
    loading,
    gates: releaseGates(view, known),
    plan: planRollback(
      view,
      revisions.map((item) => item.revision),
    ),
    need: approvalNeed({
      verdict: view.requires_approval,
      desired: view.desired_revision,
      active: view.active_revision,
      readable: access.canObserve,
      staged: stagedConfig,
      serving: activeConfig,
    }),
    review: reviewDigest(staged, view.config_digest),
  };
}
