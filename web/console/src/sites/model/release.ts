import type { SiteRevision } from "../../api.ts";
import type { ApplyStateValue } from "../../ui/state-model.ts";
import { canonicalJson, configFromStored, type SiteConfigDraft } from "./config.ts";
import { type ApprovalExplanation, explainApproval } from "./risk.ts";

/** What the server says about a site's release state (from the status or the configuration read). */
export type ReleaseFacts = Readonly<{
  desired_revision: number | null;
  active_revision: number | null;
  apply_state: ApplyStateValue | null;
  requires_approval: boolean | null;
}>;

/**
 * What a rollback will do, as the server decides it (`rollback_target_revision` in the control
 * plane). The request carries no target: there is no body. The server picks the revision, so the
 * console can only describe the rule and, when the rule fixes the target, name it.
 *
 *  - With a change still pending (desired differs from active, or the last apply did not
 *    complete) the target is the ACTIVE revision: the rollback cancels the pending change.
 *  - Otherwise it is the revision that was active before the current one, by the order in which
 *    the edge confirmed them. That order is not exposed, so the console cannot name it; the
 *    older revisions are offered as candidates for a preview only. (It is deliberately not
 *    `active - 1`: revision numbers can belong to revisions that never served traffic.)
 *  - Without an active revision there is nothing to roll back to.
 */
export type RollbackPlan = Readonly<{
  available: boolean;
  /** True when the target is known: the pending change is cancelled by restoring `target`. */
  cancelsPendingChange: boolean;
  target: number | null;
  /** Older revisions, newest first: what a preview may compare with. Not a choice. */
  candidates: readonly number[];
}>;

export function planRollback(
  facts: Pick<ReleaseFacts, "desired_revision" | "active_revision" | "apply_state">,
  revisions: readonly number[],
): RollbackPlan {
  const { desired_revision: desired, active_revision: active, apply_state: state } = facts;
  if (active === null) {
    return { available: false, cancelsPendingChange: false, target: null, candidates: [] };
  }
  const pending = desired !== active || (state !== "active" && state !== "paused");
  const older = [...revisions].filter((revision) => revision < active).sort((a, b) => b - a);
  return {
    available: true,
    cancelsPendingChange: pending,
    target: pending ? active : null,
    candidates: pending ? [] : older,
  };
}

const digestPattern = /^[0-9a-f]{64}$/;

/**
 * The digest an approval is pinned to: the configuration the reviewer actually read. It comes
 * from the staged revision of the revisions the diff was drawn from; without revisions (a role
 * that cannot read them) the status's digest is the best available fact. `stale` means the two
 * sources disagree, so what is on screen is not what the server stages now.
 */
export function reviewDigest(
  staged: Readonly<{ config_digest: string }> | null,
  viewDigest: string | null,
): { digest: string | null; stale: boolean } {
  const valid = (value: string | null) =>
    value !== null && digestPattern.test(value) ? value : null;
  if (staged) {
    const read = valid(staged.config_digest);
    const current = valid(viewDigest);
    return { digest: read, stale: read !== null && current !== null && read !== current };
  }
  return { digest: valid(viewDigest), stale: false };
}

export type Gate = Readonly<{ enabled: boolean; hint: string }>;

export type ReleaseGates = Readonly<{
  validate: Gate;
  approve: Gate;
  apply: Gate;
  rollback: Gate;
}>;

/**
 * Which release actions are worth offering now, and one line of why. This is the page's own
 * reading of the facts (the server authorizes every call independently); a role that cannot read
 * the facts (`known` false) is offered everything its role allows and the server decides.
 */
export function releaseGates(facts: ReleaseFacts, known: boolean): ReleaseGates {
  const { desired_revision: desired, active_revision: active } = facts;
  const staged = desired === null ? "当前修订" : `r${desired}`;
  const plan = planRollback(facts, []);

  const approve: Gate =
    facts.requires_approval === false
      ? { enabled: false, hint: `${staged} 不需要审批。` }
      : {
          enabled: true,
          hint:
            facts.requires_approval === true
              ? `${staged} 需要另一位审批人批准；批准后立即下发给 edge。`
              : "批准当前暂存的修订；是否需要审批由服务端判断。",
        };

  let applyBlocked: string | null = null;
  if (facts.requires_approval === true) applyBlocked = "需要先批准；批准后会立即下发。";
  else if (known && desired === null) applyBlocked = "还没有可应用的修订。";
  const apply: Gate = applyBlocked
    ? { enabled: false, hint: applyBlocked }
    : { enabled: true, hint: `把 ${staged} 下发给 edge；edge 确认前仍在服务当前版本。` };

  let rollback: Gate;
  if (known && active === null) {
    rollback = { enabled: false, hint: "edge 还没有服务过这个站点，没有可回滚的修订。" };
  } else if (!known) {
    rollback = {
      enabled: true,
      hint: "创建新修订，恢复到服务端选择的版本；当前角色读不到状态，无法预览。",
    };
  } else if (plan.cancelsPendingChange) {
    rollback = {
      enabled: true,
      hint: `放弃待生效的变更：创建新修订，内容恢复为 edge 在用的 r${active}。`,
    };
  } else {
    rollback = {
      enabled: true,
      hint: "创建新修订，内容恢复为上一个曾在 edge 生效的版本（由服务端选择）。",
    };
  }

  return {
    validate: {
      enabled: true,
      hint: `对已保存的 ${staged} 运行服务端校验。不改变站点，也不发布。`,
    },
    approve,
    apply,
    rollback,
  };
}

/** The server's verdict on approval, with the console's reconstruction of the reasons. */
export type ApprovalNeed = Readonly<{
  /** `requires_approval` as the server reports it; `null` when the role cannot read it. */
  verdict: boolean | null;
  /** The reasons rebuilt from the two stored revisions; `null` when they cannot be read. */
  explanation: ApprovalExplanation | null;
  /** Why there is no explanation. */
  limitation: string | null;
  /** The reconstruction and the server disagree: the server is right, the console incomplete. */
  disagrees: boolean;
}>;

export function approvalNeed(input: {
  verdict: boolean | null;
  desired: number | null;
  active: number | null;
  /** Whether the role can read revisions at all (Observer). */
  readable: boolean;
  staged: SiteConfigDraft | null;
  serving: SiteConfigDraft | null;
}): ApprovalNeed {
  const { verdict, desired, active, readable, staged, serving } = input;
  let limitation: string | null = null;
  if (!readable) {
    limitation = "当前角色无法读取修订内容（需要 observer 角色），只能看到服务端的结论。";
  } else if (staged === null) {
    limitation = `修订历史里没有${desired === null ? "暂存的修订" : ` r${desired}`}，无法列出原因；刷新后再看。`;
  } else if (active !== null && serving === null) {
    limitation = `修订历史里没有 edge 在用的 r${active}，无法对比；刷新后再看。`;
  }
  const explanation = limitation === null && staged ? explainApproval(serving, staged) : null;
  return {
    verdict,
    explanation,
    limitation,
    disagrees: explanation !== null && verdict !== null && explanation.required !== verdict,
  };
}

/**
 * Revisions whose content is identical to an older one, which is what a rollback produces (it
 * stores the restored configuration as a NEW revision). The map is `revision -> the older
 * revision it repeats`. A revision identical to the one right before it is a plain re-save and
 * is not listed. Derived from the stored configurations, so it is evidence, not a record.
 */
export function restoredFrom(revisions: readonly SiteRevision[]): Map<number, number> {
  const ordered = [...revisions].sort((a, b) => a.revision - b.revision);
  const seen: Array<{ revision: number; content: string }> = [];
  const repeats = new Map<number, number>();
  for (const item of ordered) {
    const config = configFromStored(item.config, item.policy_revision);
    if (config === null) continue;
    const content = canonicalJson(config);
    const previous = seen.at(-1);
    if (previous?.content !== content) {
      const match = [...seen].reverse().find((entry) => entry.content === content);
      if (match) repeats.set(item.revision, match.revision);
    }
    seen.push({ revision: item.revision, content });
  }
  return repeats;
}
