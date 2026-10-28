import { Alert, Card, Input, Radio, Select } from "antd";
import { useEffect, useState } from "react";
import type { SiteRollout } from "../../../api.ts";
import {
  observableRoutes,
  type RolloutPhase,
  rolloutPhase,
  startObserve,
} from "../../../sites/model/rollout.ts";
import { Field } from "../fields";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";

const pad = (value: number) => String(value).padStart(2, "0");

/** A UTC second as the `datetime-local` value of the browser's own time zone. */
export function localInputValue(unix: number): string {
  const date = new Date(unix * 1000);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

/** A `datetime-local` value, read in the browser's time zone, as a UTC second (or null). */
export function parseLocalInput(value: string): number | null {
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? Math.floor(time / 1000) : null;
}

/** The wall clock in seconds, refreshed every minute so the phase follows the deadline. */
export function useNowUnix(): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 60_000);
    return () => window.clearInterval(timer);
  }, []);
  return now;
}

const phaseText: Record<Exclude<RolloutPhase, "enforce">, (until: string) => string> = {
  observing: (until) => `观察中，${until} 起 edge 自动转为强制，不需要再次发布。`,
  expiring: (until) =>
    `观察将在 24 小时内结束（${until}）。到期后自动强制；如需延长，必须由另一位审批人在 MFA 再认证后批准。`,
  expired: (until) =>
    `观察已于 ${until} 结束，edge 已按强制服务。保存任何修改前请把模式改回“强制”。`,
};

/**
 * 上线模式 (docs/32): enforce, or observe until a deadline with some routes enforced early. The
 * block only ever lists routes to enforce, so nothing here can relax a single route below the
 * site's mode.
 */
export function RolloutCard({ ws }: { ws: WorkspaceApi }) {
  const now = useNowUnix();
  const draft = ws.draft;
  if (!draft) return null;
  const rollout = draft.policy.rollout;
  const set = (next: SiteRollout | undefined) => ws.setPolicy("rollout", next);
  const phase = rolloutPhase(rollout, now);
  const covered = observableRoutes(draft.policy);
  const until = rollout ? new Date(rollout.observe_until_unix * 1000).toLocaleString() : "";
  return (
    <Card title="上线模式" className="xs-card">
      <Field
        id="rollout-mode"
        group
        label="模式"
        hint="观察期间，非 PUBLIC 的只读（GET）路由上因缺少登录或资格本应拒绝的请求仍转发到源站，并在审计中记为 OBSERVED_WOULD_DENY；写操作与 WAF、限流等拒绝照常执行。转为观察、延后截止时间或取消单独强制，需要另一位审批人在 MFA 再认证后批准。"
      >
        <Radio.Group
          aria-label="上线模式"
          className="xs-choice"
          value={rollout ? "observe" : "enforce"}
          onChange={(event) =>
            set(event.target.value === "observe" ? (rollout ?? startObserve(now)) : undefined)
          }
        >
          <Radio value="enforce">
            <span className="xs-choice-title">强制</span>
            <span className="xs-choice-hint">所有确定性拒绝立即生效（默认）。</span>
          </Radio>
          <Radio value="observe">
            <span className="xs-choice-title">观察</span>
            <span className="xs-choice-hint">先看哪些请求会被拒绝，到期自动转为强制。</span>
          </Radio>
        </Radio.Group>
      </Field>
      {rollout && phase !== "enforce" && (
        <Alert
          type={phase === "observing" ? "info" : "warning"}
          showIcon
          title={phaseText[phase](until)}
          className="xs-rollout-phase"
        />
      )}
      {rollout && (
        <>
          <Field
            id="rollout-until"
            label="观察截止时间（本地时间）"
            required
            issue={ws.issueFor("rollout.observe_until_unix")}
            hint="必须在未来 30 天以内；建议至少 7 天，覆盖完整的业务周期。"
          >
            <Input
              type="datetime-local"
              value={localInputValue(rollout.observe_until_unix)}
              onChange={(event) => {
                const unix = parseLocalInput(event.target.value);
                if (unix !== null) set({ ...rollout, observe_until_unix: unix });
              }}
            />
          </Field>
          <Field
            id="rollout-revision"
            label="观察标签"
            required
            issue={ws.issueFor("rollout.revision")}
            hint="写入每一条 OBSERVED_WOULD_DENY 审计（rollout_revision），用于按观察窗口检索与生成退出报告。"
          >
            <Input
              value={rollout.revision}
              maxLength={128}
              spellCheck={false}
              onChange={(event) => set({ ...rollout, revision: event.target.value })}
            />
          </Field>
          <Field
            id="rollout-enforced"
            label="已验证、单独强制的路由"
            issue={ws.issueFor("rollout.enforced_operations")}
            hint={
              covered.length === 0
                ? "当前没有可观察的路由：只有非 PUBLIC、GET、且不带响应模式、加密、认证、传感器、页面动作、资格、分页、分享或流转块的路由才会被观察。"
                : `可观察的路由 ${covered.length} 条；在这里选中的路由提前按强制执行。`
            }
          >
            <Select
              mode="multiple"
              allowClear
              value={rollout.enforced_operations ?? []}
              options={covered.map((route) => ({
                value: route.operation_id,
                label: `${route.operation_id}（${route.method} ${route.path}）`,
              }))}
              onChange={(values: string[]) => {
                const { enforced_operations: _, ...rest } = rollout;
                set(values.length > 0 ? { ...rest, enforced_operations: values } : rest);
              }}
            />
          </Field>
        </>
      )}
    </Card>
  );
}
