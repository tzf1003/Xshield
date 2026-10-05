import { ReloadOutlined } from "@ant-design/icons";
import { App as AntdApp, Button, Empty, Skeleton } from "antd";
import type { ReactNode } from "react";
import type { SourceState } from "../../operations/sources.ts";
import type { TodoItem, TodoKind } from "../../operations/todo.ts";
import { useFrozenRetry } from "../../operations/use-retry.ts";
import { RoleHint } from "../../operations/Parts";
import { TimeStamp } from "../../ui/TimeStamp";
import { RouteLink } from "../../work/nav";
import { ErrorNotice, TonePill } from "../../work/Parts";
import type { Tone } from "../../work/status.ts";

const kinds: Record<TodoKind, { label: string; tone: Tone | "brand" }> = {
  write: { label: "结果未知", tone: "warning" },
  failed: { label: "应用失败", tone: "error" },
  site: { label: "策略审批", tone: "default" },
  access: { label: "原文审批", tone: "processing" },
  export: { label: "导出审批", tone: "brand" },
};

/**
 * A key-issuing write (create or rotate an API key) is retried on its own page only: its reply
 * carries a plaintext that is shown once, in the dialog of that page.
 */
function issuesSecret(path: string): boolean {
  return /^\/control\/v1\/agent-api-keys(?:\/key_[0-9a-f-]+\/rotate)?$/.test(path);
}

export type TodoSource = Readonly<{
  key: string;
  label: string;
  state: SourceState<unknown>;
  /** What the role refusal means for this list. */
  deniedHint: string;
  count: number;
  /** The first page had more rows than it shows. */
  more: boolean;
  retry: () => void;
  busy: boolean;
}>;

function sourceText(source: TodoSource): ReactNode {
  switch (source.state.status) {
    case "ok":
      return `${source.count}${source.more ? "+" : ""} 项`;
    case "loading":
      return "读取中…";
    case "denied":
      return "服务端拒绝（角色）";
    case "failed":
      return "读取失败";
    default:
      return "未读取";
  }
}

/**
 * "待我处理": the operator's queue across sources, each read once when the page opens. A source
 * refused for the role becomes a quiet hint; a failed source gets its own banner and retry; the
 * rows of the sources that answered are shown either way.
 */
export function TodoCard({
  items,
  sources,
  onRefresh,
}: {
  items: readonly TodoItem[];
  sources: readonly TodoSource[];
  onRefresh: () => void;
}) {
  const { message } = AntdApp.useApp();
  const { retry, busy } = useFrozenRetry();
  const read = sources.filter((source) => source.state.status !== "skipped");
  const loading = read.some((source) => source.state.status === "loading");
  const complete = read.every((source) => source.state.status === "ok");
  const writes = items.filter((item) => item.kind === "write").length;

  async function resend(item: TodoItem) {
    const result = await retry(item.id);
    if (result?.kind === "confirmed") {
      message.success(
        `“${item.operation?.label ?? "写入"}”已由服务端确认，相关页面下次打开时会重新读取。`,
      );
    } else if (result?.kind === "rejected") {
      message.warning("服务端拒绝了这次请求，没有写入任何内容。");
    }
  }

  return (
    <section className="xs-w-card" aria-labelledby="wb-todo-title">
      <div className="xs-wb-head">
        <div>
          <h2 id="wb-todo-title">
            待我处理
            <span className="xs-wb-count">{items.length}</span>
          </h2>
          <p className="xs-wb-sub">
            按你的角色读取的待办来源，打开页面时各读取一次；结果未知的写入和应用失败排在最前。
          </p>
        </div>
        {read.length > 0 && (
          <Button
            icon={<ReloadOutlined aria-hidden="true" />}
            loading={read.some((source) => source.busy)}
            onClick={onRefresh}
          >
            刷新待办
          </Button>
        )}
      </div>
      <ul className="xs-wb-sources" aria-label="待办来源">
        {read.map((source) => (
          <li key={source.key}>
            <strong>{source.label}</strong> {sourceText(source)}
          </li>
        ))}
        <li>
          <strong>本会话结果未知的写入</strong> {writes} 项
        </li>
      </ul>
      {read.map((source) =>
        source.state.status === "denied" ? (
          <RoleHint key={source.key} title={`${source.label}：服务端拒绝了当前身份`}>
            {source.deniedHint}
          </RoleHint>
        ) : source.state.status === "failed" ? (
          <ErrorNotice
            key={source.key}
            error={source.state.error}
            title={`${source.label}读取失败`}
            action={
              <Button size="small" loading={source.busy} onClick={source.retry}>
                重试
              </Button>
            }
          />
        ) : null,
      )}
      {items.length > 0 ? (
        <ul className="xs-wb-todos" aria-label="待处理事项">
          {items.map((item) => (
            <li key={item.key} className="xs-wb-todo">
              <span>
                <TonePill tone={kinds[item.kind].tone} label={kinds[item.kind].label} />
              </span>
              <div className="xs-wb-todo-main">
                <strong>{item.title}</strong>
                <small className={item.kind === "write" ? "mono" : undefined}>{item.detail}</small>
                <small>
                  {item.requester ? `${item.requester} · ` : ""}
                  {item.at ? <TimeStamp value={item.at} compact /> : "时间未知"}
                </small>
              </div>
              <div className="xs-wb-todo-actions">
                {item.kind === "write" &&
                  item.operation &&
                  item.operation.phase !== "inflight" &&
                  !issuesSecret(item.operation.path) && (
                    <Button
                      size="small"
                      type="primary"
                      loading={busy === item.id}
                      disabled={busy !== null && busy !== item.id}
                      onClick={() => void resend(item)}
                    >
                      原样重试
                    </Button>
                  )}
                {item.href && (
                  <RouteLink to={item.href} search={item.search}>
                    {item.kind === "write" ? "前往原页面" : "去处理"}
                  </RouteLink>
                )}
              </div>
            </li>
          ))}
        </ul>
      ) : loading ? (
        <div aria-busy="true">
          <Skeleton active paragraph={{ rows: 2 }} title={false} />
        </div>
      ) : (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description={
            read.length === 0
              ? "当前角色没有需要在这里处理的待办来源；本会话也没有结果未知的写入。"
              : complete
                ? "没有需要你处理的事项。"
                : "已读取的来源中没有待处理事项；有来源未能读取，见上方提示。"
          }
        />
      )}
    </section>
  );
}
