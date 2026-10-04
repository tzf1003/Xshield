import { Button, Popconfirm, Popover } from "antd";
import { useState } from "react";
import { groupChanges, groupLabel } from "../../../sites/model/diff.ts";
import { DiffModal } from "../DiffView";
import type { WorkspaceApi } from "./use-workspace.ts";

/**
 * Sticks to the bottom while anything is unsaved, whichever section the operator is in: how
 * many edits, in which sections, what is blocking the save, and the three things to do about
 * it. 保存草稿 stores a new revision; whether and when the edge serves it is the release page's
 * business, and the bar says so.
 */
export function ChangeBar({ ws, onGo }: { ws: WorkspaceApi; onGo: (section: string) => void }) {
  const [diffOpen, setDiffOpen] = useState(false);
  if (!ws.dirty || !ws.access.canConfigure) return null;

  const grouped = groupChanges(ws.changes);
  const total = ws.changes.length + (ws.creating && ws.newSiteId !== "" ? 1 : 0);
  const problems = ws.errors;
  const label = ws.creating ? "创建站点" : "保存草稿";
  return (
    <section className="xs-change-bar" aria-label="未保存的修改">
      <div className="xs-change-summary">
        <strong>{total} 项未保存修改</strong>
        <span className="xs-change-groups">
          {[...grouped].map(([group, items]) => (
            <button
              type="button"
              key={group}
              className="xs-change-chip"
              onClick={() => onGo(group)}
              title={`转到“${groupLabel[group]}”`}
            >
              {groupLabel[group]} {items.length}
            </button>
          ))}
        </span>
        {problems.length > 0 && (
          <Popover
            trigger="click"
            title="需要先修正"
            content={
              <ul className="xs-issue-list">
                {problems.map((issue) => (
                  <li key={`${issue.path}-${issue.message}`}>
                    <button type="button" className="text-button" onClick={() => onGo(issue.group)}>
                      {groupLabel[issue.group]}
                    </button>
                    ：{issue.message}
                  </li>
                ))}
              </ul>
            }
          >
            <Button type="link" size="small" danger>
              {problems.length} 项需要修正
            </Button>
          </Popover>
        )}
      </div>
      <div className="xs-change-actions">
        <Popconfirm
          title="放弃全部未保存的修改？"
          okText="放弃"
          cancelText="继续编辑"
          okButtonProps={{ danger: true }}
          onConfirm={ws.discard}
        >
          <Button disabled={ws.locked}>放弃</Button>
        </Popconfirm>
        <Button onClick={() => setDiffOpen(true)}>查看差异</Button>
        <Button
          type="primary"
          loading={ws.running}
          disabled={ws.locked || problems.length > 0}
          onClick={() => void ws.save()}
        >
          {label}
        </Button>
      </div>
      <DiffModal
        open={diffOpen}
        onClose={() => setDiffOpen(false)}
        title="未保存修改的差异"
        caption={
          ws.creating
            ? "对比：新站点的默认配置 → 当前草稿。"
            : `对比：已保存的 r${ws.view.desired_revision ?? "?"} → 当前草稿。保存会生成新修订；是否需要审批、何时生效见“发布”。`
        }
        changes={ws.changes}
      />
    </section>
  );
}
