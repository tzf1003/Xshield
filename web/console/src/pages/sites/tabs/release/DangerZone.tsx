import { Button, Input, Modal } from "antd";
import { useId, useState } from "react";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";
import { StepUpNotice } from "./StepUpNotice";
import { useStepUpAdvice } from "./use-step-up.ts";

function DeleteBody({
  siteId,
  port,
  typed,
  onTyped,
}: {
  siteId: string;
  port: number | null;
  typed: string;
  onTyped: (value: string) => void;
}) {
  const inputId = useId();
  // Only a definite mismatch is an error; a correct start is just not finished yet.
  const mismatch = typed !== "" && !siteId.startsWith(typed);
  return (
    <>
      <ul className="xs-consequences">
        <li>
          站点会先暂停，等 edge 确认已经停止服务它之后才真正删除。edge
          不可用时，站点停在“暂停”，edge 仍按旧快照服务，删除没有完成，可以稍后重试。
        </li>
        <li>
          监听端口{port === null ? "" : ` ${port}`}
          随之释放；站点配置不能再从控制台读取，也不能恢复。
        </li>
        <li>删除需要 2 分钟内完成的 MFA 再认证；本地机器凭证不能删除站点。</li>
        <li>这次操作写入审计记录。</li>
      </ul>
      <div className="xs-delete-confirm">
        <label htmlFor={inputId}>
          输入站点 ID <strong className="mono">{siteId}</strong> 以确认删除
        </label>
        <Input
          id={inputId}
          value={typed}
          onChange={(event) => onTyped(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          status={mismatch ? "error" : undefined}
          aria-invalid={mismatch}
          placeholder={siteId}
        />
        {mismatch && <small className="xs-delete-mismatch">与站点 ID 不一致。</small>}
      </div>
    </>
  );
}

/**
 * Deleting a site takes it off the edge for good, so it sits apart from the release actions and
 * needs the site's ID typed out. The server also demands a fresh MFA step-up; a refusal for that
 * keeps the request, and the pending banner repeats it unchanged after re-verifying.
 */
export function DangerZone({ ws }: { ws: WorkspaceApi }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const advice = useStepUpAdvice(open);
  if (!ws.access.canConfigure || ws.siteId === null) return null;
  const siteId = ws.siteId;

  function close() {
    setOpen(false);
    setTyped("");
  }
  function confirm() {
    close();
    void ws.run("delete", () => ws.writes.remove.submit({}));
  }

  return (
    <section className="xs-card xs-danger" aria-label="危险操作">
      <h3>危险操作</h3>
      <p>
        删除站点会让 edge 停止服务它并释放监听端口。这个操作不能撤销，所以需要输入站点 ID 并完成 MFA
        再认证。
      </p>
      <Button danger disabled={ws.locked} onClick={() => setOpen(true)}>
        删除站点
      </Button>
      <Modal
        open={open}
        onCancel={close}
        title={`删除站点 ${siteId}`}
        width={640}
        destroyOnHidden
        footer={
          <>
            <Button onClick={close}>取消</Button>
            <Button
              type="primary"
              danger
              disabled={ws.locked || typed !== siteId}
              onClick={confirm}
            >
              确认删除
            </Button>
          </>
        }
      >
        <DeleteBody
          siteId={siteId}
          port={ws.saved?.listen_port ?? null}
          typed={typed}
          onTyped={setTyped}
        />
        <StepUpNotice
          advice={advice}
          action="删除站点"
          machine="当前是本地机器凭证登录：服务端不允许机器凭证删除站点（它没有 MFA 再认证路径），请改用 OIDC 登录的管理会话。"
        />
      </Modal>
    </section>
  );
}
