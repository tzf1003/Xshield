import { Alert, Button, Modal, Space, Spin } from "antd";
import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
} from "react";
import { useSession } from "../security/SessionProvider";
import { refreshSessionInfo } from "../security/session-queries.ts";
import { StepUpCoordinator } from "./step-up.ts";
import { listenForVerificationReturn, openVerificationWindow } from "./step-up-window.ts";
import "./work.css";

const StepUpContext = createContext<StepUpCoordinator | null>(null);

export function useStepUp(): StepUpCoordinator {
  const value = useContext(StepUpContext);
  if (!value) throw new Error("useStepUp requires WorkRoot");
  return value;
}

/**
 * Every case and approval page renders inside this root. It owns the in-place step-up: while an
 * attempt waits for MFA, one dialog explains what is happening and what happens next. Leaving
 * the page cancels the wait, so a refused request never fires later in the background.
 */
export function WorkRoot({ children }: { children: ReactNode }) {
  const { runtime } = useSession();
  const [coordinator] = useState(
    () =>
      new StepUpCoordinator({
        available: () => runtime.store.getState().session !== null,
        openWindow: openVerificationWindow,
        start: (signal) => {
          const client = runtime.store.getState().client;
          if (!client) return Promise.reject(new Error("管理会话已结束。"));
          return client.startReauthentication(signal);
        },
        check: async () => (await refreshSessionInfo(runtime))?.step_up_valid === true,
        listen: listenForVerificationReturn,
      }),
  );
  useEffect(() => coordinator.attach(), [coordinator]);
  return (
    <StepUpContext.Provider value={coordinator}>
      <div className="xs-w">{children}</div>
      <StepUpDialog coordinator={coordinator} />
    </StepUpContext.Provider>
  );
}

function StepUpDialog({ coordinator }: { coordinator: StepUpCoordinator }) {
  const state = useSyncExternalStore(coordinator.subscribe, coordinator.getState);
  const busy = state.phase === "opening" || state.phase === "checking";
  return (
    <Modal
      open={state.phase !== "idle"}
      title="需要 MFA 再认证"
      onCancel={() => coordinator.cancel()}
      mask={{ closable: false }}
      keyboard={false}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={() => coordinator.cancel()}>取消，不再继续</Button>
          {state.phase === "needed" && (
            <Button type="primary" onClick={() => coordinator.begin()}>
              在新窗口验证
            </Button>
          )}
          {(state.phase === "waiting" || state.phase === "needed") && (
            <Button
              type={state.phase === "waiting" ? "primary" : "default"}
              onClick={() => void coordinator.recheck()}
            >
              我已完成，重新检查
            </Button>
          )}
        </Space>
      }
    >
      <div className="xs-w-stack" role="status" aria-live="polite">
        <p>
          服务端要求最近 2 分钟内的 MFA 再认证后才能继续。请在新窗口完成验证；验证通过后，
          <strong>原请求（相同的幂等键与内容）会自动重新发送</strong>，无需重新填写。
        </p>
        {busy && (
          <p>
            <Spin size="small" />{" "}
            {state.phase === "opening" ? "正在打开验证窗口…" : "正在确认再认证状态…"}
          </p>
        )}
        {state.phase === "waiting" && (
          <p>验证窗口已打开，完成 MFA 后会自动继续；也可手动重新检查。</p>
        )}
        {state.message && <Alert type="warning" showIcon title={state.message} />}
        <p className="xs-w-muted">
          发起再认证需要 SensitiveEvidenceReader
          角色；机器凭证无法完成再认证。取消后本次请求不会发送， 也没有任何内容被写入。
        </p>
      </div>
    </Modal>
  );
}
