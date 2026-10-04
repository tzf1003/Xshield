import { useCallback, useEffect, useState } from "react";
import { refreshSessionInfo } from "../../../../security/session-queries.ts";
import { useSession } from "../../../../security/SessionProvider";
import { type StepUpStatus, stepUpStatus } from "../../../../shell/step-up.ts";

export type StepUpAdvice = Readonly<{
  /** Only a browser session has a step-up; the local machine credential never does. */
  applicable: boolean;
  status: StepUpStatus;
  /** The last thing the operator should know about re-verifying (a failed check, a refusal). */
  note: string | null;
  checking: boolean;
  /** Leaves for the identity provider; the page is reloaded when the operator returns. */
  reauthenticate: () => void;
  /** Reads the session again, for a re-verification that happened in another window. */
  recheck: () => Promise<void>;
}>;

/**
 * What the console knows about the MFA step-up that approving and deleting need. It is advisory
 * only: the server re-checks every call, so a stale reading can never make an action unsafe, only
 * unnecessarily alarming. `active` is true while a dialog that depends on it is open; the clock
 * only ticks then.
 */
export function useStepUpAdvice(active: boolean): StepUpAdvice {
  const { runtime, state, reauthenticate: startReauthentication } = useSession();
  const session = state.session;
  const [now, setNow] = useState(() => Date.now());
  const [note, setNote] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const status: StepUpStatus = session
    ? stepUpStatus(session, now)
    : { valid: false, remainingMs: null };
  const counting = active && status.valid && status.remainingMs !== null;
  useEffect(() => {
    if (!counting) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [counting]);

  const reauthenticate = useCallback(() => {
    setNote(null);
    void startReauthentication().then((message) => {
      if (message) setNote(message);
    });
  }, [startReauthentication]);

  const recheck = useCallback(async () => {
    setNote(null);
    setChecking(true);
    try {
      const fresh = await refreshSessionInfo(runtime);
      setNow(Date.now());
      if (fresh === null) return;
      if (!stepUpStatus(fresh, Date.now()).valid) {
        setNote("尚未检测到有效的 MFA 再认证。");
      }
    } catch {
      setNote("无法读取会话状态，请稍后重试。");
    } finally {
      setChecking(false);
    }
  }, [runtime]);

  return { applicable: session !== null, status, note, checking, reauthenticate, recheck };
}
