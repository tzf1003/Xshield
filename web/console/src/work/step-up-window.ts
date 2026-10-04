/**
 * The browser side of the in-place step-up: a separate window runs the OIDC re-authentication,
 * and when the identity provider sends it back to the console root the console, instead of
 * rendering itself in that window, tells the opener over a same-origin channel and closes it.
 * The hint carries nothing: the opener re-reads the server session, which is the only proof.
 */
import type { StepUpWindow } from "./step-up.ts";

export const STEP_UP_WINDOW_NAME = "xshield-step-up";
const CHANNEL = "xshield-step-up";

/** Opens a blank window synchronously (call it from a click). `null` when the browser blocked it. */
export function openVerificationWindow(): StepUpWindow | null {
  const win = window.open("about:blank", STEP_UP_WINDOW_NAME, "popup=yes,width=520,height=720");
  if (!win) return null;
  return {
    navigate(url) {
      win.location.href = url;
    },
    close() {
      win.close();
    },
    isClosed() {
      return win.closed;
    },
  };
}

export function listenForVerificationReturn(listener: () => void): () => void {
  if (typeof BroadcastChannel === "undefined") return () => {};
  const channel = new BroadcastChannel(CHANNEL);
  channel.onmessage = (event: MessageEvent) => {
    const data: unknown = event.data;
    if (
      typeof data === "object" &&
      data !== null &&
      (data as { type?: unknown }).type === "returned"
    )
      listener();
  };
  return () => channel.close();
}

/** True in the verification window once the identity provider has sent it back to the console. */
export function isVerificationReturn(win: Pick<Window, "name">): boolean {
  return win.name === STEP_UP_WINDOW_NAME;
}

/** Tells the opener, shows a plain note and closes the window. Renders nothing else. */
export function completeVerificationReturn(win: Window): void {
  try {
    const channel = new BroadcastChannel(CHANNEL);
    channel.postMessage({ type: "returned" });
    channel.close();
  } catch {
    // Without a channel the operator uses "我已完成，重新检查" in the opener.
  }
  const note = win.document.createElement("p");
  note.textContent = "验证流程已结束，正在关闭此窗口；请回到控制台继续。";
  note.style.cssText = "font: 14px sans-serif; padding: 24px";
  win.document.body.replaceChildren(note);
  win.close();
}
