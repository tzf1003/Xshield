import { useEffect, useRef, useState } from "react";
import type { ControlClient } from "../api.ts";
import { isStaleSessionError } from "../security/errors.ts";
import { runGuardedRead } from "../security/guarded.ts";
import type { ScopedResponse } from "../security/scope.ts";
import { useSession } from "../security/SessionProvider";
import { withStepUp } from "./step-up.ts";
import { useStepUp } from "./WorkRoot";

export type Saved = Readonly<{ filename: string; bytes: number; requestId: string }>;

export type DownloadState =
  | { phase: "idle" }
  | { phase: "working" }
  | { phase: "saved"; saved: Saved }
  | { phase: "failed"; error: unknown };

type Downloaded = ScopedResponse & { blob: Blob; bytes: number; request_id: string };

export type AttachmentDownload = Readonly<{
  state: DownloadState;
  start: () => void;
}>;

/**
 * A bounded binary attachment, handed to the browser as a download and never rendered. The
 * response is validated by the client (headers, scope, target, exact length) before it gets here;
 * this hook adds what only the page can know:
 *
 *  - a different `target`, a new start or leaving the page discards a running download, and a
 *    response that arrives late is dropped without ever being saved;
 *  - 401, idle expiry and a cross-scope reply end the session through the guarded read;
 *  - the object URL lives for one second (long enough for the browser to start the download),
 *    is revoked then, and is revoked at once when the download is discarded;
 *  - an MFA step-up request pauses the same download, then repeats it for the same target.
 */
export function useAttachmentDownload<T extends Downloaded>(options: {
  target: string;
  fetch: (client: ControlClient, signal: AbortSignal) => Promise<T>;
  filename: (response: T) => string;
  /** After the browser was handed the file (for example to re-read a claim counter). */
  onSaved?: () => void;
}): AttachmentDownload {
  const { runtime } = useSession();
  const stepUp = useStepUp();
  const [state, setState] = useState<DownloadState>({ phase: "idle" });
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const object = useRef<{ href: string; timer: number } | null>(null);

  function revoke() {
    if (!object.current) return;
    window.clearTimeout(object.current.timer);
    URL.revokeObjectURL(object.current.href);
    object.current = null;
  }

  function discard() {
    generation.current += 1;
    controller.current?.abort();
    controller.current = null;
    revoke();
  }

  useEffect(() => {
    void options.target;
    setState({ phase: "idle" });
    return () => {
      generation.current += 1;
      controller.current?.abort();
      controller.current = null;
      if (object.current) {
        window.clearTimeout(object.current.timer);
        URL.revokeObjectURL(object.current.href);
        object.current = null;
      }
    };
  }, [options.target]);

  function save(blob: Blob, filename: string) {
    revoke();
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = filename;
    link.hidden = true;
    document.body.appendChild(link);
    try {
      link.click();
    } finally {
      link.remove();
      object.current = { href, timer: window.setTimeout(revoke, 1000) };
    }
  }

  function start() {
    discard();
    const mine = generation.current;
    const abort = new AbortController();
    controller.current = abort;
    setState({ phase: "working" });
    runGuardedRead(runtime.store, {
      fetch: (client, signal) => withStepUp(stepUp, signal, () => options.fetch(client, signal)),
      signal: abort.signal,
    }).then(
      (response) => {
        if (generation.current !== mine) return;
        const filename = options.filename(response);
        save(response.blob, filename);
        setState({
          phase: "saved",
          saved: { filename, bytes: response.bytes, requestId: response.request_id },
        });
        options.onSaved?.();
      },
      (error: unknown) => {
        if (generation.current !== mine || isStaleSessionError(error)) return;
        setState({ phase: "failed", error });
      },
    );
  }

  return { state, start };
}
