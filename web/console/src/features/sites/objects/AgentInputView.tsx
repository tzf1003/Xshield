// The question the agent was given, as JSON (console design 3.1 and 3.4): the positions, their flows and the candidate
// kinds, never values. It is shown as text in a block the administrator can copy, to judge why the agent chose as it did.

import { useState } from "react";
import { OBJECT_AGENT_TEXT } from "../../../lib/vocab.ts";

export function AgentInputView({ input }: { input: unknown }) {
  const [copied, setCopied] = useState(false);
  const text = JSON.stringify(input, null, 2) ?? "";

  const copy = () => {
    try {
      void navigator.clipboard.writeText(text).then(
        () => setCopied(true),
        () => setCopied(false),
      );
    } catch {
      setCopied(false);
    }
  };

  return (
    <section className="obj-agent-input" aria-label={OBJECT_AGENT_TEXT.inputTitle}>
      <div className="obj-agent-input-bar">
        <button type="button" className="linkbtn" onClick={copy}>
          {copied ? OBJECT_AGENT_TEXT.copied : OBJECT_AGENT_TEXT.copy}
        </button>
      </div>
      <pre className="obj-agent-input-text">{text}</pre>
    </section>
  );
}
