// The result of a connection test (design agent-model-ui 2.4). It stays under the form until the next test or until
// the page is left. The model's own error text is shown as untrusted text, folded away by default.

import type { TestLine } from "../../lib/model-form.ts";
import { MODEL_TEXT } from "../../lib/vocab.ts";

const TONE_CLASS = { ok: "hint-ok", warn: "hint-warn", bad: "hint-bad" } as const;

export function ModelTestResult({ line }: { line: TestLine | null }) {
  // The region is always present so a screen reader hears each new result (design 8).
  return (
    <div className="sys-test" role="status">
      {line === null ? null : (
        <>
          <div className={`sys-test-line ${TONE_CLASS[line.tone]}`}>
            <span aria-hidden="true">{line.icon}</span> {line.text}
          </div>
          {line.hint === undefined ? null : <div className="sys-test-hint">{line.hint}</div>}
          {line.detail === null || line.detail === "" ? null : (
            <details className="sys-test-detail">
              <summary>{MODEL_TEXT.testDetail}</summary>
              <pre className="mono small">{line.detail}</pre>
            </details>
          )}
        </>
      )}
    </div>
  );
}
