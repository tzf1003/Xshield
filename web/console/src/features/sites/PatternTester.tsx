// The rule tester (docs/06 6.4.9): a path is judged against the draft the way the gateway judges it. The
// same rules as the gateway's PathPattern are used (lib/patterns.ts), so an odd spelling is refused here too.

import { useState } from "react";
import { judgePath } from "../../lib/patterns.ts";

type Props = {
  entries: string[];
  bypass: string[];
  /** The saved rules, so a rule that only the draft has can be named as new. */
  savedEntries: string[];
  savedBypass: string[];
};

export function PatternTester({ entries, bypass, savedEntries, savedBypass }: Props) {
  const [path, setPath] = useState("");
  const trimmed = path.trim();
  let text: string | null = null;
  let tone = "muted";
  if (trimmed.length > 0) {
    if (!trimmed.startsWith("/")) {
      text = "路径必须以 / 开头";
      tone = "hint-bad";
    } else {
      const verdict = judgePath(trimmed, entries, bypass);
      if (verdict.kind === "invalid_spelling") {
        text = "网关不会把这种写法的路径匹配到任何入口或绕过（路径含 ; // %2e %2f 等写法）";
        tone = "hint-warn";
      } else if (verdict.kind === "bypass") {
        const fresh = savedBypass.includes(verdict.rule) ? "" : "（草稿新增）";
        text = `命中绕过 ${verdict.rule}：不判定，直接转发${fresh}`;
      } else if (verdict.kind === "entry") {
        const fresh = savedEntries.includes(verdict.rule) ? "" : "（草稿新增）";
        text = `命中入口 ${verdict.rule}${fresh}`;
      } else {
        text = "需要会话：没有命中入口或绕过，没有会话凭证的请求会被记为无会话";
      }
    }
  }
  return (
    <div className="stack-tight">
      <label className="field-label" htmlFor="site-rule-tester">
        规则测试
      </label>
      <input
        id="site-rule-tester"
        className="native-input mono"
        value={path}
        placeholder="输入一个路径，看它命中哪条规则，例如 /rest/admin/application-configuration"
        onChange={(event) => setPath(event.target.value)}
      />
      <div className={`small ${tone}`} role="status" aria-live="polite">
        {text ?? "输入路径后显示判定"}
      </div>
    </div>
  );
}
