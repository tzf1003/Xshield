// The rule tester of the entries and bypass (docs/06 6.4.9): a path is judged against the draft the way the gateway
// judges it, with the same rules as the gateway's PathPattern (lib/patterns.ts). A whole HTTP request can be pasted
// too: it is judged on its logical path when an interface-name rule names it (RouteRuleTester reads it the same way).

import { useState } from "react";
import type { RouteRule } from "../../api/types.ts";
import { TestLines, testView } from "./RouteRuleTester.tsx";

type Props = {
  entries: string[];
  bypass: string[];
  routes: RouteRule[];
  /** The saved rules, so a rule that only the draft has can be named as new. */
  savedEntries: string[];
  savedBypass: string[];
};

export function PatternTester({ entries, bypass, routes, savedEntries, savedBypass }: Props) {
  const [text, setText] = useState("");
  const view = testView(text, { routes, entries, bypass, savedEntries, savedBypass });
  return (
    <div className="stack-tight">
      <label className="field-label" htmlFor="site-rule-tester">
        规则测试
      </label>
      <textarea
        id="site-rule-tester"
        className="native-input mono"
        rows={2}
        value={text}
        placeholder="输入一个路径，看它命中哪条规则，例如 /rest/admin/application-configuration"
        onChange={(event) => setText(event.target.value)}
      />
      <div className="small" role="status" aria-live="polite">
        <TestLines view={view} placeholder="输入路径后显示判定" />
      </div>
    </div>
  );
}
