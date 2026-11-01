// The two status lights of the top bar (docs/06 6.3.2). Both read GET /api/status every 15 seconds
// (useStatus). The colour always comes with a word; a click opens the list behind the word, with a
// link to the page that explains each line.

import { Link } from "@tanstack/react-router";
import { Popover } from "antd";
import type { ReactNode } from "react";
import { useStatus } from "../api/queries.ts";
import type { GatewayProblem } from "../api/types.ts";
import { gatewayLight, jevLight, type Light, problemText } from "../lib/health.ts";
import { isSiteName } from "../lib/ids.ts";
import { keepScope } from "./scope.ts";

function dotClass(light: Light): string {
  if (light.tone === "unknown") return "dot-neutral";
  return `dot-${light.tone}`;
}

/** The page that explains one problem: its gap window, its site, or the system page. */
function problemLink(problem: GatewayProblem): ReactNode {
  if (problem.kind === "log_gap") {
    return (
      <Link
        to="/requests"
        search={{ range: "custom", since: problem.from_ms, until: problem.to_ms }}
      >
        查看这段请求
      </Link>
    );
  }
  if (
    (problem.kind === "site_load_failed" || problem.kind === "version_behind") &&
    isSiteName(problem.site)
  ) {
    return (
      <Link to="/sites/$name" params={{ name: problem.site }} search={{ tab: "config" }}>
        打开配置
      </Link>
    );
  }
  return (
    <Link to="/system" search={keepScope}>
      查看系统
    </Link>
  );
}

function GatewayDetail({ problems }: { problems: GatewayProblem[] }) {
  return (
    <div className="stack" style={{ gap: 6 }}>
      {problems.length === 0 ? <div className="small">没有问题</div> : null}
      {problems.map((problem) => (
        <div key={problemText(problem)} className="small">
          {problemText(problem)} · {problemLink(problem)}
        </div>
      ))}
      <div>
        <Link to="/system" search={keepScope}>
          查看系统
        </Link>
      </div>
    </div>
  );
}

function LightButton({ light, detail }: { light: Light; detail: ReactNode }) {
  return (
    <Popover
      trigger="click"
      placement="bottomRight"
      title={light.label}
      content={
        <div className="stack" style={{ width: 320 }}>
          {detail}
        </div>
      }
    >
      <button type="button" className="light" aria-label={light.label}>
        <span className={`dot ${dotClass(light)}`} aria-hidden="true" />
        {light.label}
      </button>
    </Popover>
  );
}

export function Lights() {
  const status = useStatus();
  const gateway = gatewayLight(status.data);
  const jev = jevLight(status.data?.jev);
  const problems = status.data?.gateway.problems ?? [];
  return (
    <div className="lights">
      <LightButton light={gateway} detail={<GatewayDetail problems={problems} />} />
      <LightButton
        light={jev}
        detail={
          <div className="stack" style={{ gap: 4 }}>
            {jev.lines.map((line) => (
              <div key={line} className="small">
                {line}
              </div>
            ))}
            <div>
              <Link to="/jev" search={keepScope}>
                查看 Jev 调用
              </Link>
            </div>
          </div>
        }
      />
    </div>
  );
}
