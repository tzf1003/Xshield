import type { WorkspaceApi } from "../workspace/use-workspace.ts";
import { HealthPanel } from "./HealthPanel";
import { ApprovalCard } from "./release/ApprovalCard";
import { DangerZone } from "./release/DangerZone";
import { ReleaseActions } from "./release/ReleaseActions";
import { RevisionHistory } from "./release/RevisionHistory";
import { StateCard } from "./release/StateCard";
import { useRelease } from "./release/use-release.ts";
import "./release/release.css";

/**
 * 发布: what the edge serves next to what is staged, why a change needs approval, the release
 * actions the roles allow (each behind a dialog that shows the change and what happens next),
 * the revision history, an explicit health read, and, for administrators, site deletion. A role
 * without Observer sees the actions without the state and the server decides.
 */
export function ReleasesTab({ ws }: { ws: WorkspaceApi }) {
  const release = useRelease(ws);
  return (
    <section className="xs-releases" aria-label="站点发布">
      <StateCard ws={ws} release={release} />
      <ApprovalCard ws={ws} release={release} />
      <ReleaseActions ws={ws} release={release} />
      {ws.access.canObserve && <RevisionHistory ws={ws} />}
      {ws.access.canObserve && ws.siteId !== null && <HealthPanel siteId={ws.siteId} />}
      {ws.configQuery.data?.config && (
        <details className="xs-card">
          <summary>edge 配置投影（只读）</summary>
          <pre className="config-preview">
            {JSON.stringify(ws.configQuery.data.config.gateway_config, null, 2)}
          </pre>
        </details>
      )}
      <DangerZone ws={ws} />
    </section>
  );
}
