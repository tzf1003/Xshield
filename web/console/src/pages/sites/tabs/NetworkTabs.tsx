import { Card, Form } from "antd";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";
import {
  EntryChoice,
  EntryPathField,
  ListenPortField,
  OriginField,
  ProbeFields,
  SiteIdFields,
  StatusChoice,
  UpstreamFields,
} from "./site-fields";

const off = (ws: WorkspaceApi) => ws.locked || !ws.access.canConfigure;

/** 网络: who the site is, where visitors arrive, where traffic goes and which port serves it. */
export function NetworkTab({ ws }: { ws: WorkspaceApi }) {
  if (!ws.draft) return null;
  return (
    <Form layout="vertical" className="xs-form" disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="站点标识" className="xs-card">
          <SiteIdFields ws={ws} />
        </Card>
        <Card title="公网入口" className="xs-card">
          <OriginField ws={ws} />
          <EntryPathField ws={ws} />
        </Card>
        <Card title="源站（上游）" className="xs-card">
          <UpstreamFields ws={ws} />
        </Card>
        <Card title="监听" className="xs-card">
          <ListenPortField ws={ws} />
        </Card>
      </div>
    </Form>
  );
}

/** 安全入口: who may enter, whether the site is served, the browser probe and the policy label. */
export function SecurityEntryTab({ ws }: { ws: WorkspaceApi }) {
  if (!ws.draft) return null;
  return (
    <Form layout="vertical" className="xs-form" disabled={off(ws)}>
      <div className="xs-cards">
        <Card title="入口准入" className="xs-card">
          <EntryChoice ws={ws} />
        </Card>
        <Card title="运行状态" className="xs-card">
          <StatusChoice ws={ws} />
        </Card>
        <Card title="探针与策略标签" className="xs-card">
          <ProbeFields ws={ws} />
        </Card>
      </div>
    </Form>
  );
}
