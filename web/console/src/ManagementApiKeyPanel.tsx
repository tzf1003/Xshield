import { useEffect, useState } from "react";
import type { ManagementApiKeyRecord, ManagementApiKeyResponse } from "./api";
import type { ControlClient } from "./api";

const capabilities = ["site.read", "site.create", "site.config.write", "site.config.validate", "site.config.apply_direct", "site.health.read", "site.rollback"];

export function ManagementApiKeyPanel({ client, tenantId, onNotice }: { client: ControlClient; tenantId: string; onNotice: (value: string) => void }) {
  const [keys, setKeys] = useState<ManagementApiKeyRecord[]>([]);
  const [displayName, setDisplayName] = useState("Juice Shop Agent");
  const [subject, setSubject] = useState("agent-juice-shop");
  const [siteId, setSiteId] = useState("site_juice");
  const [expiresAt, setExpiresAt] = useState(() => new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 16));
  const [selected, setSelected] = useState<string[]>(capabilities);
  const [issued, setIssued] = useState<ManagementApiKeyResponse | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => setKeys(await client.managementApiKeys());
  useEffect(() => { void load(); }, []);

  const create = async () => {
    setBusy(true);
    try {
      const response = await client.createManagementApiKey({
        display_name: displayName, subject, expires_at: new Date(expiresAt).toISOString(),
        scopes: [{ tenant_id: tenantId, site_id: siteId, capabilities: selected }],
      }, `key-create-${crypto.randomUUID()}`);
      setIssued(response);
      await load();
      onNotice("API Key 已创建，只显示本次明文。请立即复制保存。");
    } finally { setBusy(false); }
  };

  const revoke = async (apiKeyId: string) => {
    setBusy(true);
    try { await client.revokeManagementApiKey(apiKeyId, `key-revoke-${crypto.randomUUID()}`); await load(); onNotice("API Key 已撤销。"); }
    finally { setBusy(false); }
  };

  return <section className="panel" aria-label="管理 API Key">
    <div className="panel-heading"><div><h2>管理 API Key</h2><p className="muted">Key 绑定 tenant、site 和能力集合，明文只在创建成功时显示一次。</p></div><button className="outline" onClick={() => void load()} disabled={busy}>刷新</button></div>
    {issued && <div className="notice" role="alert"><strong>请立即复制 API Key：</strong><code className="mono">{issued.api_key}</code><button className="outline" onClick={() => void navigator.clipboard?.writeText(issued.api_key)}>复制</button><button className="text-button" onClick={() => setIssued(null)}>关闭</button></div>}
    <div className="form-grid">
      <label>名称<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={128} /></label>
      <label>Agent 主体<input value={subject} onChange={(event) => setSubject(event.target.value)} maxLength={256} /></label>
      <label>站点 ID<input value={siteId} onChange={(event) => setSiteId(event.target.value)} maxLength={128} /></label>
      <label>过期时间<input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
    </div>
    <fieldset><legend>能力</legend><div className="choice-grid">{capabilities.map((capability) => <label key={capability}><input type="checkbox" checked={selected.includes(capability)} onChange={(event) => setSelected((current) => event.target.checked ? [...current, capability] : current.filter((value) => value !== capability))} />{capability}</label>)}</div></fieldset>
    <div className="form-actions"><button onClick={() => void create()} disabled={busy || selected.length === 0}>创建 API Key</button></div>
    <div className="table-wrap"><table><thead><tr><th>前缀</th><th>名称</th><th>主体</th><th>状态</th><th>过期</th><th>最近使用</th><th /></tr></thead><tbody>{keys.map((key) => <tr key={key.api_key_id}><td className="mono">{key.key_prefix}</td><td>{key.display_name}</td><td className="mono">{key.subject}</td><td>{key.status}</td><td>{key.expires_at}</td><td>{key.last_used_at ?? "未使用"}</td><td><button className="text-button" disabled={busy || key.status !== "active"} onClick={() => void revoke(key.api_key_id)}>撤销</button></td></tr>)}</tbody></table></div>
  </section>;
}
