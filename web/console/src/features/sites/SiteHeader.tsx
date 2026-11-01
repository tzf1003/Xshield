// The header of a site page (docs/06 6.4.9): the name, the mode (an observing site shows when it started), the
// hosts and the origin, the gateway status of the current version, the mode switch, and a menu with copy,
// export and delete.

import { Link } from "@tanstack/react-router";
import type { MenuProps } from "antd";
import { Dropdown, Modal } from "antd";
import { useState } from "react";
import type { SiteDetail } from "../../api/types.ts";
import { fmtLocalDateTime } from "../../lib/format.ts";
import { specToJson, specToYaml } from "../../lib/yaml.ts";
import { PageHead } from "../../ui/Page.tsx";
import { rolloutListText } from "./rollout.ts";

const MENU_ITEMS: MenuProps["items"] = [
  { key: "copy", label: "复制为新站点" },
  { key: "yaml", label: "导出配置为 YAML" },
  { key: "json", label: "导出配置为 JSON" },
  { key: "delete", label: "删除站点", danger: true },
];

type Props = {
  site: SiteDetail;
  now: number;
  onSwitchMode: () => void;
  onCopy: () => void;
  onDelete: () => void;
  deleting: boolean;
};

/** Hands a text to the browser as a file. The text goes in a blob, never into the page as markup. */
function download(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function SiteHeader({ site, now, onSwitchMode, onCopy, onDelete, deleting }: Props) {
  const [confirming, setConfirming] = useState(false);
  const since = site.observing_since_millis;
  const status = rolloutListText(site.rollout, site.updated_at, now);
  const modeText =
    site.mode === "enforce"
      ? "拦截模式"
      : since === null
        ? "观察模式"
        : `观察模式（自 ${fmtLocalDateTime(since)} 起）`;

  const onMenu = (key: string) => {
    if (key === "copy") onCopy();
    else if (key === "yaml") download(`${site.name}.yaml`, specToYaml(site.spec), "text/yaml");
    else if (key === "json")
      download(`${site.name}.json`, specToJson(site.spec), "application/json");
    else if (key === "delete") setConfirming(true);
  };

  return (
    <>
      <PageHead
        title={site.name}
        crumbs={<Link to="/sites">站点</Link>}
        sub={
          <span className="site-sub small">
            <span className="pill">{modeText}</span>
            <span className="mono">{site.hosts.join("、")}</span>
            <span aria-hidden="true">→</span>
            <span className="mono">{site.origin}</span>
            <span>{status.text}</span>
          </span>
        }
        actions={
          <div className="row site-actions">
            <button type="button" className="btn" onClick={onSwitchMode}>
              {site.mode === "enforce" ? "切回观察模式…" : "切换到拦截模式…"}
            </button>
            <Dropdown
              menu={{ items: MENU_ITEMS, onClick: ({ key }) => onMenu(key) }}
              trigger={["click"]}
              placement="bottomRight"
            >
              <button type="button" className="iconbtn" aria-label="更多操作">
                ⋯
              </button>
            </Dropdown>
          </div>
        }
      />

      <Modal
        open={confirming}
        onCancel={() => setConfirming(false)}
        title={`删除站点 ${site.name}？`}
        width={460}
        footer={null}
      >
        <div className="stack">
          <div>删除后，网关不再按这个配置处理该站点的请求。</div>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn" onClick={() => setConfirming(false)}>
              取消
            </button>
            <button type="button" className="btn btn-danger" disabled={deleting} onClick={onDelete}>
              {deleting ? "正在删除…" : "删除站点"}
            </button>
          </div>
        </div>
      </Modal>
    </>
  );
}
