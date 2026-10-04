import { CloseOutlined } from "@ant-design/icons";
import { Button, Drawer } from "antd";
import type { ReactNode } from "react";
import { Brand } from "./Brand";

/** Off-canvas navigation below 760px. Loaded on first use; closed it renders nothing. */
export function MobileDrawer({
  open,
  onClose,
  nav,
  scope,
}: {
  open: boolean;
  onClose: () => void;
  nav: ReactNode;
  scope: string;
}) {
  return (
    <Drawer
      open={open}
      onClose={onClose}
      placement="left"
      size={288}
      closable={false}
      className="xs-drawer"
      styles={{ body: { padding: 0 }, header: { display: "none" } }}
    >
      <aside aria-label="后台导航" className="xs-drawer-nav">
        <div className="xs-drawer-head">
          <Brand />
          <Button type="text" icon={<CloseOutlined />} aria-label="关闭导航" onClick={onClose} />
        </div>
        {nav}
        <p className="xs-drawer-scope">
          当前范围 <span className="mono">{scope}</span>
        </p>
      </aside>
    </Drawer>
  );
}
