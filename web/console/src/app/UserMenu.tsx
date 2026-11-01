// The account menu (docs/06 6.3.2): theme, row height, and sign-out.

import { Button, Popover, Segmented } from "antd";
import type { Density, ThemePreference } from "../theme/tokens.ts";
import { useTheme } from "../theme/ThemeProvider.tsx";
import { useLogoutAction } from "./session-actions.ts";

export function UserMenu() {
  const theme = useTheme();
  const logout = useLogoutAction();

  const content = (
    <div className="stack" style={{ width: 240 }}>
      <div className="small muted">主题</div>
      <Segmented
        block
        value={theme.preference}
        options={[
          { label: "跟随系统", value: "system" },
          { label: "浅色", value: "light" },
          { label: "深色", value: "dark" },
        ]}
        onChange={(value) => theme.setPreference(value as ThemePreference)}
      />
      <div className="small muted">行高</div>
      <Segmented
        block
        value={theme.density}
        options={[
          { label: "紧凑", value: "compact" },
          { label: "舒适", value: "comfortable" },
        ]}
        onChange={(value) => theme.setDensity(value as Density)}
      />
      <Button danger onClick={() => void logout()}>
        退出登录
      </Button>
    </div>
  );

  return (
    <Popover trigger="click" placement="bottomRight" content={content} title="显示与账户">
      <button type="button" className="iconbtn" aria-label="用户菜单" title="显示与账户">
        ⋯
      </button>
    </Popover>
  );
}
