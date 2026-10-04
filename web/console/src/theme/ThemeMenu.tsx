import { BgColorsOutlined } from "@ant-design/icons";
import { Button, Dropdown, type MenuProps } from "antd";
import { type ThemeContextValue, useTheme } from "./ThemeProvider.tsx";
import type { DensityPreference, ThemePreference } from "./tokens.ts";

const themeLabels: Record<ThemePreference, string> = {
  system: "跟随系统",
  light: "浅色",
  dark: "深色",
};
const densityLabels: Record<DensityPreference, string> = {
  comfortable: "舒适",
  compact: "紧凑",
};

/** Choices shared by the stand-alone theme button and the user menu. */
export function themeChoiceItems(): NonNullable<MenuProps["items"]> {
  return (Object.keys(themeLabels) as ThemePreference[]).map((key) => ({
    key: `theme:${key}`,
    label: themeLabels[key],
  }));
}

export function densityChoiceItems(): NonNullable<MenuProps["items"]> {
  return (Object.keys(densityLabels) as DensityPreference[]).map((key) => ({
    key: `density:${key}`,
    label: densityLabels[key],
  }));
}

export function themeMenuItems(): NonNullable<MenuProps["items"]> {
  return [
    { type: "group", label: "主题", children: themeChoiceItems() },
    { type: "group", label: "密度", children: densityChoiceItems() },
  ];
}

export function selectedThemeKeys(theme: ThemeContextValue): string[] {
  return [`theme:${theme.preference}`, `density:${theme.density}`];
}

export function handleThemeMenuClick(theme: ThemeContextValue, key: string): boolean {
  const [group, value] = key.split(":");
  if (group === "theme" && value && value in themeLabels) {
    theme.setPreference(value as ThemePreference);
    return true;
  }
  if (group === "density" && value && value in densityLabels) {
    theme.setDensity(value as DensityPreference);
    return true;
  }
  return false;
}

export function ThemeMenu() {
  const theme = useTheme();
  return (
    <Dropdown
      trigger={["click"]}
      menu={{
        items: themeMenuItems(),
        selectable: true,
        selectedKeys: selectedThemeKeys(theme),
        onClick: ({ key }) => handleThemeMenuClick(theme, key),
      }}
    >
      <Button
        type="text"
        icon={<BgColorsOutlined />}
        aria-label="主题与密度"
        aria-haspopup="menu"
        title={`主题：${themeLabels[theme.preference]} · 密度：${densityLabels[theme.density]}`}
      />
    </Dropdown>
  );
}
