import { type ThemeConfig, theme as antdTheme } from "antd";
import { type DensityPreference, fonts, palettes, radii, type ThemeMode } from "./tokens.ts";

/**
 * antd theme derived from the same palette object as the CSS variable layer. Light and dark
 * use the stock algorithms with brand seed colours; compact density composes antd's compact
 * algorithm on top. The sidebar is dark in both modes, so its Menu tokens are mode-specific.
 */
export function antdThemeConfig(mode: ThemeMode, density: DensityPreference): ThemeConfig {
  const palette = palettes[mode];
  const algorithm = [mode === "dark" ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm];
  if (density === "compact") algorithm.push(antdTheme.compactAlgorithm);
  return {
    algorithm,
    cssVar: { key: "xshield" },
    hashed: false,
    token: {
      colorPrimary: palette.primary,
      colorInfo: palette.info,
      colorSuccess: palette.allow,
      colorWarning: palette.observe,
      colorError: palette.deny,
      colorLink: palette.primary,
      // Text on a solid primary fill: white on the light brand blue, ink on the dark one.
      colorTextLightSolid: palette.onPrimary,
      colorPrimaryHover: palette.primaryHover,
      colorPrimaryBg: palette.primarySoft,
      colorTextBase: palette.ink,
      colorBgBase: palette.surface,
      colorBgLayout: palette.canvas,
      colorBgContainer: palette.surface,
      colorBgElevated: palette.surface,
      colorText: palette.ink,
      colorTextSecondary: palette.ink2,
      colorTextTertiary: palette.ink3,
      colorTextDescription: palette.ink3,
      colorBorder: palette.lineStrong,
      colorBorderSecondary: palette.line,
      colorSplit: palette.line,
      fontFamily: fonts.sans,
      fontFamilyCode: fonts.mono,
      fontSize: 14,
      borderRadius: Number.parseInt(radii.control, 10),
      borderRadiusLG: Number.parseInt(radii.panel, 10),
      controlHeight: density === "compact" ? 32 : 36,
      motionDurationMid: "0.15s",
      wireframe: false,
    },
    components: {
      Layout: {
        bodyBg: palette.canvas,
        headerBg: palette.surface,
        headerHeight: 56,
        headerPadding: "0 24px",
        siderBg: palette.sidebar,
        triggerBg: palette.sidebarHover,
      },
      Menu: {
        darkItemBg: palette.sidebar,
        darkSubMenuItemBg: palette.sidebar,
        darkPopupBg: palette.sidebar,
        darkItemColor: palette.sidebarInk,
        darkItemHoverBg: palette.sidebarHover,
        darkItemHoverColor: palette.sidebarActiveInk,
        darkItemSelectedBg: palette.sidebarActive,
        darkItemSelectedColor: palette.sidebarActiveInk,
        darkGroupTitleColor: palette.sidebarInkMuted,
        itemSelectedColor: palette.primary,
        itemSelectedBg: palette.primarySoft,
        itemBorderRadius: 6,
        itemHeight: 38,
        iconSize: 16,
      },
      // antd's dark algorithm re-derives colorPrimary from the seed (#8098FF becomes #7084dc),
      // so the brand colour is pinned where it is drawn as a solid fill.
      Dropdown: {
        colorPrimary: palette.primary,
        controlItemBgActive: palette.primarySoft,
      },
      Button: {
        colorPrimary: palette.primary,
        colorPrimaryHover: palette.primaryHover,
        colorPrimaryActive: palette.primaryHover,
        primaryColor: palette.onPrimary,
      },
      Table: {
        headerBg: palette.surfaceSubtle,
        headerColor: palette.ink2,
        rowHoverBg: palette.primarySoft,
        borderColor: palette.line,
      },
      Tag: {
        defaultBg: palette.surfaceSubtle,
        defaultColor: palette.ink2,
      },
    },
  };
}
