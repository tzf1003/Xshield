/**
 * Single source of truth for the console's visual language.
 *
 * Both the antd `ThemeConfig` (src/theme/antd.ts) and the static CSS variable layer
 * (src/theme/tokens.generated.css, produced by `npm run theme:css`) are derived from the
 * objects below, so legacy stylesheets and antd components can never drift apart. Hex values
 * are the brand palette; contrast requirements are enforced by tests/theme.test.ts.
 */
export type ThemeMode = "light" | "dark";
export type ThemePreference = "system" | ThemeMode;
export type DensityPreference = "comfortable" | "compact";

export type Palette = {
  /** Page background behind panels. */
  canvas: string;
  /** Panels, inputs and table bodies. */
  surface: string;
  /** Table headers, read-only cells, quiet wells. */
  surfaceSubtle: string;
  line: string;
  lineStrong: string;
  /** Primary text. */
  ink: string;
  /** Secondary text (labels, captions). */
  ink2: string;
  /** Tertiary text (hints, timestamps). Still AA on every surface. */
  ink3: string;
  primary: string;
  primaryHover: string;
  primarySoft: string;
  /** Text drawn on a solid primary fill. */
  onPrimary: string;
  sidebar: string;
  sidebarInk: string;
  sidebarInkMuted: string;
  sidebarLine: string;
  sidebarHover: string;
  sidebarActive: string;
  sidebarActiveInk: string;
  /** Request decided ALLOW / succeeded. */
  allow: string;
  allowSoft: string;
  allowLine: string;
  /** Request decided DENY / failed. */
  deny: string;
  denySoft: string;
  denyLine: string;
  /** Observe, pending or awaiting approval. */
  observe: string;
  observeSoft: string;
  observeLine: string;
  /** Informational, indexed. */
  info: string;
  infoSoft: string;
  infoLine: string;
  /** Unknown, unavailable, not applicable. */
  unknown: string;
  unknownSoft: string;
  unknownLine: string;
  overlay: string;
  shadow: string;
};

export const palettes: Record<ThemeMode, Palette> = {
  light: {
    canvas: "#F2F4F8",
    surface: "#FFFFFF",
    surfaceSubtle: "#F6F8FB",
    line: "#DCE2EC",
    lineStrong: "#C5CEDD",
    ink: "#121A2B",
    ink2: "#47536C",
    ink3: "#5F6B84",
    primary: "#3550D4",
    primaryHover: "#2A42B8",
    primarySoft: "#E9EDFC",
    onPrimary: "#FFFFFF",
    sidebar: "#0F1A33",
    sidebarInk: "#C9D3EA",
    sidebarInkMuted: "#8F9CBB",
    sidebarLine: "#1D2A4A",
    sidebarHover: "#19284A",
    sidebarActive: "#3550D4",
    sidebarActiveInk: "#FFFFFF",
    allow: "#167A42",
    allowSoft: "#E2F3E9",
    allowLine: "#B5DDC5",
    deny: "#C2303B",
    denySoft: "#FBE8EA",
    denyLine: "#F0B8BD",
    observe: "#A35F0A",
    observeSoft: "#FCF3E4",
    observeLine: "#EAD2A4",
    info: "#1F6FB8",
    infoSoft: "#EAF3FB",
    infoLine: "#BBD6EE",
    unknown: "#5F6B84",
    unknownSoft: "#EEF0F5",
    unknownLine: "#CFD5E0",
    overlay: "rgba(15, 26, 51, 0.45)",
    shadow: "0 1px 2px rgba(18, 26, 43, 0.06)",
  },
  dark: {
    canvas: "#0A0F1C",
    surface: "#111929",
    surfaceSubtle: "#162036",
    line: "#243049",
    lineStrong: "#34425F",
    ink: "#E6EBF4",
    ink2: "#B3BDD0",
    ink3: "#94A0B6",
    primary: "#8098FF",
    primaryHover: "#9AADFF",
    primarySoft: "#1C2547",
    onPrimary: "#0A0F1C",
    sidebar: "#070C17",
    sidebarInk: "#C9D3EA",
    sidebarInkMuted: "#8895B3",
    sidebarLine: "#162037",
    sidebarHover: "#111B31",
    sidebarActive: "#1C2547",
    sidebarActiveInk: "#FFFFFF",
    allow: "#4FC37E",
    allowSoft: "#12301F",
    allowLine: "#24563A",
    deny: "#F2767F",
    denySoft: "#3A1B20",
    denyLine: "#6A2F37",
    observe: "#E5A84C",
    observeSoft: "#382A10",
    observeLine: "#66501F",
    info: "#6CB0F0",
    infoSoft: "#112B44",
    infoLine: "#24527D",
    unknown: "#94A0B6",
    unknownSoft: "#1D273B",
    unknownLine: "#34425F",
    overlay: "rgba(2, 5, 12, 0.66)",
    shadow: "0 1px 2px rgba(0, 0, 0, 0.45)",
  },
};

export const fonts = {
  /** IBM Plex Sans for Latin and digits; the system CJK stack renders Chinese. */
  sans: '"IBM Plex Sans", "PingFang SC", "Microsoft YaHei", "Noto Sans SC", -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif',
  /** JetBrains Mono for IDs, hashes and codes. */
  mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
} as const;

/** Legacy stylesheets read these; antd's own compact algorithm covers antd components. */
export const densities: Record<DensityPreference, Record<string, string>> = {
  comfortable: {
    controlHeight: "40px",
    controlHeightSm: "32px",
    cellPaddingY: "14px",
    cellPaddingX: "15px",
    panelPadding: "22px",
    pageGutter: "32px",
  },
  compact: {
    controlHeight: "32px",
    controlHeightSm: "28px",
    cellPaddingY: "8px",
    cellPaddingX: "12px",
    panelPadding: "16px",
    pageGutter: "24px",
  },
};

export const radii = { control: "6px", panel: "8px" } as const;
