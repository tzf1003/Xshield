// Colour and type tokens (docs/06 6.5). Light and dark are two palettes, chosen separately rather
// than inverted. The CSS variables in global.css carry the same values; antd reads them from here.

export type ThemeMode = "light" | "dark";
export type ThemePreference = "system" | ThemeMode;
export type Density = "comfortable" | "compact";

export const palettes: Record<ThemeMode, Record<string, string>> = {
  light: {
    page: "#f9f9f7",
    surface: "#fcfcfb",
    sunken: "#f3f2ef",
    border: "rgba(11,11,11,0.10)",
    borderStrong: "rgba(11,11,11,0.18)",
    ink: "#0b0b0b",
    ink2: "#52514e",
    ink3: "#6f6d68",
    accent: "#256abf",
    accentFill: "#256abf",
    accentWeak: "rgba(37,106,191,0.12)",
    grid: "#e1e0d9",
    axis: "#c3c2b7",
    s1: "#2a78d6",
    s2: "#eb6834",
    s3: "#1baf7a",
    neutralSeg: "#a19f98",
  },
  dark: {
    page: "#0d0d0d",
    surface: "#1a1a19",
    sunken: "#222220",
    border: "rgba(255,255,255,0.10)",
    borderStrong: "rgba(255,255,255,0.18)",
    ink: "#f0efec",
    ink2: "#c3c2b7",
    ink3: "#9c9a93",
    accent: "#5598e7",
    accentFill: "#256abf",
    accentWeak: "rgba(85,152,231,0.18)",
    grid: "#2c2c2a",
    axis: "#383835",
    s1: "#3987e5",
    s2: "#d95926",
    s3: "#199e70",
    neutralSeg: "#6b6a65",
  },
};

export const density = {
  comfortable: { row: 40, control: 36 },
  compact: { row: 32, control: 32 },
} as const;
