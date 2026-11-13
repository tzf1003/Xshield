import { ConfigProvider, theme as antdTheme } from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { type Density, palettes, type ThemeMode, type ThemePreference } from "./tokens.ts";

const THEME_KEY = "xshield.console.theme";
const DENSITY_KEY = "xshield.console.density";
const DARK_QUERY = "(prefers-color-scheme: dark)";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

type ThemeContextValue = {
  preference: ThemePreference;
  mode: ThemeMode;
  density: Density;
  setPreference: (value: ThemePreference) => void;
  setDensity: (value: Density) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string | null) {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    // Storage may be blocked; the preference then lasts for this page only.
  }
}

function mediaMatches(query: string): boolean {
  try {
    return window.matchMedia(query).matches;
  } catch {
    return false;
  }
}

/** Follows a media query for as long as the provider is mounted. */
function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(() => mediaMatches(query));
  useEffect(() => {
    let media: MediaQueryList | null = null;
    try {
      media = window.matchMedia(query);
    } catch {
      media = null;
    }
    if (!media) return undefined;
    const onChange = () => setMatches(media?.matches ?? false);
    media.addEventListener("change", onChange);
    return () => media?.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

function parsePreference(raw: string | null): ThemePreference {
  return raw === "light" || raw === "dark" ? raw : "system";
}

function parseDensity(raw: string | null): Density {
  return raw === "compact" ? "compact" : "comfortable";
}

/** Applied before the first render so a stored choice never flashes the other theme. */
export function applyStoredAttributes() {
  const preference = parsePreference(readStored(THEME_KEY));
  const root = document.documentElement;
  if (preference === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", preference);
  root.setAttribute("data-density", parseDensity(readStored(DENSITY_KEY)));
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(() =>
    parsePreference(readStored(THEME_KEY)),
  );
  const [density, setDensityState] = useState<Density>(() => parseDensity(readStored(DENSITY_KEY)));
  const dark = useMediaQuery(DARK_QUERY);
  const reducedMotion = useMediaQuery(REDUCED_MOTION_QUERY);

  const mode: ThemeMode = preference === "system" ? (dark ? "dark" : "light") : preference;

  useEffect(() => {
    const root = document.documentElement;
    if (preference === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", preference);
    root.setAttribute("data-density", density);
  }, [preference, density]);

  const setPreference = useCallback((value: ThemePreference) => {
    setPreferenceState(value);
    writeStored(THEME_KEY, value === "system" ? null : value);
  }, []);

  const setDensity = useCallback((value: Density) => {
    setDensityState(value);
    writeStored(DENSITY_KEY, value === "comfortable" ? null : value);
  }, []);

  const antdConfig = useMemo(() => {
    const palette = palettes[mode];
    return {
      algorithm: [
        mode === "dark" ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
        ...(density === "compact" ? [antdTheme.compactAlgorithm] : []),
      ],
      token: {
        colorPrimary: palette?.accent,
        colorBgBase: palette?.surface,
        colorTextBase: palette?.ink,
        colorBorder: palette?.borderStrong,
        borderRadius: 6,
        borderRadiusLG: 10,
        // Under reduced motion antd turns its own motion off too, so drawers and modals do not slide in.
        motion: !reducedMotion,
        fontFamily:
          'system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
      },
    };
  }, [mode, density, reducedMotion]);

  const value = useMemo(
    () => ({ preference, mode, density, setPreference, setDensity }),
    [preference, mode, density, setPreference, setDensity],
  );

  return (
    <ThemeContext.Provider value={value}>
      <ConfigProvider locale={zhCN} theme={antdConfig}>
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext);
  if (!value) throw new Error("useTheme outside ThemeProvider");
  return value;
}
