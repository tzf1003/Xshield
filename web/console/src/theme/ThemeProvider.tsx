import { ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useState,
} from "react";
import { antdThemeConfig } from "./antd.ts";
import {
  documentAttributes,
  preferenceStorage,
  readDensityPreference,
  readThemePreference,
  resolveThemeMode,
  writeDensityPreference,
  writeThemePreference,
} from "./preference.ts";
import type { DensityPreference, ThemeMode, ThemePreference } from "./tokens.ts";

const darkQuery = "(prefers-color-scheme: dark)";

export type ThemeContextValue = {
  preference: ThemePreference;
  /** The mode actually rendered (the system preference resolved). */
  mode: ThemeMode;
  density: DensityPreference;
  setPreference: (value: ThemePreference) => void;
  setDensity: (value: DensityPreference) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

function systemPrefersDark(): boolean {
  try {
    return typeof window !== "undefined" && window.matchMedia(darkQuery).matches;
  } catch {
    return false;
  }
}

function applyAttributes(preference: ThemePreference, density: DensityPreference) {
  const attributes = documentAttributes(preference, density);
  const root = document.documentElement;
  if (attributes.theme) root.setAttribute("data-theme", attributes.theme);
  else root.removeAttribute("data-theme");
  if (attributes.density) root.setAttribute("data-density", attributes.density);
  else root.removeAttribute("data-density");
}

/** Runs before the first React render so an explicit choice never flashes the other theme. */
export function applyStoredThemeAttributes() {
  const storage = preferenceStorage();
  applyAttributes(readThemePreference(storage), readDensityPreference(storage));
}

export function ThemeProvider({ children, cspNonce }: { children: ReactNode; cspNonce?: string }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(() =>
    readThemePreference(preferenceStorage()),
  );
  const [density, setDensityState] = useState<DensityPreference>(() =>
    readDensityPreference(preferenceStorage()),
  );
  const [systemDark, setSystemDark] = useState(systemPrefersDark);

  useEffect(() => {
    let query: MediaQueryList;
    try {
      query = window.matchMedia(darkQuery);
    } catch {
      return;
    }
    const onChange = () => setSystemDark(query.matches);
    onChange();
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  useLayoutEffect(() => applyAttributes(preference, density), [preference, density]);

  const setPreference = useCallback((value: ThemePreference) => {
    setPreferenceState(value);
    writeThemePreference(preferenceStorage(), value);
  }, []);
  const setDensity = useCallback((value: DensityPreference) => {
    setDensityState(value);
    writeDensityPreference(preferenceStorage(), value);
  }, []);

  const mode = resolveThemeMode(preference, systemDark);
  const antd = useMemo(() => antdThemeConfig(mode, density), [mode, density]);
  const value = useMemo(
    () => ({ preference, mode, density, setPreference, setDensity }),
    [preference, mode, density, setPreference, setDensity],
  );

  return (
    <ThemeContext.Provider value={value}>
      <ConfigProvider
        locale={zhCN}
        componentSize="middle"
        csp={cspNonce ? { nonce: cspNonce } : undefined}
        theme={antd}
      >
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext);
  if (!value) throw new Error("useTheme requires ThemeProvider");
  return value;
}
