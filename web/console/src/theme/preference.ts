import type { DensityPreference, ThemeMode, ThemePreference } from "./tokens.ts";

/**
 * Theme and density are the only values the console ever persists in web storage. They are
 * presentation preferences with no tenant, session or investigation content. Reads and writes
 * never throw: private windows and blocked site data fall back to the in-memory default.
 */
export const THEME_STORAGE_KEY = "xshield.console.theme";
export const DENSITY_STORAGE_KEY = "xshield.console.density";

export type PreferenceStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

export function parseThemePreference(raw: unknown): ThemePreference {
  return raw === "light" || raw === "dark" ? raw : "system";
}

export function parseDensityPreference(raw: unknown): DensityPreference {
  return raw === "compact" ? "compact" : "comfortable";
}

export function resolveThemeMode(
  preference: ThemePreference,
  systemPrefersDark: boolean,
): ThemeMode {
  if (preference === "system") return systemPrefersDark ? "dark" : "light";
  return preference;
}

/** `window.localStorage` itself may throw (blocked storage), so the accessor is guarded too. */
export function preferenceStorage(): PreferenceStorage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

function read(storage: PreferenceStorage | null, key: string): string | null {
  try {
    return storage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function readThemePreference(storage: PreferenceStorage | null): ThemePreference {
  return parseThemePreference(read(storage, THEME_STORAGE_KEY));
}

export function readDensityPreference(storage: PreferenceStorage | null): DensityPreference {
  return parseDensityPreference(read(storage, DENSITY_STORAGE_KEY));
}

/** The default ("system" / "comfortable") is represented by an absent key, not a stored value. */
function write(storage: PreferenceStorage | null, key: string, value: string, isDefault: boolean) {
  try {
    if (!storage) return false;
    if (isDefault) storage.removeItem(key);
    else storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export function writeThemePreference(storage: PreferenceStorage | null, value: ThemePreference) {
  return write(storage, THEME_STORAGE_KEY, value, value === "system");
}

export function writeDensityPreference(
  storage: PreferenceStorage | null,
  value: DensityPreference,
) {
  return write(storage, DENSITY_STORAGE_KEY, value, value === "comfortable");
}

/** Attribute contract consumed by tokens.generated.css. */
export function documentAttributes(
  theme: ThemePreference,
  density: DensityPreference,
): { theme: ThemeMode | null; density: DensityPreference | null } {
  return {
    theme: theme === "system" ? null : theme,
    density: density === "comfortable" ? null : density,
  };
}
