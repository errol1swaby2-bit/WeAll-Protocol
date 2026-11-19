import { themePalette } from "./themePresets";

export type ThemeMode = "dark" | "light";
export type AccentTone = "mint" | "cyan" | "gold" | "rose";
export type FontScale = "sm" | "md" | "lg";
export type Density = "compact" | "comfortable";
export type MotionMode = "full" | "reduced";

export type ClientSettings = {
  showGenesisBootstrap: boolean;
  showAdvancedMode: boolean;
  themeMode: ThemeMode;
  accentTone: AccentTone;
  fontScale: FontScale;
  density: Density;
  motionMode: MotionMode;
};

export const CLIENT_SETTINGS_CHANGED_EVENT = "weall:client-settings-changed";

const KEY = "weall_client_settings_v3";

export const DEFAULT_SETTINGS: ClientSettings = {
  showGenesisBootstrap: false,
  showAdvancedMode: false,
  themeMode: "dark",
  accentTone: "mint",
  fontScale: "md",
  density: "comfortable",
  motionMode: "full",
};

function asThemeMode(value: unknown): ThemeMode {
  return value === "light" ? "light" : "dark";
}

function asAccentTone(value: unknown): AccentTone {
  return value === "cyan" || value === "gold" || value === "rose" ? value : "mint";
}

function asFontScale(value: unknown): FontScale {
  return value === "sm" || value === "lg" ? value : "md";
}

function asDensity(value: unknown): Density {
  return value === "compact" ? "compact" : "comfortable";
}

function asMotionMode(value: unknown): MotionMode {
  return value === "reduced" ? "reduced" : "full";
}

export function loadSettings(): ClientSettings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const j = JSON.parse(raw);
    return {
      showGenesisBootstrap: Boolean(j?.showGenesisBootstrap),
      showAdvancedMode: Boolean(j?.showAdvancedMode),
      themeMode: asThemeMode(j?.themeMode),
      accentTone: asAccentTone(j?.accentTone),
      fontScale: asFontScale(j?.fontScale),
      density: asDensity(j?.density),
      motionMode: asMotionMode(j?.motionMode),
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(next: ClientSettings): void {
  localStorage.setItem(KEY, JSON.stringify(next));
  try {
    window.dispatchEvent(new CustomEvent(CLIENT_SETTINGS_CHANGED_EVENT, { detail: next }));
  } catch {
    // ignore event dispatch failures in non-browser test environments
  }
}

function setAccentVars(root: HTMLElement, accent: string, accent2: string, accentRgb: string, accent2Rgb: string): void {
  root.style.setProperty("--accent", accent);
  root.style.setProperty("--accent-2", accent2);
  root.style.setProperty("--accent-rgb", accentRgb);
  root.style.setProperty("--accent-2-rgb", accent2Rgb);
  root.style.setProperty("--accent-soft", `rgba(${accentRgb}, 0.12)`);
  root.style.setProperty("--accent-hover", `rgba(${accent2Rgb}, 0.1)`);
  root.style.setProperty("--accent-border", `rgba(${accentRgb}, 0.28)`);
  root.style.setProperty("--accent-focus", `rgba(${accentRgb}, 0.42)`);
  root.style.setProperty("--accent-focus-ring", `rgba(${accentRgb}, 0.12)`);
  root.style.setProperty("--accent-glow-left", `rgba(${accentRgb}, 0.12)`);
  root.style.setProperty("--accent-glow-right", `rgba(${accent2Rgb}, 0.16)`);
}

export function applySettingsToDocument(settings: ClientSettings): void {
  const root = document.documentElement;

  root.dataset.themeMode = settings.themeMode;
  root.dataset.accentTone = settings.accentTone;
  root.dataset.fontScale = settings.fontScale;
  root.dataset.density = settings.density;
  root.dataset.motionMode = settings.motionMode;

  const palette = themePalette(settings);
  const light = settings.themeMode === "light";
  const rgb = (hex: string) => [1, 3, 5].map(index => parseInt(hex.slice(index, index + 2), 16)).join(", ");
  const vars: Record<string, string> = {
    "--bg": palette.background, "--bg2": palette.backgroundEnd,
    "--panel": palette.surface, "--panel-strong": palette.raised, "--panel-soft": palette.soft,
    "--text": palette.foreground, "--muted": palette.muted, "--muted-strong": palette.muted,
    "--border": palette.border, "--border-strong": palette.border,
    "--on-accent": palette.onAccent,
    "--gold": light ? "#70430a" : "#ffda8c",
    "--danger": light ? "#942b40" : "#ffb6c4",
    "--ok": light ? "#155b36" : "#a4f2c1",
    "--shadow": light ? "0 12px 32px rgba(25,38,48,.10)" : "0 16px 42px rgba(0,0,0,.26)",
  };
  for (const [name, value] of Object.entries(vars)) root.style.setProperty(name, value);
  root.style.colorScheme = light ? "light" : "dark";
  setAccentVars(root, palette.accent, palette.accent2, rgb(palette.accent), rgb(palette.accent2));

  switch (settings.fontScale) {
    case "sm":
      root.style.setProperty("--font-scale", "0.94");
      break;
    case "lg":
      root.style.setProperty("--font-scale", "1.08");
      break;
    default:
      root.style.setProperty("--font-scale", "1");
      break;
  }

  switch (settings.density) {
    case "compact":
      root.style.setProperty("--density-gap", "12px");
      root.style.setProperty("--density-pad", "14px");
      break;
    default:
      root.style.setProperty("--density-gap", "18px");
      root.style.setProperty("--density-pad", "20px");
      break;
  }

  if (settings.motionMode === "reduced") {
    root.style.setProperty("--motion-scale", "0");
  } else {
    root.style.setProperty("--motion-scale", "1");
  }
}
