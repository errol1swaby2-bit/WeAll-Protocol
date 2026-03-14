export type ThemeMode = "dark" | "light";
export type AccentTone = "mint" | "cyan" | "gold" | "rose";
export type FontScale = "sm" | "md" | "lg";
export type Density = "compact" | "comfortable";
export type MotionMode = "full" | "reduced";

export type ClientSettings = {
  showGenesisBootstrap: boolean;
  themeMode: ThemeMode;
  accentTone: AccentTone;
  fontScale: FontScale;
  density: Density;
  motionMode: MotionMode;
};

const KEY = "weall_client_settings_v2";

export const DEFAULT_SETTINGS: ClientSettings = {
  showGenesisBootstrap: false,
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
}

export function applySettingsToDocument(settings: ClientSettings): void {
  const root = document.documentElement;

  root.dataset.themeMode = settings.themeMode;
  root.dataset.accentTone = settings.accentTone;
  root.dataset.fontScale = settings.fontScale;
  root.dataset.density = settings.density;
  root.dataset.motionMode = settings.motionMode;

  if (settings.themeMode === "light") {
    root.style.setProperty("--bg", "#eef5fb");
    root.style.setProperty("--bg2", "#dfeaf5");
    root.style.setProperty("--panel", "rgba(255, 255, 255, 0.88)");
    root.style.setProperty("--panel-strong", "rgba(255, 255, 255, 0.96)");
    root.style.setProperty("--panel-soft", "rgba(15, 23, 42, 0.05)");
    root.style.setProperty("--text", "#0b1724");
    root.style.setProperty("--muted", "rgba(11, 23, 36, 0.72)");
    root.style.setProperty("--muted-strong", "rgba(11, 23, 36, 0.86)");
    root.style.setProperty("--border", "rgba(15, 23, 42, 0.12)");
    root.style.setProperty("--border-strong", "rgba(15, 23, 42, 0.18)");
    root.style.setProperty("--shadow", "0 22px 50px rgba(15, 23, 42, 0.12)");
  } else {
    root.style.setProperty("--bg", "#07111b");
    root.style.setProperty("--bg2", "#0b1724");
    root.style.setProperty("--panel", "rgba(10, 23, 36, 0.88)");
    root.style.setProperty("--panel-strong", "rgba(10, 23, 36, 0.96)");
    root.style.setProperty("--panel-soft", "rgba(255, 255, 255, 0.04)");
    root.style.setProperty("--text", "#edf4fb");
    root.style.setProperty("--muted", "rgba(237, 244, 251, 0.72)");
    root.style.setProperty("--muted-strong", "rgba(237, 244, 251, 0.86)");
    root.style.setProperty("--border", "rgba(186, 219, 255, 0.14)");
    root.style.setProperty("--border-strong", "rgba(186, 219, 255, 0.22)");
    root.style.setProperty("--shadow", "0 22px 50px rgba(0, 0, 0, 0.32)");
  }

  switch (settings.accentTone) {
    case "cyan":
      root.style.setProperty("--accent", "#6fe7ff");
      root.style.setProperty("--accent-2", "#4cc9f0");
      break;
    case "gold":
      root.style.setProperty("--accent", "#f4c95d");
      root.style.setProperty("--accent-2", "#ffd166");
      break;
    case "rose":
      root.style.setProperty("--accent", "#fb7185");
      root.style.setProperty("--accent-2", "#f9a8d4");
      break;
    default:
      root.style.setProperty("--accent", "#4ce0b3");
      root.style.setProperty("--accent-2", "#6fe7ff");
      break;
  }

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
