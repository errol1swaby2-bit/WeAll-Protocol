import type { AccentTone, ClientSettings, ThemeMode } from "./settings";

/** Previews only predefined, vetted palettes. No arbitrary CSS or remote images. */
export type ThemePreset = {
  id: string;
  name: string;
  description: string;
  themeMode: ThemeMode;
  accentTone: AccentTone;
  background: string;
  surface: string;
  foreground: string;
  accent: string;
};

export const THEME_PRESETS: readonly ThemePreset[] = [
  { id: "weall-dark", name: "WeAll Dark", description: "Classic mint-on-navy", themeMode: "dark", accentTone: "mint", background: "#07111b", surface: "#142635", foreground: "#edf4fb", accent: "#4ce0b3" },
  { id: "weall-light", name: "WeAll Light", description: "Clear and bright", themeMode: "light", accentTone: "mint", background: "#eef5fb", surface: "#ffffff", foreground: "#0b1724", accent: "#4ce0b3" },
  { id: "ocean", name: "Ocean", description: "Blue accents with a deep canvas", themeMode: "dark", accentTone: "cyan", background: "#07111b", surface: "#142635", foreground: "#edf4fb", accent: "#6fe7ff" },
  { id: "sky", name: "Clear Sky", description: "Light canvas with cyan accents", themeMode: "light", accentTone: "cyan", background: "#eef5fb", surface: "#ffffff", foreground: "#0b1724", accent: "#4cc9f0" },
  { id: "amber-night", name: "Amber Night", description: "Warm gold accents after dark", themeMode: "dark", accentTone: "gold", background: "#07111b", surface: "#142635", foreground: "#edf4fb", accent: "#f4c95d" },
  { id: "gold-day", name: "Gold Day", description: "Golden accents on light surfaces", themeMode: "light", accentTone: "gold", background: "#eef5fb", surface: "#ffffff", foreground: "#0b1724", accent: "#f4c95d" },
  { id: "twilight", name: "Twilight", description: "Rose accents on deep surfaces", themeMode: "dark", accentTone: "rose", background: "#07111b", surface: "#142635", foreground: "#edf4fb", accent: "#fb7185" },
  { id: "soft-rose", name: "Soft Rose", description: "Rose accents on light surfaces", themeMode: "light", accentTone: "rose", background: "#eef5fb", surface: "#ffffff", foreground: "#0b1724", accent: "#fb7185" },
];

export function presetMatchesSettings(preset: ThemePreset, settings: Pick<ClientSettings, "themeMode" | "accentTone">): boolean {
  return preset.themeMode === settings.themeMode && preset.accentTone === settings.accentTone;
}
