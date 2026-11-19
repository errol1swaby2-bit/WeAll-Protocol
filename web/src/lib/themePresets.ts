import type { AccentTone, ClientSettings, ThemeMode } from "./settings";

/** One vetted palette drives both the preview and the actual application. */
export type ThemePreset = {
  id: string;
  name: string;
  description: string;
  themeMode: ThemeMode;
  accentTone: AccentTone;
  background: string;
  backgroundEnd: string;
  surface: string;
  raised: string;
  soft: string;
  foreground: string;
  muted: string;
  border: string;
  accent: string;
  accent2: string;
  onAccent: string;
};

export const THEME_PRESETS: readonly ThemePreset[] = [
  { id: "weall-dark", name: "WeAll Dark", description: "Deep graphite teal · mint highlights", themeMode: "dark", accentTone: "mint", background: "#07151b", backgroundEnd: "#0d2028", surface: "#132a32", raised: "#1b363e", soft: "#203b43", foreground: "#eef9f6", muted: "#b3cbd0", border: "#526d76", accent: "#6de8bc", accent2: "#85ebe6", onAccent: "#09251e" },
  { id: "weall-light", name: "WeAll Light", description: "Pearl green · forest accents", themeMode: "light", accentTone: "mint", background: "#e7f1ed", backgroundEnd: "#d5e7df", surface: "#ffffff", raised: "#f2f8f5", soft: "#e2eee8", foreground: "#172e29", muted: "#415d54", border: "#718e83", accent: "#12694e", accent2: "#176c69", onAccent: "#ffffff" },
  { id: "ocean", name: "Ocean", description: "Midnight blue · luminous aqua", themeMode: "dark", accentTone: "cyan", background: "#081426", backgroundEnd: "#10243c", surface: "#162d47", raised: "#203b57", soft: "#25415e", foreground: "#eff7ff", muted: "#b5cbe2", border: "#587897", accent: "#7be1ff", accent2: "#9bc4ff", onAccent: "#102739" },
  { id: "sky", name: "Clear Sky", description: "Airy blue · deep sapphire", themeMode: "light", accentTone: "cyan", background: "#e7f0fb", backgroundEnd: "#d7e6f6", surface: "#ffffff", raised: "#f0f6fd", soft: "#e0ebf9", foreground: "#172c46", muted: "#415972", border: "#758ca8", accent: "#155d9b", accent2: "#176789", onAccent: "#ffffff" },
  { id: "amber-night", name: "Amber Night", description: "Warm charcoal · honey gold", themeMode: "dark", accentTone: "gold", background: "#1a1510", backgroundEnd: "#292017", surface: "#32271d", raised: "#403225", soft: "#49392a", foreground: "#fff7e8", muted: "#dfcdb3", border: "#8e785c", accent: "#ffd477", accent2: "#f6b76d", onAccent: "#30200a" },
  { id: "gold-day", name: "Gold Day", description: "Warm ivory · bronze accents", themeMode: "light", accentTone: "gold", background: "#f6eddd", backgroundEnd: "#eadcc7", surface: "#fffcf5", raised: "#faf3e6", soft: "#efe3cf", foreground: "#3a2a1b", muted: "#66513b", border: "#9b8265", accent: "#84520d", accent2: "#8b531f", onAccent: "#ffffff" },
  { id: "twilight", name: "Twilight", description: "Plum night · soft rose", themeMode: "dark", accentTone: "rose", background: "#1b1426", backgroundEnd: "#2c203b", surface: "#322640", raised: "#45334f", soft: "#4b3859", foreground: "#fff3fc", muted: "#dcc4e2", border: "#8b7197", accent: "#ffabc1", accent2: "#e3b7ff", onAccent: "#38172b" },
  { id: "soft-rose", name: "Soft Rose", description: "Petal ivory · berry accents", themeMode: "light", accentTone: "rose", background: "#f6e9ee", backgroundEnd: "#ead9e3", surface: "#fffafd", raised: "#faf0f5", soft: "#efdfeb", foreground: "#41283b", muted: "#70526a", border: "#9e7d93", accent: "#92385f", accent2: "#79468c", onAccent: "#ffffff" },
];

export function presetMatchesSettings(preset: ThemePreset, settings: Pick<ClientSettings, "themeMode" | "accentTone">): boolean {
  return preset.themeMode === settings.themeMode && preset.accentTone === settings.accentTone;
}

export function themePalette(settings: Pick<ClientSettings, "themeMode" | "accentTone">): ThemePreset {
  return THEME_PRESETS.find(preset => presetMatchesSettings(preset, settings)) || THEME_PRESETS[0];
}
