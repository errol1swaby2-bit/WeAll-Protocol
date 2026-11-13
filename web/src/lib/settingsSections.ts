/** Personal appearance settings are local to the browser, never protocol state. */
export const SETTINGS_SECTIONS = [
  { id: "overview", label: "Overview", href: "/settings" },
  { id: "connection", label: "Connection", href: "/settings/connection" },
  { id: "themes", label: "Themes", href: "/settings/themes" },
  { id: "layout", label: "Layout", href: "/settings/layout" },
  { id: "accessibility", label: "Accessibility", href: "/settings/accessibility" },
  { id: "advanced", label: "Advanced", href: "/settings/advanced" },
] as const;

export type SettingsSection = (typeof SETTINGS_SECTIONS)[number]["id"];

export function settingsSectionFromHash(hash: string): SettingsSection {
  const raw = String(hash || "").replace(/^#/, "");
  const question = raw.indexOf("?");
  const pathname = question >= 0 ? raw.slice(0, question) : raw;
  if (pathname === "/settings/appearance") return "themes";
  const entry = SETTINGS_SECTIONS.find((item) => item.href === pathname);
  if (entry) return entry.id;
  const params = new URLSearchParams(question >= 0 ? raw.slice(question + 1) : "");
  const requested = params.get("tab");
  return SETTINGS_SECTIONS.find((item) => item.id === requested)?.id || "overview";
}
