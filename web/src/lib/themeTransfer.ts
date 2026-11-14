import type { ClientSettings } from "./settings";

/**
 * Portable visual preferences only. Never include account, node, session,
 * recovery, custom CSS, external resources, or canonical state in this file.
 * The only supported tokens are already implemented, vetted UI enums.
 */
export const THEME_TRANSFER_KIND = "weall.presentation.theme";
export const THEME_TRANSFER_VERSION = 1;
export const MAX_THEME_TRANSFER_BYTES = 8192;

export type ThemeTransferTokens = Pick<
  ClientSettings,
  "themeMode" | "accentTone" | "fontScale" | "density" | "motionMode"
>;

export type ThemeTransferDocument = {
  kind: typeof THEME_TRANSFER_KIND;
  version: typeof THEME_TRANSFER_VERSION;
  name: string;
  tokens: ThemeTransferTokens;
};

const VALUES = {
  themeMode: ["dark", "light"],
  accentTone: ["mint", "cyan", "gold", "rose"],
  fontScale: ["sm", "md", "lg"],
  density: ["compact", "comfortable"],
  motionMode: ["full", "reduced"],
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactlyKeys(value: Record<string, unknown>, names: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === names.length && keys.every((key) => names.includes(key));
}

function isSafeName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 60 &&
    /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(value)
  );
}

export function createThemeTransfer(
  settings: ClientSettings,
  name = "My WeAll theme",
): ThemeTransferDocument {
  const tokens: ThemeTransferTokens = {
    themeMode: settings.themeMode,
    accentTone: settings.accentTone,
    fontScale: settings.fontScale,
    density: settings.density,
    motionMode: settings.motionMode,
  };
  return parseThemeTransfer(
    JSON.stringify({ kind: THEME_TRANSFER_KIND, version: THEME_TRANSFER_VERSION, name, tokens }),
  );
}

export function serializeThemeTransfer(document: ThemeTransferDocument): string {
  const validated = parseThemeTransfer(JSON.stringify(document));
  return JSON.stringify(validated, null, 2) + "\n";
}

/** Parse before previewing; imported data is never executed or stored here. */
export function parseThemeTransfer(text: string): ThemeTransferDocument {
  if (typeof text !== "string" || new TextEncoder().encode(text).byteLength > MAX_THEME_TRANSFER_BYTES) {
    throw new Error("Theme file is too large (maximum 8 KB).");
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error("Theme file is not valid JSON.");
  }

  if (!isRecord(raw) || !hasExactlyKeys(raw, ["kind", "version", "name", "tokens"])) {
    throw new Error("Theme file has unsupported or missing fields.");
  }
  if (raw.kind !== THEME_TRANSFER_KIND || raw.version !== THEME_TRANSFER_VERSION) {
    throw new Error("This theme format or version is not supported.");
  }
  if (!isSafeName(raw.name)) {
    throw new Error("Theme name must be 1–60 simple characters.");
  }
  if (!isRecord(raw.tokens) || !hasExactlyKeys(raw.tokens, Object.keys(VALUES))) {
    throw new Error("Theme contains missing or unsupported visual tokens.");
  }

  for (const key of Object.keys(VALUES) as Array<keyof ThemeTransferTokens>) {
    if (!(VALUES[key] as readonly unknown[]).includes(raw.tokens[key])) {
      throw new Error(`Unsupported value for visual token: ${key}.`);
    }
  }

  // Reconstruct trusted, declarative data from enumerated fields only.
  return {
    kind: THEME_TRANSFER_KIND,
    version: THEME_TRANSFER_VERSION,
    name: raw.name,
    tokens: {
      themeMode: raw.tokens.themeMode as ThemeTransferTokens["themeMode"],
      accentTone: raw.tokens.accentTone as ThemeTransferTokens["accentTone"],
      fontScale: raw.tokens.fontScale as ThemeTransferTokens["fontScale"],
      density: raw.tokens.density as ThemeTransferTokens["density"],
      motionMode: raw.tokens.motionMode as ThemeTransferTokens["motionMode"],
    },
  };
}
