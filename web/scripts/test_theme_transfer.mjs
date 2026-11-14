import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const source = read("src/lib/themeTransfer.ts");
const settingsUi = read("src/pages/Settings.tsx");
const settingsStorage = read("src/lib/settings.ts");

const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, strict: true },
}).outputText;
const {
  createThemeTransfer,
  parseThemeTransfer,
  serializeThemeTransfer,
  THEME_TRANSFER_KIND,
  THEME_TRANSFER_VERSION,
  MAX_THEME_TRANSFER_BYTES,
} = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);

const settings = {
  showGenesisBootstrap: true,
  showAdvancedMode: true,
  themeMode: "light",
  accentTone: "gold",
  fontScale: "lg",
  density: "compact",
  motionMode: "reduced",
};
const exportDoc = createThemeTransfer(settings);
const portable = serializeThemeTransfer(exportDoc);
const parsed = parseThemeTransfer(portable);

assert.deepEqual(parsed, {
  kind: THEME_TRANSFER_KIND,
  version: THEME_TRANSFER_VERSION,
  name: "My WeAll theme",
  tokens: {
    themeMode: "light",
    accentTone: "gold",
    fontScale: "lg",
    density: "compact",
    motionMode: "reduced",
  },
});
assert.ok(!portable.includes("showAdvancedMode"), "Advanced/testing toggle is not portable");
assert.ok(!portable.includes("showGenesisBootstrap"), "Bootstrap controls are not portable");
assert.ok(!portable.includes("account"), "No account identifier field");
assert.ok(!portable.includes("network"), "No node connection URL field");
assert.ok(!portable.includes("session"), "No bearer/session field");
assert.ok(!portable.includes("secret"), "No signing or recovery field");

for (const [key, choices] of Object.entries({
  themeMode: ["dark", "light"],
  accentTone: ["mint", "cyan", "gold", "rose"],
  fontScale: ["sm", "md", "lg"],
  density: ["compact", "comfortable"],
  motionMode: ["full", "reduced"],
})) {
  for (const choice of choices) {
    const changed = { ...settings, [key]: choice };
    assert.deepEqual(parseThemeTransfer(serializeThemeTransfer(createThemeTransfer(changed))).tokens[key], choice);
  }
}

function shouldReject(variant, reason) {
  assert.throws(
    () => parseThemeTransfer(JSON.stringify(variant)),
    /theme|format|token|value|name/i,
    reason,
  );
}
shouldReject({ ...exportDoc, version: 2 }, "Unknown versions fail closed");
shouldReject({ ...exportDoc, kind: "http://example.org/theme" }, "No alternate scheme");
shouldReject({ ...exportDoc, node_url: "https://attacker.invalid" }, "Unknown endpoint fields rejected");
shouldReject({ ...exportDoc, css: "body{display:none}" }, "No CSS fields accepted");
shouldReject({ ...exportDoc, tokens: { ...exportDoc.tokens, fontScale: "extreme" } }, "No unknown enum values");
shouldReject({ ...exportDoc, tokens: { ...exportDoc.tokens, script: "alert(1)" } }, "No executable tokens");
shouldReject({ ...exportDoc, tokens: { themeMode: "light" } }, "All supported tokens required");
shouldReject({ ...exportDoc, tokens: ["dark", "gold"] }, "No array-valued token documents");
shouldReject({ ...exportDoc, name: "<img onerror=alert(1)>" }, "No unsafe theme name");
shouldReject({ ...exportDoc, tokens: { ...exportDoc.tokens, __proto__: "ignored", backgroundUrl: "https://example.org" } }, "No remote media");
assert.throws(() => parseThemeTransfer("{not json"), /valid JSON/);
assert.throws(() => parseThemeTransfer("x".repeat(MAX_THEME_TRANSFER_BYTES + 1)), /too large/);
assert.throws(() => parseThemeTransfer("null"), /unsupported/);
assert.throws(() => parseThemeTransfer("[]"), /unsupported/);

assert.ok(settingsUi.includes("setPendingTheme(candidate)"), "Import must first prepare a preview");
assert.ok(settingsUi.includes("if (!pendingTheme) return"), "Apply must require validated preview");
assert.ok(settingsUi.includes('aria-label="Imported theme preview"'), "Preview needs an accessible label");
assert.ok(settingsUi.includes("Apply imported theme"), "Explicit Apply action required");
assert.ok(settingsUi.includes("Cancel import"), "Preview must be cancellable");
assert.ok(settingsUi.includes("parseThemeTransfer(await file.text())"), "Import must be strictly validated");
assert.ok(settingsUi.includes("saveSettings(next)"), "Approved import persists browser-only settings");
assert.ok(!settingsStorage.includes("setApiBase"), "Appearance storage must not change API target");
assert.ok(!source.includes("localStorage"), "Parser must be pure and free from storage writes");

console.log("OK: versioned, bounded, non-executable theme export/import and explicit preview/apply guards");
