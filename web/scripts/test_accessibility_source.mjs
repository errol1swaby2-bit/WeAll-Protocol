import { readFileSync } from "node:fs";

function read(path) {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

const css = read("src/styles.css");
const shell = read("src/components/AppShell.tsx");
const node = read("src/pages/NodeDashboard.tsx");
const settings = read("src/pages/Settings.tsx");
const errorBanner = read("src/components/ErrorBanner.tsx");

assertIncludes(shell, "Skip to content", "shell skip link");
assertIncludes(shell, `id="app-shell-content"`, "main content target");
assertIncludes(shell, `aria-label="Helpful page summary"`, "route summary landmark");
assertIncludes(css, "@media (prefers-reduced-motion: reduce)", "reduced motion media query");
assertIncludes(css, ":focus-visible", "visible keyboard focus state");
assertIncludes(css, ".visuallyHidden", "screen-reader helper class");
assertIncludes(node, `aria-live="polite"`, "node dashboard live status");
assertIncludes(node, `role="alert"`, "node dashboard alert state");
assertIncludes(node, `aria-describedby="storage-quota-help"`, "storage quota accessible description");
assertIncludes(settings, "<label", "settings has explicit labels");
assertIncludes(errorBanner, `role="alert"`, "error banner announces failures");

console.log("accessibility source checks passed");
