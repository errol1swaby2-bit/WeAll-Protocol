import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const shell = read("src/components/AppShell.tsx");
const nav = read("src/components/SidebarNav.tsx");
const css = read("src/styles.css");

for (const token of [
  'className="appShellMenuToggle"',
  "aria-expanded={menuOpen}",
  "onNavigate={() => setMenuOpen(false)}",
  'aria-label="Breadcrumbs"',
  'id="app-shell-content"',
  "key={routeKey}",
  'className="appShellInfoToggle"',
  'id="app-shell-context-drawer"',
  'role="dialog"',
  'aria-modal={infoOpen}',
  'aria-label="Close context and status panel"',
  'drawer.setAttribute("inert", "")',
  'drawer.removeAttribute("inert")',
  'document.addEventListener("keydown", onDrawerKeyDown)',
  'onClick={() => setInfoOpen(false)}',
  'className="appShellRouteStripAction appShellRouteStripAction-secondary"',
  'aria-label="Helpful page summary"',
]) {
  if (!shell.includes(token)) throw new Error(`Focused shell contract missing: ${token}`);
}
for (const token of [
  "onNavigate?.()",
  'className="sidebarNavSectionHead"',
  'aria-current={active ? "page" : undefined}',
]) {
  if (!nav.includes(token)) throw new Error(`Compact navigation missing: ${token}`);
}
for (const token of [
  ".appShell--focus .appShellBody",
  ".appShellMenuPopover",
  ".appShellDrawerLayer.isOpen",
  ".appShellContextDrawer",
  "transform: translateX(102%)",
  "@media (prefers-reduced-motion: reduce)",
]) {
  if (!css.includes(token)) throw new Error(`Focused shell styles missing: ${token}`);
}
console.log("OK: focused navigation tunnel and context drawer source contract");
