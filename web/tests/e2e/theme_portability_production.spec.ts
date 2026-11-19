import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

// Compiled-production browser rehearsal for J20. Both browser contexts are
// independent and neither uses a signer, fake account, or privileged backend.
test("safe visual theme exports, previews on another browser and applies only after consent", async ({
  browser,
  baseURL,
}) => {
  if (!baseURL) throw new Error("production_base_url_required");
  const origin = new URL(baseURL).origin;
  const first = await browser.newContext({ acceptDownloads: true });
  const second = await browser.newContext({ acceptDownloads: true });

  try {
    const owner = await first.newPage();
    const visitor = await second.newPage();
    await owner.goto(`${origin}/#/settings/themes`);
    await visitor.goto(`${origin}/#/settings/themes`);

    await expect(owner.getByRole("heading", { name: "Export or import a visual theme" })).toBeVisible();
    await expect(visitor.getByRole("heading", { name: "Export or import a visual theme" })).toBeVisible();

    await owner.getByRole("button", { name: /Soft Rose/ }).click();
    await expect(owner.locator("html")).toHaveAttribute("data-theme-mode", "light");
    await expect(owner.locator("html")).toHaveAttribute("data-accent-tone", "rose");
    await expect(visitor.locator("html")).toHaveAttribute("data-theme-mode", "dark");
    await expect(visitor.locator("html")).toHaveAttribute("data-accent-tone", "mint");

    const event = owner.waitForEvent("download");
    await owner.getByRole("button", { name: "Export theme" }).click();
    const download = await event;
    expect(download.suggestedFilename()).toBe("weall-theme-v1.json");
    const filePath = await download.path();
    if (!filePath) throw new Error("theme_download_path_unavailable");
    const payload = JSON.parse(await readFile(filePath, "utf8"));
    expect(Object.keys(payload).sort()).toEqual(["kind", "name", "tokens", "version"]);
    expect(payload).toMatchObject({
      kind: "weall.presentation.theme",
      version: 1,
      tokens: { themeMode: "light", accentTone: "rose" },
    });
    expect(Object.keys(payload.tokens).sort()).toEqual([
      "accentTone",
      "density",
      "fontScale",
      "motionMode",
      "themeMode",
    ]);

    const input = visitor.getByLabel("Import visual theme JSON");
    await input.setInputFiles(filePath);
    await expect(visitor.getByRole("heading", { name: "Preview: My WeAll theme" })).toBeVisible();
    // Merely selecting an import file must never change persistent or live UI state.
    await expect(visitor.locator("html")).toHaveAttribute("data-theme-mode", "dark");
    await expect(visitor.locator("html")).toHaveAttribute("data-accent-tone", "mint");
    expect(await visitor.evaluate(() => localStorage.getItem("weall_client_settings_v3"))).toBeNull();

    await visitor.getByRole("button", { name: "Cancel import" }).click();
    await expect(visitor.getByRole("heading", { name: "Preview: My WeAll theme" })).toHaveCount(0);
    await expect(visitor.locator("html")).toHaveAttribute("data-accent-tone", "mint");

    await input.setInputFiles(filePath);
    await visitor.getByRole("button", { name: "Apply imported theme" }).click();
    await expect(visitor.locator("html")).toHaveAttribute("data-theme-mode", "light");
    await expect(visitor.locator("html")).toHaveAttribute("data-accent-tone", "rose");

    const currentSettings = await visitor.evaluate(() => JSON.parse(localStorage.getItem("weall_client_settings_v3") || "{}"));
    expect(currentSettings).toMatchObject({ themeMode: "light", accentTone: "rose" });
    expect(await visitor.evaluate(() => localStorage.getItem("weall_session_v1"))).toBeNull();
    expect(await visitor.evaluate(() => localStorage.getItem("weall.api.base"))).toBeNull();

    // Rejected imported content must preserve the applied safe theme.
    await input.setInputFiles({
      name: "untrusted.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify({ ...payload, css: "body{display:none}", version: 2 })),
    });
    await expect(visitor.getByRole("alert")).toContainText("Theme not imported.");
    await expect(visitor.locator("html")).toHaveAttribute("data-accent-tone", "rose");
    expect(await visitor.evaluate(() => JSON.parse(localStorage.getItem("weall_client_settings_v3") || "{}"))).toMatchObject(currentSettings);
  } finally {
    await Promise.all([first.close(), second.close()]);
  }
});


test("all eight bundled themes render readable surfaces and matching preview colors", async ({ page }) => {
  await page.goto("/#/settings/themes");
  const names = ["WeAll Dark", "WeAll Light", "Ocean", "Clear Sky", "Amber Night", "Gold Day", "Twilight", "Soft Rose"];
  const canvases = new Set<string>();
  for (const name of names) {
    const tile = page.locator(".themePresetTile").filter({ has: page.getByText(name, { exact: true }) });
    await tile.click();
    await expect(tile).toHaveAttribute("aria-pressed", "true");
    const values = await tile.evaluate(el => {
      const root = getComputedStyle(document.documentElement);
      const card = el.querySelector(".themePresetMockCard")!;
      const button = el.querySelector(".themePresetMockAccent")!;
      const surfaces = Array.from(document.querySelectorAll(".settingsPage .card")).filter(card => card.getClientRects().length > 0);
      const read = (name: string) => root.getPropertyValue(name).trim();
      const rgb = (str: string) => str.match(/\d+/g)!.slice(0, 3).map(Number);
      const hex = (str: string) => [1, 3, 5].map(i => parseInt(str.slice(i, i + 2), 16));
      const l = (arr: number[]) => arr.map(c => c / 255).map(c => c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
      const contrast = (a: number[], b: number[]) => (Math.max(l(a), l(b)) + .05) / (Math.min(l(a), l(b)) + .05);
      return {
        canvas: read("--bg"),
        previewMatches: rgb(getComputedStyle(card).backgroundColor).join(",") === hex(read("--panel")).join(","),
        primaryContrast: contrast(rgb(getComputedStyle(button).color), rgb(getComputedStyle(button).backgroundColor)),
        cardContrasts: surfaces.map(surface => {
          const style = getComputedStyle(surface);
          return { classes: surface.className, color: style.color, background: style.backgroundColor, ratio: contrast(rgb(style.color), rgb(style.backgroundColor)) };
        }),
        bodyColor: rgb(getComputedStyle(document.body).color).join(","),
        shellColor: rgb(getComputedStyle(document.querySelector(".appShell")!).color).join(","),
        expectedColor: hex(read("--text")).join(","),
        mutedContrast: contrast(hex(read("--muted")), hex(read("--panel"))),
      };
    });
    expect(values.previewMatches, name).toBe(true);
    expect(values.primaryContrast, name).toBeGreaterThanOrEqual(4.5);
    expect(values.bodyColor, name + " body foreground").toBe(values.expectedColor);
    expect(values.shellColor, name + " shell foreground").toBe(values.expectedColor);
    expect(values.cardContrasts.length, name + " visible cards").toBeGreaterThan(0);
    for (const card of values.cardContrasts) {
      expect(card.ratio, name + " " + card.classes + " " + card.color + " on " + card.background).toBeGreaterThanOrEqual(4.5);
    }
    expect(values.mutedContrast, name).toBeGreaterThanOrEqual(4.5);
    canvases.add(values.canvas);
  }
  expect(canvases.size).toBe(8);
});
