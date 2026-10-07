import { expect, test } from "@playwright/test";

test("production nginx deployment emits CSP and preserves app/API behavior", async ({
  page,
  request,
}) => {
  const response = await request.get("/");
  expect(response.ok()).toBeTruthy();

  const csp = response.headers()["content-security-policy"];
  expect(csp).toBeTruthy();
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
  expect(csp).not.toContain("script-src 'self' 'unsafe-eval'");

  const scriptResponses: string[] = [];
  page.on("response", (resp) => {
    const url = resp.url();
    if (url.includes("/assets/") && url.endsWith(".js") && resp.ok()) {
      scriptResponses.push(url);
    }
  });

  await page.goto("/#/login");
  await expect(page.locator("#root")).toBeVisible();
  await expect.poll(async () => (await page.locator("#root").innerText()).trim()).not.toBe("");

  const origin = new URL(page.url()).origin;
  const scriptSources = await page.locator("script[src]").evaluateAll((nodes) =>
    nodes.map((node) => (node as HTMLScriptElement).src),
  );
  expect(scriptSources.length).toBeGreaterThan(0);
  for (const src of scriptSources) {
    expect(new URL(src, origin).origin).toBe(origin);
  }
  expect(scriptResponses.length).toBeGreaterThan(0);

  const ready = await page.evaluate(async () => {
    const resp = await fetch("/v1/readyz");
    return { status: resp.status, body: await resp.json() };
  });
  expect(ready.status).toBe(200);
  expect(ready.body).toMatchObject({ ok: true });

  const imageLoaded = await page.evaluate(async () => {
    const img = new Image();
    const done = new Promise<boolean>((resolve) => {
      img.onload = () => resolve(true);
      img.onerror = () => resolve(false);
    });
    img.src =
      "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";
    document.body.appendChild(img);
    return await done;
  });
  expect(imageLoaded).toBe(true);
});
