import { expect, test } from "@playwright/test";

// Browser isolation smoke against the real compiled frontend. This does not
// simulate two real WeAll accounts, session issuance, or PoH verification.
test("separate browser profiles isolate account/session/node; same-profile tabs share only persistent metadata", async ({
  browser,
  baseURL,
}) => {
  if (!baseURL) throw new Error("production_base_url_required");
  const alpha = await browser.newContext();
  const beta = await browser.newContext();
  try {
    const alphaPage = await alpha.newPage();
    const betaPage = await beta.newPage();
    await Promise.all([alphaPage.goto(baseURL), betaPage.goto(baseURL)]);

    await alphaPage.evaluate(() => {
      localStorage.setItem("weall.account", "@alpha-fixture");
      localStorage.setItem("weall.api.base", "https://alpha-api.example.test");
      sessionStorage.setItem("weall_session_bearer_v1", "alpha-test-bearer-not-a-real-session");
    });

    const betaBefore = await betaPage.evaluate(() => ({
      account: localStorage.getItem("weall.account"),
      node: localStorage.getItem("weall.api.base"),
      bearer: sessionStorage.getItem("weall_session_bearer_v1"),
    }));
    expect(betaBefore).toEqual({ account: null, node: null, bearer: null });

    await betaPage.evaluate(() => {
      localStorage.setItem("weall.account", "@beta-fixture");
      localStorage.setItem("weall.api.base", "https://beta-api.example.test");
      sessionStorage.setItem("weall_session_bearer_v1", "beta-test-bearer-not-a-real-session");
    });

    const alphaAfter = await alphaPage.evaluate(() => ({
      account: localStorage.getItem("weall.account"),
      node: localStorage.getItem("weall.api.base"),
      bearer: sessionStorage.getItem("weall_session_bearer_v1"),
    }));
    expect(alphaAfter).toEqual({
      account: "@alpha-fixture",
      node: "https://alpha-api.example.test",
      bearer: "alpha-test-bearer-not-a-real-session",
    });

    const secondAlphaTab = await alpha.newPage();
    await secondAlphaTab.goto(baseURL);
    const sameProfile = await secondAlphaTab.evaluate(() => ({
      account: localStorage.getItem("weall.account"),
      node: localStorage.getItem("weall.api.base"),
      bearer: sessionStorage.getItem("weall_session_bearer_v1"),
    }));
    expect(sameProfile.account).toBe("@alpha-fixture");
    expect(sameProfile.node).toBe("https://alpha-api.example.test");
    expect(sameProfile.bearer).toBeNull();
  } finally {
    await Promise.all([alpha.close(), beta.close()]);
  }
});
