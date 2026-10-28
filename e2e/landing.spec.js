import { expect, test } from "@playwright/test";

test("signs in, manages private/public sessions, and stays responsive on mobile and desktop", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const consoleErrors = [];
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && !message.text().includes("status of 401 (Unauthorized)")) {
      consoleErrors.push(message.text());
    }
  });
  const pageResponse = await page.goto("/");
  const pageCsp = pageResponse.headers()["content-security-policy"];
  expect(pageResponse.headers()["x-frame-options"]).toBe("DENY");
  expect(pageCsp).not.toContain("unsafe-eval");
  expect(pageCsp).not.toContain("unpkg.com");
  expect(pageCsp).not.toContain("sodium.static.apphor.de");
  expect(pageCsp).not.toContain("style-src-attr");
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your sessions" })).toBeVisible();
  await expect(page.getByText("No sessions yet.")).toBeVisible();

  const privateFrameResponsePromise = page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/snippet-frame.html",
  );
  await page.getByRole("button", { name: "Create session" }).click();
  const privateFrameResponse = await privateFrameResponsePromise;
  const privateFrameCsp = privateFrameResponse.headers()["content-security-policy"];
  expect(privateFrameResponse.headers()["x-frame-options"]).toBe("SAMEORIGIN");
  expect(privateFrameCsp).toContain("unsafe-eval");
  expect(privateFrameCsp).toContain("style-src-attr 'unsafe-inline'");
  expect(privateFrameCsp).toContain("https://sodium.static.apphor.de/code-block.html");
  const firstSession = page.getByLabel("Session ID").nth(0);
  await expect(firstSession).toHaveValue(/^[0-9a-f]{128}$/);
  await expect(page.locator("#session-list > li p").first()).toContainText("Private · 0 connected");
  await expect(page.getByRole("button", { name: "Generate key" })).toBeVisible();
  const sessionKey = page.getByLabel("New session key; copy and store safely");
  await expect(sessionKey).toHaveValue(/^[A-Za-z0-9_-]{43}$/);
  const privateFrame = page.locator('iframe[title="WebSocket snippet"]').first();
  await expect(privateFrame).toHaveAttribute("sandbox", "allow-scripts");
  expect(await privateFrame.evaluate((frame) => frame.contentDocument)).toBeNull();
  const privateFrameLocator = privateFrame.contentFrame();
  await expect(privateFrameLocator.locator('link[rel="component"]')).toHaveAttribute(
    "href",
    "https://sodium.static.apphor.de/code-block.html",
  );
  const privateCode = privateFrameLocator.locator("code-block code");
  await expect(privateCode).toContainText('type: "authorize"');
  await expect(privateCode).not.toContainText(await sessionKey.inputValue());
  await expect(privateFrameLocator.locator("code-block")).toHaveAttribute("aria-label", "WebSocket snippet.");
  await expect(page.getByText("Scroll horizontally to view the full snippet.", { exact: true })).toHaveCount(0);
  await expect.poll(() => privateCode.evaluate((code) => code.scrollWidth <= code.clientWidth)).toBe(true);

  await page.getByLabel("Public").check();
  await expect(page.locator("#public-session")).toBeChecked();
  await page.getByRole("button", { name: "Create session" }).click();
  await expect(page.getByLabel("Session ID")).toHaveCount(2);
  await expect(page.locator("#session-list > li p").first()).toContainText("Public · open read/write · 0 connected");
  const publicFrame = page.locator('iframe[title="WebSocket snippet"]').last();
  const publicCode = publicFrame.contentFrame().locator("code-block code");
  await expect(publicCode).toContainText("/api/v1/sessions/");
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
  await page.setViewportSize({ width: 320, height: 844 });
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 320);
  expect(await page.locator("main").evaluate((element) => element.clientWidth)).toBe(320);
  await expect.poll(() => privateCode.evaluate((code) => code.scrollWidth <= code.clientWidth)).toBe(true);
  await expect.poll(() => publicCode.evaluate((code) => code.scrollWidth <= code.clientWidth)).toBe(true);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(consoleErrors).toEqual([]);

  await page
    .getByRole("button", { name: /^Delete session/ })
    .last()
    .click();
  await expect(page.getByLabel("Session ID")).toHaveCount(1);
  await expect(page.locator("#session-list > li p").first()).toContainText("Public · open read/write");
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByRole("heading", { name: "Your sessions" })).toBeVisible();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 1440);
  expect(await page.locator("main").evaluate((element) => element.clientWidth)).toBe(1120);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
});
