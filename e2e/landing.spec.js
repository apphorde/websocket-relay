import { expect, test } from "@playwright/test";

test("signs in, manages private/public sessions, and stays responsive on mobile and desktop", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const consoleErrors = [];
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your sessions" })).toBeVisible();
  await expect(page.getByText("No sessions yet.")).toBeVisible();

  await page.getByRole("button", { name: "Create session" }).click();
  const firstSession = page.locator(".session-id").nth(0);
  await expect(firstSession).toHaveValue(/^[0-9a-f]{128}$/);
  await expect(page.locator(".session-meta").first()).toContainText("Private · 0 connected");
  await expect(page.getByRole("button", { name: "Generate key" })).toBeVisible();
  await expect(page.getByLabel("New session key; copy and store safely")).toHaveValue(/^[A-Za-z0-9_-]{43}$/);
  await expect(page.locator(".session-row pre").first()).toContainText('type: "authorize"');

  await page.getByLabel("Public").check();
  await expect(page.locator("#public-session")).toBeChecked();
  await page.getByRole("button", { name: "Create session" }).click();
  await expect(page.locator(".session-id")).toHaveCount(2);
  await expect(page.locator(".session-meta").first()).toContainText("Public · open read/write · 0 connected");
  await expect(page.locator(".session-row pre").last()).toContainText("/api/v1/sessions/");
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
  expect(consoleErrors).toEqual([]);

  await page
    .getByRole("button", { name: /^Delete session/ })
    .last()
    .click();
  await expect(page.locator(".session-id")).toHaveCount(1);
  await expect(page.locator(".session-meta").first()).toContainText("Public · open read/write");
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByRole("heading", { name: "Your sessions" })).toBeVisible();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 1440);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
});
