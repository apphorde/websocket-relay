import { expect, test } from "@playwright/test";

test("signs in, manages private/public sessions, and stays responsive on mobile and desktop", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const consoleErrors = [];
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sessions, simply." })).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your sessions" })).toBeVisible();
  await expect(page.getByText("No sessions yet.")).toBeVisible();

  await page.getByRole("button", { name: "Create session" }).click();
  const firstSession = page.locator(".session-id").nth(0);
  await expect(firstSession).toHaveText(/^[0-9a-f]{128}$/);
  await expect(page.locator(".session-meta").first()).toContainText("Private · 0 connected");

  await page.getByLabel("Public · listeners only").check();
  await expect(page.locator("#public-session")).toBeChecked();
  await page.getByRole("button", { name: "Create session" }).click();
  await expect(page.locator(".session-id")).toHaveCount(2);
  await expect(page.locator(".session-meta").first()).toContainText("Public · listen-only · 0 connected");
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
  expect(consoleErrors).toEqual([]);

  await page
    .getByRole("button", { name: /^Delete session/ })
    .last()
    .click();
  await expect(page.locator(".session-id")).toHaveCount(1);
  await expect(page.locator(".session-meta").first()).toContainText("Public · listen-only");
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByRole("heading", { name: "Your sessions" })).toBeVisible();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 1440);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
});
