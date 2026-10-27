import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  outputDir: "/tmp/opencode/websocket-relay-playwright",
  use: {
    baseURL: "http://127.0.0.1:4174",
    browserName: "chromium",
    headless: true,
  },
  webServer: {
    command: "node test/e2e-server.mjs",
    url: "http://127.0.0.1:4174/health",
    reuseExistingServer: !process.env.CI,
    timeout: 15_000,
  },
});
