import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.PROBE_E2E_BASE_URL ?? "https://tools.bsns.cc";

export default defineConfig({
  expect: {
    timeout: 10_000
  },
  forbidOnly: Boolean(process.env.CI),
  fullyParallel: false,
  reporter: process.env.CI ? "github" : "list",
  testDir: "./tests",
  timeout: 45_000,
  use: {
    baseURL,
    trace: "retain-on-failure"
  },
  projects: [
    {
      name: "chromium-desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1280, height: 900 }
      }
    },
    {
      name: "mobile-chrome",
      use: devices["Pixel 5"]
    }
  ]
});
