#!/usr/bin/env node

import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const baseUrl = normalizeBaseUrl(
  process.env.PROBE_SCREENSHOT_BASE_URL ?? process.argv[2] ?? "https://tools.bsns.cc"
);
const targetDomain = process.env.PROBE_SCREENSHOT_DOMAIN ?? new URL(baseUrl).hostname;
const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = resolve(rootDir, "docs", "assets");

await mkdir(outputDir, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({
  deviceScaleFactor: 1,
  viewport: {
    height: 1100,
    width: 1440
  }
});

try {
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.screenshot({
    fullPage: true,
    path: resolve(outputDir, "probe-home.png")
  });

  await page.getByRole("textbox", { name: "Domain" }).fill(targetDomain);
  await page.getByRole("button", { name: "Run check" }).click();
  await page.getByRole("heading", { name: targetDomain }).waitFor({ timeout: 30_000 });
  await page.screenshot({
    fullPage: true,
    path: resolve(outputDir, "probe-report.png")
  });
} finally {
  await browser.close();
}

console.log(`captured production screenshots for ${baseUrl} in ${outputDir}`);

function normalizeBaseUrl(value) {
  return value.replace(/\/+$/u, "");
}
