import { expect, test } from "@playwright/test";

const baseUrl = process.env.PROBE_E2E_BASE_URL ?? "https://tools.bsns.cc";

test.describe("bsns probe production UI", () => {
  test("shows the trust surface and keeps the domain input lowercase-friendly", async ({ page }) => {
    await page.goto("/");

    await expect(
      page.getByRole("heading", {
        name: "Check your domain's DNS, website, TLS, headers, and email setup."
      })
    ).toBeVisible();
    await expect(page.getByText("Free, open source, no account, no ads.")).toBeVisible();
    await expect(page.getByRole("link", { name: "View sample report" })).toBeVisible();
    await expect(page.locator('a[href="https://github.com/bsnscc/bsns-probe"]').first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Domain health for bsns.cc" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Raw records" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Copy Markdown" })).toBeVisible();
    await expect(page.getByText("DKIM selector record found")).toBeVisible();

    const domainInput = page.getByRole("textbox", { name: "Domain" });
    await expect(domainInput).toHaveAttribute("autocapitalize", "none");
    await expect(domainInput).toHaveAttribute("autocorrect", "off");

    await expect(page.getByText("Advanced email checks")).toBeVisible();
    await expect(page.getByLabel("DKIM selectors")).toBeHidden();
  });

  test("rejects local hostnames in the browser flow", async ({ page }) => {
    await page.goto("/");

    await page.getByRole("textbox", { name: "Domain" }).fill("localhost");
    await page.getByRole("button", { name: "Run check" }).click();

    await expect(page.locator(".form-error")).toContainText(
      "Enter a public domain name, not a local or reserved hostname."
    );
  });

  test("runs a hosted scan and renders export actions", async ({ page }) => {
    const hostname = new URL(baseUrl).hostname;

    await page.goto("/");
    await page.getByRole("textbox", { name: "Domain" }).fill(hostname);
    await page.getByRole("button", { name: "Run check" }).click();

    const runner = page.getByLabel("Domain health checker");

    await expect(runner.getByRole("heading", { name: hostname })).toBeVisible({ timeout: 30_000 });
    await expect(runner.locator(".report-preview .score-badge")).toBeVisible();
    await expect(runner.getByRole("button", { name: "Copy Markdown" })).toBeVisible();
    await expect(runner.getByRole("button", { name: "Download JSON" })).toBeVisible();
    await expect(runner.getByRole("button", { name: "Download Markdown" })).toBeVisible();
  });
});
