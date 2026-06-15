import { describe, expect, it } from "vitest";

import { PageFetchError } from "./fetch-page.js";
import { scanAccessibility } from "./scan.js";
import type { FetchedPage, PageFetcher } from "./types.js";

const SEED_URL = "https://diner.example/";

const SEED_HTML = `<html lang="en"><head><title>Joe's Diner</title></head>
  <body><main><h1>Welcome</h1>
    <a href="/contact">Contact us</a>
    <a href="/menu">See the menu</a>
  </main></body></html>`;

// /contact has an unlabeled field and a missing-alt image -> should score lower.
const CONTACT_HTML = `<html lang="en"><head><title>Contact</title></head>
  <body><main><h1>Contact</h1>
    <img src="map.png">
    <form><input type="text" name="name"></form>
  </main></body></html>`;

const MENU_HTML = `<html lang="en"><head><title>Menu</title></head>
  <body><main><h1>Menu</h1><p>Food</p></main></body></html>`;

function fakeFetcher(pages: Record<string, string>): PageFetcher {
  return async (url) => {
    const finalUrl = url === "diner.example" || url === SEED_URL ? SEED_URL : url;
    const html = pages[finalUrl];
    if (html === undefined) {
      throw new PageFetchError("HTTP_ERROR", `no fixture for ${finalUrl}`);
    }
    return {
      requestedUrl: url,
      finalUrl,
      status: 200,
      contentType: "text/html",
      html
    } satisfies FetchedPage;
  };
}

describe("scanAccessibility", () => {
  it("scans the seed plus discovered pages and aggregates a score", async () => {
    const report = await scanAccessibility("diner.example", {
      fetchPage: fakeFetcher({
        [SEED_URL]: SEED_HTML,
        "https://diner.example/contact": CONTACT_HTML,
        "https://diner.example/menu": MENU_HTML
      })
    });

    expect(report.target.hostname).toBe("diner.example");
    expect(report.pages.map((page) => page.discovery)).toContain("seed");
    expect(report.pages.length).toBe(3);
    expect(report.summary.disclaimer).toMatch(/not a compliance certification/iu);

    // The contact page is the weakest (missing alt + unlabeled field).
    expect(report.score.weakestPage?.url).toBe("https://diner.example/contact");
    expect(report.score.total).toBeLessThan(100);
  });

  it("records discovered pages that fail to fetch without aborting the scan", async () => {
    const report = await scanAccessibility("diner.example", {
      fetchPage: fakeFetcher({
        [SEED_URL]: SEED_HTML,
        "https://diner.example/menu": MENU_HTML
        // /contact intentionally missing -> fetch error
      })
    });

    const contact = report.pages.find((page) => page.url.endsWith("/contact"));
    expect(contact?.error?.code).toBe("HTTP_ERROR");
    // Errored pages are excluded from the aggregate score.
    expect(report.score.total).toBeGreaterThan(0);
  });

  it("limits the number of pages scanned", async () => {
    const report = await scanAccessibility("diner.example", {
      maxPages: 1,
      fetchPage: fakeFetcher({ [SEED_URL]: SEED_HTML })
    });
    expect(report.pages).toHaveLength(1);
    expect(report.pages[0]?.discovery).toBe("seed");
  });

  it("throws when the seed page cannot be fetched", async () => {
    await expect(
      scanAccessibility("diner.example", { fetchPage: fakeFetcher({}) })
    ).rejects.toBeInstanceOf(PageFetchError);
  });
});
