import { describe, expect, it } from "vitest";

import { discoverPages } from "./crawl.js";

const SEED = "https://diner.example/";

const HTML = `<html><body>
  <a href="/contact">Contact us</a>
  <a href="/about">About</a>
  <a href="/menu">Menu</a>
  <a href="/legal/privacy">Privacy</a>
  <a href="https://facebook.com/diner">Facebook</a>
  <a href="mailto:hi@diner.example">Email</a>
  <a href="/menu.pdf">Menu PDF</a>
  <a href="#top">Back to top</a>
</body></html>`;

describe("discoverPages", () => {
  it("ranks operationally important pages first", () => {
    const pages = discoverPages(HTML, SEED, 4);
    const paths = pages.map((url) => new URL(url).pathname);
    expect(paths[0]).toBe("/contact");
    expect(paths).toContain("/menu");
  });

  it("stays on the same host", () => {
    const pages = discoverPages(HTML, SEED, 10);
    expect(pages.every((url) => new URL(url).hostname === "diner.example")).toBe(true);
  });

  it("skips mailto, fragments, and binary files", () => {
    const pages = discoverPages(HTML, SEED, 10);
    expect(pages.some((url) => url.includes("mailto"))).toBe(false);
    expect(pages.some((url) => url.endsWith(".pdf"))).toBe(false);
    expect(pages.some((url) => url.includes("#top"))).toBe(false);
  });

  it("respects the limit", () => {
    expect(discoverPages(HTML, SEED, 2)).toHaveLength(2);
  });

  it("returns nothing when the limit is zero", () => {
    expect(discoverPages(HTML, SEED, 0)).toHaveLength(0);
  });

  it("does not re-list the seed page", () => {
    const pages = discoverPages('<html><body><a href="/">Home</a></body></html>', SEED, 4);
    expect(pages.some((url) => new URL(url).pathname === "/")).toBe(false);
  });
});
