import { describe, expect, it } from "vitest";

import { runRules } from "./rules.js";
import type { A11yFinding } from "./types.js";

function ids(findings: A11yFinding[]): string[] {
  return findings.map((finding) => finding.id);
}

function byId(findings: A11yFinding[], id: string): A11yFinding | undefined {
  return findings.find((finding) => finding.id === id);
}

const GOOD_PAGE = `<!doctype html>
<html lang="en">
  <head><title>Joe's Diner — Lunch Menu</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  </head>
  <body>
    <nav><a href="/menu">View the lunch menu</a></nav>
    <main>
      <h1>Lunch Menu</h1>
      <h2>Sandwiches</h2>
      <img src="/blt.jpg" alt="A bacon, lettuce, and tomato sandwich">
      <form>
        <label for="email">Email</label>
        <input id="email" type="email" name="email">
        <button type="submit">Join our list</button>
      </form>
      <table>
        <tr><th>Item</th><th>Price</th></tr>
        <tr><td>BLT</td><td>$9</td></tr>
      </table>
    </main>
  </body>
</html>`;

describe("runRules — a clean page", () => {
  const findings = runRules(GOOD_PAGE);

  it("passes language, title, images, forms, links", () => {
    expect(byId(findings, "a11y.language.html_lang_present")?.status).toBe("pass");
    expect(byId(findings, "a11y.language.title_present")?.status).toBe("pass");
    expect(byId(findings, "a11y.images.alt_ok")?.status).toBe("pass");
    expect(byId(findings, "a11y.forms.label_ok")?.status).toBe("pass");
    expect(byId(findings, "a11y.links.ok")?.status).toBe("pass");
  });

  it("reports no failures", () => {
    expect(findings.filter((f) => f.status === "fail")).toHaveLength(0);
  });
});

describe("runRules — language and document", () => {
  it("fails when html lang is missing", () => {
    const findings = runRules("<html><head><title>x</title></head><body></body></html>");
    expect(byId(findings, "a11y.language.html_lang_missing")?.status).toBe("fail");
  });

  it("fails when title is missing or empty", () => {
    const findings = runRules('<html lang="en"><head></head><body></body></html>');
    expect(byId(findings, "a11y.language.title_missing")?.status).toBe("fail");
  });

  it("fails when the viewport blocks zoom", () => {
    const html =
      '<html lang="en"><head><title>x</title>' +
      '<meta name="viewport" content="width=device-width, user-scalable=no"></head><body></body></html>';
    expect(ids(runRules(html))).toContain("a11y.language.viewport_blocks_zoom");
  });

  it("fails when maximum-scale is below 2", () => {
    const html =
      '<html lang="en"><head><title>x</title>' +
      '<meta name="viewport" content="maximum-scale=1.0"></head><body></body></html>';
    expect(ids(runRules(html))).toContain("a11y.language.viewport_blocks_zoom");
  });
});

describe("runRules — images", () => {
  it("flags images with no alt attribute", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><img src="a.jpg"></body></html>');
    const finding = byId(findings, "a11y.images.alt_missing");
    expect(finding?.status).toBe("fail");
    expect(finding?.evidence?.count).toBe(1);
  });

  it("treats empty alt as intentional (decorative)", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><img src="a.jpg" alt=""></body></html>');
    expect(byId(findings, "a11y.images.alt_missing")).toBeUndefined();
    expect(byId(findings, "a11y.images.alt_ok")?.status).toBe("pass");
  });

  it("ignores aria-hidden images", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><img src="a.jpg" aria-hidden="true"></body></html>');
    expect(byId(findings, "a11y.images.alt_missing")).toBeUndefined();
  });
});

describe("runRules — forms", () => {
  it("flags inputs without any label association", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><form><input type="text" name="q"></form></body></html>');
    expect(byId(findings, "a11y.forms.label_missing")?.status).toBe("fail");
  });

  it("accepts aria-label", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><input type="text" aria-label="Search"></body></html>');
    expect(byId(findings, "a11y.forms.label_missing")).toBeUndefined();
  });

  it("accepts a wrapping label", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><label>Name <input type="text"></label></body></html>');
    expect(byId(findings, "a11y.forms.label_missing")).toBeUndefined();
  });

  it("ignores hidden and submit inputs", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><form><input type="hidden" name="t"><input type="submit" value="Go"></form></body></html>');
    expect(byId(findings, "a11y.forms.label_missing")).toBeUndefined();
  });
});

describe("runRules — links and buttons", () => {
  it("flags links with no accessible name", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><a href="/x"><img src="i.png"></a></body></html>');
    expect(byId(findings, "a11y.links.name_missing")?.status).toBe("fail");
  });

  it("uses an icon image alt as the link name", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><a href="/x"><img src="i.png" alt="Home"></a></body></html>');
    expect(byId(findings, "a11y.links.name_missing")).toBeUndefined();
  });

  it("warns on vague link text", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><a href="/x">click here</a></body></html>');
    expect(byId(findings, "a11y.links.generic_text")?.status).toBe("warn");
  });

  it("flags icon-only buttons", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><button></button></body></html>');
    expect(byId(findings, "a11y.links.name_missing")?.status).toBe("fail");
  });
});

describe("runRules — structure", () => {
  it("warns when there is no h1", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><h2>Hi</h2></body></html>');
    expect(byId(findings, "a11y.structure.h1_missing")?.status).toBe("warn");
  });

  it("warns when heading levels skip", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><h1>A</h1><h3>B</h3></body></html>');
    expect(byId(findings, "a11y.structure.heading_skip")?.status).toBe("warn");
  });

  it("warns when there is no main landmark", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><h1>A</h1></body></html>');
    expect(byId(findings, "a11y.structure.main_missing")?.status).toBe("warn");
  });

  it("flags duplicate ids", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><main><span id="dup"></span><span id="dup"></span></main></body></html>');
    expect(byId(findings, "a11y.structure.duplicate_ids")?.status).toBe("warn");
  });
});

describe("runRules — tables", () => {
  it("warns on a multi-row data table without headers", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><table><tr><td>a</td></tr><tr><td>b</td></tr></table></body></html>');
    expect(byId(findings, "a11y.tables.headers_missing")?.status).toBe("warn");
  });

  it("does not flag a single-row table", () => {
    const findings = runRules('<html lang="en"><head><title>x</title></head><body><table><tr><td>a</td></tr></table></body></html>');
    expect(byId(findings, "a11y.tables.headers_missing")).toBeUndefined();
  });
});
