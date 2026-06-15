import { describe, expect, it } from "vitest";

import { buildReportScore, scorePage } from "./score.js";
import type { A11yFinding, A11yPageResult } from "./types.js";

function fail(category: A11yFinding["category"], severity: A11yFinding["severity"]): A11yFinding {
  return {
    id: `test.${category}.${severity}`,
    category,
    status: "fail",
    severity,
    title: "t",
    summary: "s"
  };
}

describe("scorePage", () => {
  it("gives a clean page a perfect score and an A", () => {
    const result = scorePage([
      { id: "p", category: "images", status: "pass", severity: "info", title: "t", summary: "s" }
    ]);
    expect(result.score).toBe(100);
    expect(result.grade).toBe("A");
  });

  it("deducts from the matching category for failures", () => {
    const result = scorePage([fail("images", "high")]);
    // images starts at 20, a high failure deducts 10 -> total 90.
    expect(result.categories.images.score).toBe(10);
    expect(result.score).toBe(90);
  });

  it("never drops a category below zero", () => {
    const result = scorePage([
      fail("images", "high"),
      fail("images", "high"),
      fail("images", "high")
    ]);
    expect(result.categories.images.score).toBe(0);
    expect(result.score).toBe(80);
  });

  it("ignores pass and info findings", () => {
    const result = scorePage([
      { id: "i", category: "forms", status: "info", severity: "info", title: "t", summary: "s" }
    ]);
    expect(result.score).toBe(100);
  });
});

describe("buildReportScore", () => {
  function page(score: number, findings: A11yFinding[] = []): A11yPageResult {
    return {
      url: `https://x/${score}`,
      requestedUrl: `https://x/${score}`,
      discovery: "discovered",
      status: 200,
      score,
      grade: "A",
      findings
    };
  }

  it("averages page scores and flags the weakest page", () => {
    const result = buildReportScore([
      { ...page(100), findings: [] },
      { ...page(60, [fail("forms", "high"), fail("forms", "high")]), url: "https://x/bad" }
    ]);
    expect(result.total).toBe(80);
    expect(result.weakestPage?.score).toBe(60);
    expect(result.weakestPage?.url).toBe("https://x/bad");
  });

  it("excludes errored pages from the average", () => {
    const errored: A11yPageResult = {
      url: "https://x/err",
      requestedUrl: "https://x/err",
      discovery: "discovered",
      status: null,
      score: 0,
      grade: "F",
      findings: [],
      error: { code: "TIMEOUT", message: "slow" }
    };
    const result = buildReportScore([page(100), errored]);
    expect(result.total).toBe(100);
  });

  it("returns a zero F report when nothing scored", () => {
    const result = buildReportScore([]);
    expect(result.total).toBe(0);
    expect(result.grade).toBe("F");
  });
});
