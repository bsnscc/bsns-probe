import { gradeScore } from "@bsns/probe-core";

import type {
  A11yCategory,
  A11yFinding,
  A11yPageResult,
  A11yReport,
  A11yScoreCategory,
  FindingStatus,
  ReportGrade
} from "./types.js";

/** Accessibility score weights by WCAG area. Sums to 100. */
const CATEGORY_MAX: Record<Exclude<A11yCategory, "meta">, number> = {
  images: 20,
  forms: 20,
  language: 20,
  structure: 20,
  links: 15,
  tables: 5
};

const TOP_FIX_PRIORITY = new Map<string, number>([
  ["a11y.language.viewport_blocks_zoom", 100],
  ["a11y.images.alt_missing", 95],
  ["a11y.forms.label_missing", 94],
  ["a11y.links.name_missing", 92],
  ["a11y.language.html_lang_missing", 90],
  ["a11y.language.title_missing", 88],
  ["a11y.tables.headers_missing", 70],
  ["a11y.structure.h1_missing", 65]
]);

export type ScoredCategories = Record<A11yCategory, A11yScoreCategory>;

/** Score a single page (0-100) from its findings. */
export function scorePage(findings: A11yFinding[]): {
  score: number;
  grade: ReportGrade;
  categories: ScoredCategories;
} {
  const categories = buildInitialCategories();

  for (const finding of findings) {
    if (finding.status !== "fail" && finding.status !== "warn") {
      continue;
    }
    const category = categories[finding.category];
    if (!category || category.max === 0) {
      continue;
    }
    category.score = Math.max(0, category.score - severityDeduction(finding.severity));
    if (finding.severity === "critical") {
      category.score = Math.min(category.score, Math.floor(category.max / 2));
    }
  }

  const total = scorableTotal(categories);
  return { score: total, grade: gradeScore(total), categories };
}

/** Aggregate per-page scores into the site-wide report score block. */
export function buildReportScore(pages: A11yPageResult[]): A11yReport["score"] {
  const scored = pages.filter((page) => !page.error);
  const categories = buildInitialCategories();

  if (scored.length === 0) {
    return { total: 0, grade: gradeScore(0), categories };
  }

  // Average each category across the pages that were scored.
  for (const key of Object.keys(categories) as A11yCategory[]) {
    if (categories[key].max === 0) {
      continue;
    }
    const sum = scored.reduce((acc, page) => acc + categoryScore(page.findings, key), 0);
    categories[key].score = Math.round(sum / scored.length);
  }

  const total = Math.round(scored.reduce((acc, page) => acc + page.score, 0) / scored.length);
  const weakest = scored.reduce((worst, page) => (page.score < worst.score ? page : worst));

  return {
    total,
    grade: gradeScore(total),
    categories,
    weakestPage: { url: weakest.url, score: weakest.score, grade: weakest.grade }
  };
}

export function countFindings(findings: A11yFinding[]): Record<FindingStatus, number> {
  const counts: Record<FindingStatus, number> = { pass: 0, warn: 0, fail: 0, info: 0, skip: 0 };
  for (const finding of findings) {
    counts[finding.status] += 1;
  }
  return counts;
}

export function buildHeadline(counts: Record<FindingStatus, number>, pageCount: number): string {
  const pages = `${pageCount} page${pageCount === 1 ? "" : "s"}`;
  if (counts.fail > 0 && counts.warn > 0) {
    return `Scanned ${pages}: ${counts.fail} accessibility failures and ${counts.warn} warnings.`;
  }
  if (counts.fail > 0) {
    return `Scanned ${pages}: ${counts.fail} accessibility failures.`;
  }
  if (counts.warn > 0) {
    return `Scanned ${pages}: ${counts.warn} warnings, no outright failures.`;
  }
  return `Scanned ${pages}: no machine-detectable issues found.`;
}

export function buildTopFixes(findings: A11yFinding[]): string[] {
  const ranked = findings
    .map((finding, index) => ({ finding, index }))
    .filter(
      ({ finding }) =>
        (finding.status === "fail" || finding.status === "warn") && Boolean(finding.fix)
    )
    .sort((a, b) => {
      const severityDifference = severityRank(b.finding.severity) - severityRank(a.finding.severity);
      if (severityDifference !== 0) {
        return severityDifference;
      }
      const priorityDifference =
        (TOP_FIX_PRIORITY.get(b.finding.id) ?? 0) - (TOP_FIX_PRIORITY.get(a.finding.id) ?? 0);
      if (priorityDifference !== 0) {
        return priorityDifference;
      }
      return a.index - b.index;
    })
    .map(({ finding }) => finding.fix)
    .filter((fix): fix is string => Boolean(fix));

  const unique = [...new Set(ranked)];
  return unique.length > 0 ? unique.slice(0, 5) : ["No machine-detectable fixes were needed."];
}

function buildInitialCategories(): ScoredCategories {
  const categories = {} as ScoredCategories;
  for (const [key, max] of Object.entries(CATEGORY_MAX)) {
    categories[key as A11yCategory] = { score: max, max };
  }
  // "meta" carries the disclaimer finding and does not affect the score.
  categories.meta = { score: 0, max: 0 };
  return categories;
}

function categoryScore(findings: A11yFinding[], category: A11yCategory): number {
  const max = CATEGORY_MAX[category as Exclude<A11yCategory, "meta">] ?? 0;
  if (max === 0) {
    return 0;
  }
  let score = max;
  for (const finding of findings) {
    if (finding.category !== category) {
      continue;
    }
    if (finding.status !== "fail" && finding.status !== "warn") {
      continue;
    }
    score = Math.max(0, score - severityDeduction(finding.severity));
    if (finding.severity === "critical") {
      score = Math.min(score, Math.floor(max / 2));
    }
  }
  return score;
}

function scorableTotal(categories: ScoredCategories): number {
  return Object.values(categories).reduce((sum, category) => sum + category.score, 0);
}

function severityDeduction(severity: A11yFinding["severity"]): number {
  switch (severity) {
    case "critical":
      return 20;
    case "high":
      return 10;
    case "medium":
      return 5;
    case "low":
      return 2;
    case "info":
      return 0;
  }
}

function severityRank(severity: A11yFinding["severity"]): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
  }
}
