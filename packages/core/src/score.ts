import type {
  Finding,
  FindingStatus,
  ProbeReport,
  ReportGrade,
  ScoreCategory
} from "./types.js";

const CATEGORY_MAX = {
  dns: 20,
  web: 30,
  email: 30,
  headers: 15,
  performance: 5
};

const TOP_FIX_PRIORITY = new Map<string, number>([
  ["tls.expired", 100],
  ["web.https.unreachable", 95],
  ["web.redirect.to_http", 90],
  ["email.spf.lookup_limit_exceeded", 85],
  ["email.spf.permissive_all", 84],
  ["email.spf.multiple_records", 83],
  ["email.dmarc.multiple_records", 82],
  ["email.dmarc.missing", 80],
  ["email.spf.missing", 78],
  ["tls.expiring_soon", 75],
  ["tls.hostname_mismatch", 74],
  ["tls.untrusted_chain", 73],
  ["web.http.no_https_redirect", 70],
  ["headers.hsts.missing", 65],
  ["headers.hsts.short_max_age", 64]
]);

export function buildScore(findings: Finding[]): ProbeReport["score"] {
  const categories = buildInitialCategories();

  for (const finding of findings) {
    if (finding.status !== "fail" && finding.status !== "warn") {
      continue;
    }

    const categoryKey = scoreCategoryForFinding(finding);
    if (!categoryKey) {
      continue;
    }

    const category = categories[categoryKey];
    if (!category) {
      continue;
    }

    const deduction = severityDeduction(finding.severity);
    category.score = Math.max(0, category.score - deduction);

    if (finding.severity === "critical") {
      category.score = Math.min(category.score, Math.floor(category.max / 2));
    }
  }

  const total = Object.values(categories).reduce((sum, category) => sum + category.score, 0);

  return {
    total,
    grade: gradeScore(total),
    categories
  };
}

export function buildSummary(findings: Finding[]): ProbeReport["summary"] {
  const counts = countFindings(findings);

  return {
    headline: buildHeadline(counts),
    topFixes: buildTopFixes(findings),
    counts
  };
}

export function countFindings(findings: Finding[]): Record<FindingStatus, number> {
  const counts: Record<FindingStatus, number> = {
    pass: 0,
    warn: 0,
    fail: 0,
    info: 0,
    skip: 0
  };

  for (const finding of findings) {
    counts[finding.status] += 1;
  }

  return counts;
}

export function gradeScore(total: number): ReportGrade {
  if (total >= 90) {
    return "A";
  }

  if (total >= 80) {
    return "B";
  }

  if (total >= 65) {
    return "C";
  }

  if (total >= 50) {
    return "D";
  }

  return "F";
}

function buildInitialCategories(): ProbeReport["score"]["categories"] {
  return Object.fromEntries(
    Object.entries(CATEGORY_MAX).map(([category, max]) => [
      category,
      { score: max, max } satisfies ScoreCategory
    ])
  );
}

function buildHeadline(counts: Record<FindingStatus, number>): string {
  if (counts.fail > 0 && counts.warn > 0) {
    return `Scan complete with ${counts.fail} failed checks and ${counts.warn} warnings.`;
  }

  if (counts.fail > 0) {
    return `Scan complete with ${counts.fail} failed checks.`;
  }

  if (counts.warn > 0) {
    return `Scan complete with ${counts.warn} warnings.`;
  }

  return "Scan complete with no urgent fixes found.";
}

function buildTopFixes(findings: Finding[]): string[] {
  const fixes = findings
    .map((finding, index) => ({ finding, index }))
    .filter(
      ({ finding }) =>
        (finding.status === "fail" || finding.status === "warn") &&
        severityRank(finding.severity) >= severityRank("medium") &&
        Boolean(finding.fix)
    )
    .sort((a, b) => {
      const severityDifference =
        severityRank(b.finding.severity) - severityRank(a.finding.severity);
      if (severityDifference !== 0) {
        return severityDifference;
      }

      const priorityDifference =
        topFixPriority(b.finding.id) - topFixPriority(a.finding.id);
      if (priorityDifference !== 0) {
        return priorityDifference;
      }

      return a.index - b.index;
    })
    .map(({ finding }) => finding.fix)
    .filter((fix): fix is string => Boolean(fix));

  const uniqueFixes = [...new Set(fixes)];

  if (uniqueFixes.length > 0) {
    return uniqueFixes.slice(0, 5);
  }

  return ["No urgent fixes found in the checks that completed."];
}

function scoreCategoryForFinding(finding: Finding): keyof typeof CATEGORY_MAX | null {
  if (finding.category === "tls") {
    return "web";
  }

  if (finding.category in CATEGORY_MAX) {
    return finding.category as keyof typeof CATEGORY_MAX;
  }

  return null;
}

function severityDeduction(severity: Finding["severity"]): number {
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

function severityRank(severity: Finding["severity"]): number {
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

function topFixPriority(id: string): number {
  return TOP_FIX_PRIORITY.get(id) ?? 0;
}
