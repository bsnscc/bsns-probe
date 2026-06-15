import type { A11yFinding, A11yPageResult, A11yReport } from "./types.js";

/** Stable JSON serialization of an accessibility report. */
export function renderA11yJson(report: A11yReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

/** Plain-text report for terminals. */
export function renderA11yText(report: A11yReport): string {
  const lines: string[] = [];
  lines.push(`bsns accessibility — ${report.target.hostname}`);
  lines.push(`Scanned ${report.target.seedUrl} at ${report.target.scannedAt}`);
  lines.push("");
  lines.push(`Score: ${report.score.total}/100 (${report.score.grade})`);
  lines.push(report.summary.headline);
  if (report.score.weakestPage) {
    lines.push(
      `Weakest page: ${report.score.weakestPage.url} (${report.score.weakestPage.score}/100)`
    );
  }
  lines.push("");
  lines.push("Fix these first:");
  for (const fix of report.summary.topFixes) {
    lines.push(`  - ${fix}`);
  }
  lines.push("");
  for (const page of report.pages) {
    lines.push(`Page: ${page.url}  [${page.discovery}]`);
    if (page.error) {
      lines.push(`  could not scan (${page.error.code}): ${page.error.message}`);
      lines.push("");
      continue;
    }
    lines.push(`  Score: ${page.score}/100 (${page.grade})`);
    for (const finding of sortFindings(page.findings)) {
      if (finding.status === "pass" || finding.status === "info") {
        continue;
      }
      lines.push(`  [${finding.status.toUpperCase()}] ${finding.title}`);
      if (finding.fix) {
        lines.push(`        fix: ${finding.fix}`);
      }
    }
    lines.push("");
  }
  lines.push(report.summary.disclaimer);
  return `${lines.join("\n")}\n`;
}

/** Markdown report suitable for sharing or handing to a developer. */
export function renderA11yMarkdown(report: A11yReport): string {
  const lines: string[] = [];
  lines.push(`# Accessibility report — ${report.target.hostname}`);
  lines.push("");
  lines.push(`**Score:** ${report.score.total}/100 (${report.score.grade})`);
  lines.push("");
  lines.push(report.summary.headline);
  if (report.score.weakestPage) {
    lines.push("");
    lines.push(
      `**Weakest page:** [${report.score.weakestPage.url}](${report.score.weakestPage.url}) — ${report.score.weakestPage.score}/100`
    );
  }
  lines.push("");
  lines.push("## Fix these first");
  lines.push("");
  for (const fix of report.summary.topFixes) {
    lines.push(`1. ${fix}`);
  }
  lines.push("");
  for (const page of report.pages) {
    lines.push(`## ${page.url}`);
    lines.push("");
    if (page.error) {
      lines.push(`> Could not scan this page (${page.error.code}): ${page.error.message}`);
      lines.push("");
      continue;
    }
    lines.push(`Score: ${page.score}/100 (${page.grade})`);
    lines.push("");
    for (const finding of sortFindings(page.findings)) {
      const badge = finding.status === "pass" ? "✓" : finding.status === "info" ? "·" : "✗";
      lines.push(`- ${badge} **${finding.title}** — ${finding.summary}`);
      if (finding.fix && finding.status !== "pass") {
        lines.push(`  - _Fix:_ ${finding.fix}`);
      }
    }
    lines.push("");
  }
  lines.push("---");
  lines.push("");
  lines.push(`_${report.summary.disclaimer}_`);
  lines.push("");
  return lines.join("\n");
}

const STATUS_ORDER: Record<A11yFinding["status"], number> = {
  fail: 0,
  warn: 1,
  info: 2,
  pass: 3,
  skip: 4
};

function sortFindings(findings: A11yPageResult["findings"]): A11yFinding[] {
  return [...findings].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
}
