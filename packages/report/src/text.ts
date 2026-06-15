import type { ProbeReport } from "@bsns/probe-core";

const ORDERED_CATEGORIES = [
  ["dns", "DNS"],
  ["web", "Web/TLS"],
  ["email", "Email"],
  ["headers", "Headers"],
  ["performance", "Perf"]
] as const;

export function renderTextReport(report: ProbeReport): string {
  const hasPriorityFixes = report.summary.topFixes.some(isPriorityFix);
  const lines = [
    `bsns probe: ${report.target.hostname}`,
    `Score: ${report.score.grade} / ${report.score.total}`,
    "",
    hasPriorityFixes ? "Fix these first:" : "No urgent fixes:"
  ];

  if (report.summary.topFixes.length === 0) {
    lines.push("No priority fixes found.");
  } else if (!hasPriorityFixes) {
    lines.push(...report.summary.topFixes);
  } else {
    report.summary.topFixes.forEach((fix, index) => {
      lines.push(`${index + 1}. ${fix}`);
    });
  }

  lines.push("");

  for (const [key, label] of ORDERED_CATEGORIES) {
    const category = report.score.categories[key];
    if (!category) {
      continue;
    }

    lines.push(`${label.padEnd(10)} ${category.score}/${category.max}`);
  }

  return `${lines.join("\n")}\n`;
}

function isPriorityFix(fix: string): boolean {
  return !fix.toLowerCase().startsWith("no urgent fixes");
}
