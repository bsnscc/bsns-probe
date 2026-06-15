#!/usr/bin/env node
import { Command, Option } from "commander";

import { scanDomain } from "@bsns/probe-core";
import {
  renderJsonReport,
  renderMarkdownReport,
  renderTextReport
} from "@bsns/probe-report";

const program = new Command()
  .name("bsns-probe")
  .description("Check a domain's DNS, website, TLS, headers, and email setup.")
  .argument("<domain>", "Domain name to scan")
  .option("--json", "Print JSON output")
  .option("--markdown", "Print Markdown output")
  .option("--selectors <selectors>", "Comma-separated DKIM selectors to check")
  .option("--timeout <ms>", "Per-check timeout in milliseconds", parseTimeout, 15000)
  .option("--no-raw", "Omit raw diagnostic data from the report")
  .addOption(
    new Option("--fail-on <level>", "Exit 2 when findings meet this threshold").choices([
      "warn",
      "fail"
    ])
  );

program.action(async (domain: string, options: CliOptions) => {
  try {
    const report = await scanDomain(domain, {
      dkimSelectors: parseSelectors(options.selectors),
      includeRaw: options.raw,
      timeoutMs: options.timeout
    });

    if (options.json) {
      process.stdout.write(renderJsonReport(report));
    } else if (options.markdown) {
      process.stdout.write(renderMarkdownReport(report));
    } else {
      process.stdout.write(renderTextReport(report));
    }

    if (shouldFail(report.summary.counts, options.failOn)) {
      process.exitCode = 2;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown scanner failure.";
    process.stderr.write(`bsns probe failed: ${message}\n`);
    process.exitCode = 1;
  }
});

await program.parseAsync(process.argv);

interface CliOptions {
  json?: boolean;
  markdown?: boolean;
  selectors?: string;
  timeout: number;
  raw: boolean;
  failOn?: "warn" | "fail";
}

function parseTimeout(value: string): number {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error("Timeout must be a positive number of milliseconds.");
  }

  return parsed;
}

function parseSelectors(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((selector) => selector.trim())
    .filter(Boolean);
}

function shouldFail(
  counts: { warn: number; fail: number },
  failOn: CliOptions["failOn"]
): boolean {
  if (failOn === "fail") {
    return counts.fail > 0;
  }

  if (failOn === "warn") {
    return counts.fail > 0 || counts.warn > 0;
  }

  return false;
}
