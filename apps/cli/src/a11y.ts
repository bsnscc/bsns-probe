#!/usr/bin/env node
import { Command } from "commander";

import {
  renderA11yJson,
  renderA11yMarkdown,
  renderA11yText,
  scanAccessibility
} from "@bsns/a11y-core";

const program = new Command()
  .name("bsns-a11y")
  .description("Check a website's pages for machine-detectable accessibility issues.")
  .argument("<url>", "Page URL to scan (the scan also follows a few key links)")
  .option("--json", "Print JSON output")
  .option("--markdown", "Print Markdown output")
  .option("--max-pages <n>", "Maximum pages to scan (seed + discovered)", parsePositiveInt, 5)
  .option("--timeout <ms>", "Per-request timeout in milliseconds", parsePositiveInt, 10000);

program.action(async (url: string, options: A11yCliOptions) => {
  try {
    const report = await scanAccessibility(url, {
      maxPages: options.maxPages,
      timeoutMs: options.timeout
    });

    if (options.json) {
      process.stdout.write(renderA11yJson(report));
    } else if (options.markdown) {
      process.stdout.write(renderA11yMarkdown(report));
    } else {
      process.stdout.write(renderA11yText(report));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown scanner failure.";
    process.stderr.write(`bsns a11y failed: ${message}\n`);
    process.exitCode = 1;
  }
});

await program.parseAsync(process.argv);

interface A11yCliOptions {
  json?: boolean;
  markdown?: boolean;
  maxPages: number;
  timeout: number;
}

function parsePositiveInt(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error("Value must be a positive number.");
  }
  return parsed;
}
