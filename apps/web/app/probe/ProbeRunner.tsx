"use client";

import { useMemo, useState } from "react";
import type { FormEvent } from "react";

import type { Finding, ProbeReport } from "@bsns/probe-core";
import { renderMarkdownReport } from "@bsns/probe-report";

import {
  buildScanUiError,
  networkScanUiError,
  unreadableScanResponseError,
  type ScanApiErrorBody,
  type ScanUiError
} from "@/lib/scan-error";

type ScanState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; error: ScanUiError }
  | { status: "success"; report: ProbeReport };
type CopyState = "idle" | "copied" | "error";

interface ProbeRunnerProps {
  compact?: boolean;
}

export function ProbeRunner({ compact = false }: ProbeRunnerProps) {
  const [domain, setDomain] = useState("");
  const [selectorInput, setSelectorInput] = useState("");
  const [state, setState] = useState<ScanState>({ status: "idle" });
  const domainInputId = compact ? "home-domain" : "probe-domain";
  const domainHelpId = compact ? "home-domain-help" : "probe-domain-help";

  async function runScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedDomain = domain.trim();

    if (!trimmedDomain) {
      setState({
        status: "error",
        error: {
          title: "Check the domain",
          message: "Enter a domain name."
        }
      });
      return;
    }

    setState({ status: "loading" });

    try {
      const response = await fetch("/api/probe/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json"
        },
        body: JSON.stringify({
          domain: trimmedDomain,
          dkimSelectors: parseSelectors(selectorInput),
          includeRaw: !compact
        })
      });
      const body = await readScanResponse(response);

      if (!response.ok || !body.ok) {
        const errorBody = body.ok
          ? ({
              ok: false,
              error: {
                code: "SCAN_FAILED",
                message: `The scanner returned HTTP ${response.status}. Try again in a moment.`
              }
            } satisfies ScanApiErrorBody)
          : body;

        setState({
          status: "error",
          error: buildScanUiError({
            body: errorBody,
            headers: response.headers,
            status: response.status
          })
        });
        return;
      }

      setState({ status: "success", report: body.report });
    } catch {
      setState({
        status: "error",
        error: networkScanUiError()
      });
    }
  }

  return (
    <section className="probe-runner" aria-label="Domain health checker">
      <form className="scan-form" onSubmit={runScan}>
        <label htmlFor={domainInputId}>Domain</label>
        <div className="scan-row">
          <input
            id={domainInputId}
            name="domain"
            placeholder="example.com"
            required
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            aria-describedby={domainHelpId}
            value={domain}
            onChange={(event) => setDomain(event.currentTarget.value)}
          />
          <button type="submit" disabled={state.status === "loading"}>
            {state.status === "loading" ? "Checking" : "Run check"}
          </button>
        </div>
        <p className="field-help" id={domainHelpId}>
          Enter a public domain, like example.com. Private hostnames and internal IPs are rejected.
        </p>
        <div className="quick-actions" aria-label="Examples">
          <button type="button" className="link-button" onClick={() => setDomain("bsns.cc")}>
            Try bsns.cc
          </button>
          <a href="#sample-report">View sample report</a>
        </div>
        {!compact ? (
          <details className="advanced-checks">
            <summary>Advanced email checks</summary>
            <div className="advanced-field">
              <label htmlFor="dkim-selectors">DKIM selectors</label>
              <input
                id="dkim-selectors"
                name="dkimSelectors"
                placeholder="google, selector1, selector2"
                type="text"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={selectorInput}
                onChange={(event) => setSelectorInput(event.currentTarget.value)}
              />
              <p className="field-help">
                Optional. Common selectors include google, selector1, selector2, k1, and default.
              </p>
            </div>
          </details>
        ) : null}
        <p className="scan-promise">
          Checks public DNS, website reachability, TLS, headers, and email authentication records.
          Most scans finish quickly; slow domains can take up to 15 seconds.
        </p>
      </form>

      {state.status === "loading" ? (
        <p className="form-status" role="status" aria-live="polite">
          Running DNS, web, TLS, header, email, and performance checks. This can take up to 15
          seconds.
        </p>
      ) : null}

      {state.status === "error" ? <FormError error={state.error} /> : null}

      {state.status === "success" ? (
        <ReportPreview report={state.report} compact={compact} />
      ) : null}
    </section>
  );
}

function FormError({ error }: { error: ScanUiError }) {
  return (
    <div className="form-error" role="alert">
      <strong>{error.title}</strong>
      <p>{error.message}</p>
      {error.detail ? <p className="form-error-detail">{error.detail}</p> : null}
    </div>
  );
}

async function readScanResponse(response: Response): Promise<ScanResponse> {
  try {
    return (await response.json()) as ScanResponse;
  } catch {
    return unreadableScanResponseError(response.status);
  }
}

export function ReportPreview({
  compact,
  report
}: {
  compact: boolean;
  report: ProbeReport;
}) {
  const markdown = useMemo(() => renderMarkdownReport(report), [report]);
  const groupedFindings = groupFindings(report.findings);
  const rawSections = buildRawSections(report);
  const hasPriorityFixes = report.summary.topFixes.some(isPriorityFix);

  return (
    <div className="report-preview">
      <div className="score-row">
        <div>
          <p className="eyebrow">Report</p>
          <h2>{report.target.hostname}</h2>
        </div>
        <div className="score-badge">
          <span>{report.score.grade}</span>
          <small>{report.score.total}/100</small>
        </div>
      </div>

      <p className="report-headline">{report.summary.headline}</p>

      <div className="fix-list">
        <h3>{hasPriorityFixes ? "Fix these first" : "No urgent fixes"}</h3>
        <ol>
          {report.summary.topFixes.map((fix) => (
            <li key={fix}>{fix}</li>
          ))}
        </ol>
      </div>

      {!compact ? (
        <>
          <div className="category-grid">
            {Object.entries(report.score.categories).map(([key, value]) => (
              <div className="category-score" key={key}>
                <span>{formatCategory(key)}</span>
                <strong>
                  {value.score}/{value.max}
                </strong>
              </div>
            ))}
          </div>

          <div className="findings-list">
            {groupedFindings.map(([category, findings]) => (
              <section className="finding-group" key={category}>
                <div className="finding-group-header">
                  <h3>{formatCategory(category)}</h3>
                  <span>{findings.length}</span>
                </div>

                {findings.map((finding) => (
                  <article key={finding.id}>
                    <div>
                      <div className="finding-title-row">
                        <h4>{finding.title}</h4>
                        <span data-status={finding.status}>{finding.status}</span>
                      </div>
                      <p>{finding.summary}</p>
                      <dl>
                        <div>
                          <dt>ID</dt>
                          <dd>{finding.id}</dd>
                        </div>
                        <div>
                          <dt>Severity</dt>
                          <dd>{finding.severity}</dd>
                        </div>
                      </dl>
                      {finding.whyItMatters ? (
                        <p className="finding-note">{finding.whyItMatters}</p>
                      ) : null}
                      {finding.fix ? <p className="finding-fix">{finding.fix}</p> : null}
                    </div>
                  </article>
                ))}
              </section>
            ))}
          </div>

          {rawSections.length > 0 ? (
            <section className="raw-records" aria-label="Raw records">
              <h3>Raw records</h3>
              {rawSections.map(([label, value]) => (
                <details key={label}>
                  <summary>{label}</summary>
                  <pre>{JSON.stringify(value, null, 2)}</pre>
                </details>
              ))}
            </section>
          ) : null}

          <div className="export-actions">
            <CopyButton label="Copy Markdown" value={markdown} />
            <DownloadButton
              filename={`${report.target.hostname}-bsns-probe.json`}
              label="Download JSON"
              mimeType="application/json"
              value={JSON.stringify(report, null, 2)}
            />
            <DownloadButton
              filename={`${report.target.hostname}-bsns-probe.md`}
              label="Download Markdown"
              mimeType="text/markdown"
              value={markdown}
            />
          </div>
        </>
      ) : null}
    </div>
  );
}

function CopyButton({ label, value }: { label: string; value: string }) {
  const [status, setStatus] = useState<CopyState>("idle");

  async function copy() {
    try {
      await copyText(value);
      setStatus("copied");
    } catch {
      setStatus("error");
    }

    window.setTimeout(() => setStatus("idle"), 1800);
  }

  return (
    <button className="secondary-button" type="button" onClick={copy}>
      {status === "copied" ? "Copied" : status === "error" ? "Copy failed" : label}
    </button>
  );
}

const CATEGORY_ORDER = ["dns", "web", "tls", "email", "headers", "performance", "meta"];

function groupFindings(findings: Finding[]): Array<[string, Finding[]]> {
  const groups = new Map<string, Finding[]>();

  for (const finding of findings) {
    const existing = groups.get(finding.category) ?? [];
    existing.push(finding);
    groups.set(finding.category, existing);
  }

  return [...groups.entries()].sort((a, b) => categoryRank(a[0]) - categoryRank(b[0]));
}

function categoryRank(category: string): number {
  const index = CATEGORY_ORDER.indexOf(category);
  return index === -1 ? CATEGORY_ORDER.length : index;
}

function buildRawSections(report: ProbeReport): Array<[string, unknown]> {
  return Object.entries(report.raw)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => [formatCategory(key), value]);
}

function isPriorityFix(fix: string): boolean {
  return !fix.toLowerCase().startsWith("no urgent fixes");
}

function parseSelectors(value: string): string[] {
  return value
    .split(",")
    .map((selector) => selector.trim())
    .filter(Boolean);
}

function DownloadButton({
  filename,
  label,
  mimeType,
  value
}: {
  filename: string;
  label: string;
  mimeType: string;
  value: string;
}) {
  function download() {
    const blob = new Blob([value], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <button className="secondary-button" type="button" onClick={download}>
      {label}
    </button>
  );
}

async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.left = "-9999px";
  textarea.style.position = "fixed";
  document.body.appendChild(textarea);
  textarea.select();

  try {
    if (!document.execCommand("copy")) {
      throw new Error("Copy command failed.");
    }
  } finally {
    document.body.removeChild(textarea);
  }
}

function formatCategory(category: string) {
  if (category === "dns") {
    return "DNS";
  }

  if (category === "web") {
    return "Web/TLS";
  }

  if (category === "tls") {
    return "TLS";
  }

  if (category === "dkim") {
    return "DKIM";
  }

  return `${category.charAt(0).toUpperCase()}${category.slice(1)}`;
}

type ScanResponse =
  | { ok: true; report: ProbeReport }
  | ScanApiErrorBody;
