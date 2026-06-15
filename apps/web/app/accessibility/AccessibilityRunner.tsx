"use client";

import { useState } from "react";
import type { FormEvent } from "react";

import type { A11yFinding, A11yPageResult, A11yReport } from "@bsns/a11y-core";

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
  | { status: "success"; report: A11yReport };

type A11yResponse = { ok: true; report: A11yReport } | ScanApiErrorBody;

export function AccessibilityRunner() {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<ScanState>({ status: "idle" });

  async function runScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setState({
        status: "error",
        error: { title: "Check the address", message: "Enter a website URL." }
      });
      return;
    }

    setState({ status: "loading" });
    try {
      const response = await fetch("/api/accessibility", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: trimmed })
      });
      const body = await readResponse(response);

      if (!response.ok || !body.ok) {
        const errorBody: ScanApiErrorBody = body.ok
          ? {
              ok: false,
              error: {
                code: "SCAN_FAILED",
                message: `The scanner returned HTTP ${response.status}. Try again in a moment.`
              }
            }
          : body;
        setState({
          status: "error",
          error: buildScanUiError({ body: errorBody, headers: response.headers, status: response.status })
        });
        return;
      }

      setState({ status: "success", report: body.report });
    } catch {
      setState({ status: "error", error: networkScanUiError() });
    }
  }

  return (
    <section className="probe-runner" aria-label="Website accessibility checker">
      <form className="scan-form" onSubmit={runScan}>
        <label htmlFor="a11y-url">Website URL</label>
        <div className="scan-row">
          <input
            id="a11y-url"
            name="url"
            placeholder="https://example.com"
            required
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            aria-describedby="a11y-url-help"
            value={url}
            onChange={(event) => setUrl(event.currentTarget.value)}
          />
          <button type="submit" disabled={state.status === "loading"}>
            {state.status === "loading" ? "Checking" : "Check accessibility"}
          </button>
        </div>
        <p className="field-help" id="a11y-url-help">
          Enter any public page URL. The scan also follows a few key links (contact, menu, booking).
          Private hostnames and internal IPs are rejected.
        </p>
        <div className="quick-actions" aria-label="Examples">
          <button type="button" className="link-button" onClick={() => setUrl("https://bsns.cc")}>
            Try bsns.cc
          </button>
        </div>
        <p className="scan-promise">
          Checks machine-detectable accessibility issues: image alt text, form labels, headings,
          link names, page language, and zoom. Most scans finish in a few seconds.
        </p>
      </form>

      {state.status === "loading" ? (
        <p className="form-status" role="status" aria-live="polite">
          Fetching pages and checking accessibility. This can take several seconds.
        </p>
      ) : null}

      {state.status === "error" ? (
        <div className="form-error" role="alert">
          <strong>{state.error.title}</strong>
          <p>{state.error.message}</p>
          {state.error.detail ? <p className="form-error-detail">{state.error.detail}</p> : null}
        </div>
      ) : null}

      {state.status === "success" ? <A11yReportView report={state.report} /> : null}
    </section>
  );
}

async function readResponse(response: Response): Promise<A11yResponse> {
  try {
    return (await response.json()) as A11yResponse;
  } catch {
    return unreadableScanResponseError(response.status);
  }
}

export function A11yReportView({ report }: { report: A11yReport }) {
  const hasPriorityFixes = report.summary.topFixes.some(
    (fix) => !fix.toLowerCase().startsWith("no machine-detectable")
  );

  return (
    <div className="report-preview">
      <div className="score-row">
        <div>
          <p className="eyebrow">Accessibility</p>
          <h2>{report.target.hostname}</h2>
        </div>
        <div className="score-badge">
          <span>{report.score.grade}</span>
          <small>{report.score.total}/100</small>
        </div>
      </div>

      <p className="report-headline">{report.summary.headline}</p>

      <p className="field-help">{report.summary.disclaimer}</p>

      {report.score.weakestPage ? (
        <p className="report-headline">
          Weakest page: <a href={report.score.weakestPage.url}>{report.score.weakestPage.url}</a> (
          {report.score.weakestPage.score}/100)
        </p>
      ) : null}

      <div className="fix-list">
        <h3>{hasPriorityFixes ? "Fix these first" : "No urgent fixes"}</h3>
        <ol>
          {report.summary.topFixes.map((fix) => (
            <li key={fix}>{fix}</li>
          ))}
        </ol>
      </div>

      <div className="category-grid">
        {Object.entries(report.score.categories)
          .filter(([, value]) => value.max > 0)
          .map(([key, value]) => (
            <div className="category-score" key={key}>
              <span>{formatCategory(key)}</span>
              <strong>
                {value.score}/{value.max}
              </strong>
            </div>
          ))}
      </div>

      <div className="findings-list">
        {report.pages.map((page) => (
          <PageSection key={page.url} page={page} />
        ))}
      </div>

      <div className="export-actions">
        <DownloadButton
          filename={`${report.target.hostname}-accessibility.json`}
          label="Download JSON"
          value={JSON.stringify(report, null, 2)}
        />
      </div>
    </div>
  );
}

function PageSection({ page }: { page: A11yPageResult }) {
  return (
    <section className="finding-group">
      <div className="finding-group-header">
        <h3>
          {page.url} {page.discovery === "seed" ? "(entered)" : ""}
        </h3>
        <span>{page.error ? "—" : `${page.score}/100 ${page.grade}`}</span>
      </div>

      {page.error ? (
        <article>
          <div>
            <p>Could not scan this page ({page.error.code}): {page.error.message}</p>
          </div>
        </article>
      ) : (
        sortFindings(page.findings).map((finding) => (
          <article key={finding.id}>
            <div>
              <div className="finding-title-row">
                <h4>{finding.title}</h4>
                <span data-status={finding.status}>{finding.status}</span>
              </div>
              <p>{finding.summary}</p>
              {finding.whyItMatters ? <p className="finding-note">{finding.whyItMatters}</p> : null}
              {finding.fix ? <p className="finding-fix">{finding.fix}</p> : null}
            </div>
          </article>
        ))
      )}
    </section>
  );
}

function DownloadButton({
  filename,
  label,
  value
}: {
  filename: string;
  label: string;
  value: string;
}) {
  function download() {
    const blob = new Blob([value], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  return (
    <button className="secondary-button" type="button" onClick={download}>
      {label}
    </button>
  );
}

const STATUS_ORDER: Record<A11yFinding["status"], number> = {
  fail: 0,
  warn: 1,
  info: 2,
  pass: 3,
  skip: 4
};

function sortFindings(findings: A11yFinding[]): A11yFinding[] {
  return [...findings].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
}

function formatCategory(category: string): string {
  const labels: Record<string, string> = {
    images: "Images",
    forms: "Forms",
    language: "Language",
    structure: "Structure",
    links: "Links & buttons",
    tables: "Tables"
  };
  return labels[category] ?? `${category.charAt(0).toUpperCase()}${category.slice(1)}`;
}
