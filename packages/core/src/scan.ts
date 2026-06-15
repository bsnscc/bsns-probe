import type { DnsCheckResult } from "./dns.js";
import type { EmailCheckResult } from "./email.js";
import type { HttpCheckResult, HttpFetchResult } from "./http.js";
import type { TlsCheckResult } from "./tls.js";
import type { Finding, ProbeReport, ScanOptions } from "./types.js";
import { checkDns } from "./dns.js";
import { checkEmail } from "./email.js";
import { checkHeaders } from "./headers.js";
import { ProbeInputError, normalizeDomainInput } from "./domain.js";
import { checkHttp } from "./http.js";
import { checkPerformance } from "./performance.js";
import { checkTls } from "./tls.js";
import { buildScore, buildSummary } from "./score.js";

const DEFAULT_SCAN_TIMEOUT_MS = 15000;

export async function scanDomain(
  input: string,
  options: ScanOptions = {}
): Promise<ProbeReport> {
  const target = normalizeDomainInput(input);
  const scannedAt = new Date().toISOString();
  const timeoutMs = options.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
  const dns = await runPartialCheck(
    () => checkDns(target, options.dnsResolver),
    timeoutMs,
    () => partialDnsResult(target.asciiHostname, target.registrableDomain, timeoutMs),
    (error) => partialDnsResult(target.asciiHostname, target.registrableDomain, timeoutMs, error)
  );
  const [http, tls, email] = hasPartialDnsResult(dns)
    ? [
        skippedHttpResult(target.asciiHostname, "DNS validation did not complete."),
        skippedTlsResult(target.asciiHostname, "DNS validation did not complete."),
        skippedEmailResult(target.registrableDomain ?? target.asciiHostname, "DNS validation did not complete.")
      ]
    : await Promise.all([
        runPartialCheck(
          () =>
            checkHttp(target, {
              addressResolver: options.addressResolver,
              client: options.httpClient,
              timeoutMs
            }),
          timeoutMs,
          () => partialHttpResult(target.asciiHostname, timeoutMs),
          (error) => partialHttpResult(target.asciiHostname, timeoutMs, error)
        ),
        runPartialCheck(
          () =>
            checkTls(target, {
              addressResolver: options.addressResolver,
              inspector: options.tlsInspector,
              timeoutMs
            }),
          timeoutMs,
          () => partialTlsResult(target.asciiHostname, timeoutMs),
          (error) => partialTlsResult(target.asciiHostname, timeoutMs, error)
        ),
        runPartialCheck(
          () =>
            checkEmail(target, {
              addressResolver: options.addressResolver,
              httpClient: options.httpClient,
              resolver: options.dnsResolver,
              selectors: options.dkimSelectors,
              timeoutMs
            }),
          timeoutMs,
          () => partialEmailResult(target.registrableDomain ?? target.asciiHostname, timeoutMs),
          (error) =>
            partialEmailResult(target.registrableDomain ?? target.asciiHostname, timeoutMs, error)
        )
      ]);
  const headers = checkHeaders(http.raw);
  const performance = checkPerformance(http.raw);
  const findings = [
    ...dns.findings,
    ...http.findings,
    ...tls.findings,
    ...headers.findings,
    ...email.findings,
    ...performance.findings
  ];
  const score = buildScore(findings);
  const summary = buildSummary(findings);

  return {
    schemaVersion: "1.0",
    target: {
      input,
      hostname: target.hostname,
      asciiHostname: target.asciiHostname,
      registrableDomain: target.registrableDomain,
      scannedAt
    },
    score,
    summary,
    findings,
    raw:
      options.includeRaw === false
        ? {}
        : buildRaw(options, dns.raw, http.raw, tls.raw, email.raw, performance.raw)
  };
}

function buildRaw(
  options: ScanOptions,
  dns: unknown,
  http: unknown,
  tls: unknown,
  email: unknown,
  performance: unknown
): ProbeReport["raw"] {
  return {
    dns,
    http,
    tls,
    email,
    performance,
    timings: {
      timeoutMs: options.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS,
      mode: "dns-http-tls-email-performance"
    }
  };
}

async function runPartialCheck<T>(
  check: () => Promise<T>,
  timeoutMs: number,
  onTimeout: () => T,
  onError: (error: unknown) => T
): Promise<T> {
  try {
    return await withTimeout(check(), timeoutMs);
  } catch (error) {
    if (error instanceof ProbeInputError) {
      throw error;
    }

    if (error instanceof CheckTimeoutError) {
      return onTimeout();
    }

    return onError(error);
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;

  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      timeout = setTimeout(() => {
        reject(new CheckTimeoutError(timeoutMs));
      }, timeoutMs);
    })
  ]).finally(() => {
    if (timeout) {
      clearTimeout(timeout);
    }
  });
}

function hasPartialDnsResult(result: DnsCheckResult): boolean {
  return result.findings.some(
    (finding) => finding.id === "dns.check.timeout" || finding.id === "dns.check.error"
  );
}

function partialDnsResult(
  hostname: string,
  registrableDomain: string | null,
  timeoutMs: number,
  error?: unknown
): DnsCheckResult {
  const timeout = !error;

  return {
    findings: [
      {
        id: timeout ? "dns.check.timeout" : "dns.check.error",
        category: "dns",
        status: "skip",
        severity: "info",
        title: timeout ? "DNS check timed out" : "DNS check did not complete",
        summary: timeout
          ? `DNS checks for ${hostname} did not finish within ${timeoutMs} ms.`
          : `DNS checks for ${hostname} did not complete.`,
        evidence: buildPartialEvidence(timeoutMs, error),
        whyItMatters: "DNS results are needed before connecting to web and TLS services safely.",
        fix: "Retry the scan. If DNS timeouts persist, check the domain's DNS provider."
      }
    ],
    raw: {
      hostname,
      registrableDomain,
      checkedAt: new Date().toISOString(),
      status: timeout ? "timeout" : "error",
      ...(error ? { error: normalizePartialError(error) } : {}),
      timeoutMs
    }
  };
}

function partialHttpResult(hostname: string, timeoutMs: number, error?: unknown): HttpCheckResult {
  const timeout = !error;
  const normalized = timeout
    ? {
        code: "CHECK_TIMEOUT",
        kind: "timeout" as const,
        message: `HTTP checks did not finish within ${timeoutMs} ms.`
      }
    : {
        code: normalizePartialError(error).code,
        kind: "other" as const,
        message: normalizePartialError(error).message
      };

  return {
    findings: [
      {
        id: timeout ? "web.check.timeout" : "web.check.error",
        category: "web",
        status: "skip",
        severity: "info",
        title: timeout ? "Web checks timed out" : "Web checks did not complete",
        summary: timeout
          ? `Web reachability checks for ${hostname} did not finish within ${timeoutMs} ms.`
          : `Web reachability checks for ${hostname} did not complete.`,
        evidence: buildPartialEvidence(timeoutMs, error),
        whyItMatters: "HTTP and HTTPS checks are needed before assessing redirects, headers, and performance.",
        fix: "Retry the scan. If it keeps timing out, check web server latency and network reachability."
      }
    ],
    raw: {
      hostname,
      checkedAt: new Date().toISOString(),
      https: partialFetchResult(`https://${hostname}/`, hostname, timeoutMs, normalized),
      http: partialFetchResult(`http://${hostname}/`, hostname, timeoutMs, normalized)
    }
  };
}

function skippedHttpResult(hostname: string, reason: string): HttpCheckResult {
  const error = {
    code: "SKIPPED",
    kind: "other" as const,
    message: reason
  };

  return {
    findings: [
      {
        id: "web.check.skipped",
        category: "web",
        status: "skip",
        severity: "info",
        title: "Web checks skipped",
        summary: `Web reachability checks for ${hostname} were skipped.`,
        evidence: { reason },
        whyItMatters: "The scanner only connects to hosts after public DNS validation completes.",
        fix: "Retry the scan after DNS checks complete successfully."
      }
    ],
    raw: {
      hostname,
      checkedAt: new Date().toISOString(),
      https: partialFetchResult(`https://${hostname}/`, hostname, 0, error),
      http: partialFetchResult(`http://${hostname}/`, hostname, 0, error)
    }
  };
}

function partialFetchResult(
  url: string,
  hostname: string,
  timeoutMs: number,
  error: HttpFetchResult["attempts"][number]["error"]
): HttpFetchResult {
  return {
    startUrl: url,
    status: "error",
    attempts: [
      {
        url,
        hostname,
        responseTimeMs: timeoutMs,
        error
      }
    ],
    totalTimeMs: timeoutMs
  };
}

function partialTlsResult(hostname: string, timeoutMs: number, error?: unknown): TlsCheckResult {
  const timeout = !error;

  return {
    findings: [
      {
        id: timeout ? "tls.check.timeout" : "tls.check.error",
        category: "tls",
        status: "skip",
        severity: "info",
        title: timeout ? "TLS check timed out" : "TLS check did not complete",
        summary: timeout
          ? `TLS inspection for ${hostname} did not finish within ${timeoutMs} ms.`
          : `TLS inspection for ${hostname} did not complete.`,
        evidence: buildPartialEvidence(timeoutMs, error),
        whyItMatters: "TLS findings depend on completing a certificate handshake.",
        fix: "Retry the scan. If it keeps timing out, check the TLS listener on port 443."
      }
    ],
    raw: {
      hostname,
      checkedAt: new Date().toISOString(),
      handshake: false,
      chainTrusted: false,
      error: normalizePartialError(error ?? new CheckTimeoutError(timeoutMs))
    }
  };
}

function skippedTlsResult(hostname: string, reason: string): TlsCheckResult {
  return {
    findings: [
      {
        id: "tls.check.skipped",
        category: "tls",
        status: "skip",
        severity: "info",
        title: "TLS check skipped",
        summary: `TLS inspection for ${hostname} was skipped.`,
        evidence: { reason },
        whyItMatters: "The scanner only connects to hosts after public DNS validation completes.",
        fix: "Retry the scan after DNS checks complete successfully."
      }
    ],
    raw: {
      hostname,
      checkedAt: new Date().toISOString(),
      handshake: false,
      chainTrusted: false,
      error: {
        code: "SKIPPED",
        message: reason
      }
    }
  };
}

function partialEmailResult(domain: string, timeoutMs: number, error?: unknown): EmailCheckResult {
  const timeout = !error;

  return {
    findings: [
      {
        id: timeout ? "email.check.timeout" : "email.check.error",
        category: "email",
        status: "skip",
        severity: "info",
        title: timeout ? "Email checks timed out" : "Email checks did not complete",
        summary: timeout
          ? `Email authentication checks for ${domain} did not finish within ${timeoutMs} ms.`
          : `Email authentication checks for ${domain} did not complete.`,
        evidence: buildPartialEvidence(timeoutMs, error),
        whyItMatters: "SPF, DMARC, DKIM, MTA-STS, and TLS-RPT findings depend on DNS lookups.",
        fix: "Retry the scan. If DNS keeps timing out, check the domain's DNS provider."
      }
    ],
    raw: {
      domain,
      checkedAt: new Date().toISOString(),
      status: timeout ? "timeout" : "error",
      ...(error ? { error: normalizePartialError(error) } : {}),
      timeoutMs
    }
  };
}

function skippedEmailResult(domain: string, reason: string): EmailCheckResult {
  return {
    findings: [
      {
        id: "email.check.skipped",
        category: "email",
        status: "skip",
        severity: "info",
        title: "Email checks skipped",
        summary: `Email authentication checks for ${domain} were skipped.`,
        evidence: { reason },
        whyItMatters: "Email checks depend on DNS completing reliably.",
        fix: "Retry the scan after DNS checks complete successfully."
      }
    ],
    raw: {
      domain,
      checkedAt: new Date().toISOString(),
      status: "skipped",
      reason
    }
  };
}

function buildPartialEvidence(timeoutMs: number, error?: unknown): Record<string, unknown> {
  return {
    timeoutMs,
    ...(error ? { error: normalizePartialError(error) } : {})
  };
}

function normalizePartialError(error: unknown): { code: string; message: string } {
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && code.length > 0) {
      return {
        code,
        message: error instanceof Error ? error.message : "Check did not complete."
      };
    }
  }

  return {
    code: error instanceof Error && error.name ? error.name : "CHECK_FAILED",
    message: error instanceof Error ? error.message : "Check did not complete."
  };
}

class CheckTimeoutError extends Error {
  readonly code = "CHECK_TIMEOUT";

  constructor(timeoutMs: number) {
    super(`Check did not finish within ${timeoutMs} ms.`);
    this.name = "CheckTimeoutError";
  }
}
