import type { HttpRawResult } from "./http.js";
import type { Finding } from "./types.js";

export interface HeaderCheckResult {
  findings: Finding[];
  raw: HeaderRawResult;
}

export interface HeaderRawResult {
  checkedAt: string;
  source: "https-final-response" | "unavailable";
  headers: Record<string, string>;
}

const MIN_HSTS_MAX_AGE = 15_552_000;

export function checkHeaders(http: HttpRawResult): HeaderCheckResult {
  const headers = normalizeHeaders(http.https.finalHeaders ?? {});
  const raw: HeaderRawResult = {
    checkedAt: new Date().toISOString(),
    source: http.https.status === "ok" ? "https-final-response" : "unavailable",
    headers
  };

  if (http.https.status !== "ok" || !http.https.finalHeaders) {
    return {
      findings: [
        {
          id: "headers.unavailable",
          category: "headers",
          status: "skip",
          severity: "info",
          title: "Security headers not checked",
          summary: "No final HTTPS response was available for header checks.",
          whyItMatters: "Header checks are meaningful only after the HTTPS page is reachable.",
          fix: "Fix HTTPS reachability first, then re-run the scan."
        }
      ],
      raw
    };
  }

  return {
    findings: buildHeaderFindings(headers),
    raw
  };
}

function buildHeaderFindings(headers: Record<string, string>): Finding[] {
  return [
    ...checkHsts(headers),
    ...checkCsp(headers),
    ...checkClickjacking(headers),
    ...checkNosniff(headers),
    ...checkReferrerPolicy(headers),
    ...checkPermissionsPolicy(headers),
    ...checkCoopCorp(headers),
    ...checkCookies(headers),
    ...checkDisclosureHeaders(headers)
  ];
}

function checkHsts(headers: Record<string, string>): Finding[] {
  const hsts = headers["strict-transport-security"];

  if (!hsts) {
    return [
      {
        id: "headers.hsts.missing",
        category: "headers",
        status: "warn",
        severity: "medium",
        title: "HSTS header is missing",
        summary: "The final HTTPS response does not include Strict-Transport-Security.",
        whyItMatters:
          "HSTS is a risk reducer that tells browsers to prefer HTTPS for future visits.",
        fix: "Add Strict-Transport-Security after HTTPS and redirects are stable."
      }
    ];
  }

  const maxAge = parseMaxAge(hsts);
  if (typeof maxAge === "number" && maxAge < MIN_HSTS_MAX_AGE) {
    return [
      {
        id: "headers.hsts.short_max_age",
        category: "headers",
        status: "warn",
        severity: "low",
        title: "HSTS max-age is short",
        summary: `Strict-Transport-Security max-age is ${maxAge} seconds.`,
        evidence: { header: hsts, maxAge },
        whyItMatters: "Short HSTS lifetimes reduce how long browsers remember the HTTPS preference.",
        fix: "Increase max-age gradually after confirming HTTPS works for the domain."
      }
    ];
  }

  return [
    {
      id: "headers.hsts.present",
      category: "headers",
      status: "pass",
      severity: "info",
      title: "HSTS header is present",
      summary: "The final HTTPS response includes Strict-Transport-Security.",
      evidence: { header: hsts }
    }
  ];
}

function checkCsp(headers: Record<string, string>): Finding[] {
  const csp = headers["content-security-policy"];

  if (!csp) {
    return [
      {
        id: "headers.csp.missing",
        category: "headers",
        status: "warn",
        severity: "medium",
        title: "Content Security Policy is missing",
        summary: "The final HTTPS response does not include Content-Security-Policy.",
        whyItMatters: "CSP can reduce the impact of some script injection and content injection bugs.",
        fix: "Add a Content-Security-Policy suited to the site before tightening it."
      }
    ];
  }

  if (/'unsafe-inline'/iu.test(csp)) {
    return [
      {
        id: "headers.csp.unsafe_inline",
        category: "headers",
        status: "warn",
        severity: "low",
        title: "CSP allows unsafe inline code",
        summary: "Content-Security-Policy contains 'unsafe-inline'.",
        evidence: { header: csp },
        whyItMatters: "Allowing inline scripts weakens CSP as an injection risk reducer.",
        fix: "Move inline scripts/styles to nonces, hashes, or external files where practical."
      }
    ];
  }

  return [
    {
      id: "headers.csp.present",
      category: "headers",
      status: "pass",
      severity: "info",
      title: "Content Security Policy is present",
      summary: "The final HTTPS response includes Content-Security-Policy.",
      evidence: { header: csp }
    }
  ];
}

function checkClickjacking(headers: Record<string, string>): Finding[] {
  const xFrameOptions = headers["x-frame-options"];
  const csp = headers["content-security-policy"];
  const hasFrameAncestors = Boolean(csp && /(?:^|;)\s*frame-ancestors\s+/iu.test(csp));

  if (xFrameOptions || hasFrameAncestors) {
    return [
      {
        id: "headers.clickjacking.present",
        category: "headers",
        status: "pass",
        severity: "info",
        title: "Framing policy is present",
        summary: "The response includes X-Frame-Options or CSP frame-ancestors.",
        evidence: { xFrameOptions, frameAncestors: hasFrameAncestors }
      }
    ];
  }

  return [
    {
      id: "headers.clickjacking.missing",
      category: "headers",
      status: "warn",
      severity: "medium",
      title: "Framing policy is missing",
      summary: "The response does not include X-Frame-Options or CSP frame-ancestors.",
      whyItMatters: "A framing policy can reduce clickjacking risk for browser-based pages.",
      fix: "Add CSP frame-ancestors or X-Frame-Options for pages that should not be framed."
    }
  ];
}

function checkNosniff(headers: Record<string, string>): Finding[] {
  const nosniff = headers["x-content-type-options"];

  if (nosniff?.toLowerCase() === "nosniff") {
    return [
      {
        id: "headers.nosniff.present",
        category: "headers",
        status: "pass",
        severity: "info",
        title: "Content type sniffing protection is present",
        summary: "The response includes X-Content-Type-Options: nosniff."
      }
    ];
  }

  return [
    {
      id: "headers.nosniff.missing",
      category: "headers",
      status: "warn",
      severity: "low",
      title: "nosniff header is missing",
      summary: "The response does not include X-Content-Type-Options: nosniff.",
      whyItMatters: "nosniff helps browsers avoid interpreting content as a different type.",
      fix: "Add X-Content-Type-Options: nosniff."
    }
  ];
}

function checkReferrerPolicy(headers: Record<string, string>): Finding[] {
  const policy = headers["referrer-policy"];

  if (policy) {
    return [
      {
        id: "headers.referrer_policy.present",
        category: "headers",
        status: "pass",
        severity: "info",
        title: "Referrer policy is present",
        summary: "The response includes Referrer-Policy.",
        evidence: { header: policy }
      }
    ];
  }

  return [
    {
      id: "headers.referrer_policy.missing",
      category: "headers",
      status: "warn",
      severity: "low",
      title: "Referrer policy is missing",
      summary: "The response does not include Referrer-Policy.",
      whyItMatters: "Referrer-Policy controls how much URL information is sent to other sites.",
      fix: "Add a Referrer-Policy such as strict-origin-when-cross-origin."
    }
  ];
}

function checkPermissionsPolicy(headers: Record<string, string>): Finding[] {
  const policy = headers["permissions-policy"];

  if (policy) {
    return [
      {
        id: "headers.permissions_policy.present",
        category: "headers",
        status: "pass",
        severity: "info",
        title: "Permissions policy is present",
        summary: "The response includes Permissions-Policy.",
        evidence: { header: policy }
      }
    ];
  }

  return [
    {
      id: "headers.permissions_policy.missing",
      category: "headers",
      status: "info",
      severity: "low",
      title: "Permissions policy is missing",
      summary: "The response does not include Permissions-Policy.",
      whyItMatters: "Permissions-Policy can limit access to powerful browser features.",
      fix: "Add a Permissions-Policy if the site needs to restrict browser capabilities."
    }
  ];
}

function checkCoopCorp(headers: Record<string, string>): Finding[] {
  const findings: Finding[] = [];

  if (!headers["cross-origin-opener-policy"]) {
    findings.push({
      id: "headers.coop.missing",
      category: "headers",
      status: "info",
      severity: "info",
      title: "COOP header is missing",
      summary: "The response does not include Cross-Origin-Opener-Policy.",
      whyItMatters: "COOP is useful for some apps that need cross-origin isolation.",
      fix: "Add COOP only if it matches the app's cross-origin behavior."
    });
  }

  if (!headers["cross-origin-resource-policy"]) {
    findings.push({
      id: "headers.corp.missing",
      category: "headers",
      status: "info",
      severity: "info",
      title: "CORP header is missing",
      summary: "The response does not include Cross-Origin-Resource-Policy.",
      whyItMatters: "CORP is useful for some apps that need cross-origin resource isolation.",
      fix: "Add CORP only if it matches the app's resource sharing behavior."
    });
  }

  return findings;
}

function checkCookies(headers: Record<string, string>): Finding[] {
  const cookies = splitSetCookie(headers["set-cookie"]);
  const findings: Finding[] = [];

  for (const [index, cookie] of cookies.entries()) {
    const lower = cookie.toLowerCase();
    const evidence = { cookieIndex: index + 1 };

    if (!/;\s*secure(?:;|$)/iu.test(cookie)) {
      findings.push({
        id: "headers.cookie.missing_secure",
        category: "headers",
        status: "warn",
        severity: "medium",
        title: "Cookie is missing Secure",
        summary: "A Set-Cookie header does not include the Secure attribute.",
        evidence,
        whyItMatters: "Secure tells browsers to send the cookie only over HTTPS.",
        fix: "Add the Secure attribute to HTTPS cookies."
      });
    }

    if (!/;\s*httponly(?:;|$)/iu.test(cookie)) {
      findings.push({
        id: "headers.cookie.missing_httponly",
        category: "headers",
        status: "warn",
        severity: "low",
        title: "Cookie is missing HttpOnly",
        summary: "A Set-Cookie header does not include the HttpOnly attribute.",
        evidence,
        whyItMatters: "HttpOnly can reduce cookie exposure to injected JavaScript.",
        fix: "Add HttpOnly to cookies that do not need browser JavaScript access."
      });
    }

    if (!lower.includes("samesite=")) {
      findings.push({
        id: "headers.cookie.missing_samesite",
        category: "headers",
        status: "warn",
        severity: "low",
        title: "Cookie is missing SameSite",
        summary: "A Set-Cookie header does not include the SameSite attribute.",
        evidence,
        whyItMatters: "SameSite helps control when cookies are sent on cross-site requests.",
        fix: "Add SameSite=Lax, Strict, or None depending on the cookie's purpose."
      });
    }
  }

  return dedupeCookieFindings(findings);
}

function checkDisclosureHeaders(headers: Record<string, string>): Finding[] {
  const findings: Finding[] = [];

  if (headers.server) {
    findings.push({
      id: "headers.server.disclosed",
      category: "headers",
      status: "info",
      severity: "low",
      title: "Server header is present",
      summary: "The response includes a Server header.",
      evidence: { header: headers.server },
      whyItMatters: "Server headers are usually low risk, but can expose implementation details.",
      fix: "Reduce Server header detail if your platform allows it."
    });
  }

  if (headers["x-powered-by"]) {
    findings.push({
      id: "headers.x_powered_by.disclosed",
      category: "headers",
      status: "info",
      severity: "low",
      title: "X-Powered-By header is present",
      summary: "The response includes X-Powered-By.",
      evidence: { header: headers["x-powered-by"] },
      whyItMatters: "X-Powered-By is usually low risk, but can expose framework details.",
      fix: "Remove X-Powered-By if your framework or platform allows it."
    });
  }

  return findings;
}

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const normalized: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value.trim();
  }

  return normalized;
}

function parseMaxAge(header: string): number | null {
  const match = header.match(/(?:^|;)\s*max-age=(\d+)/iu);
  return match ? Number.parseInt(match[1] ?? "", 10) : null;
}

function splitSetCookie(header: string | undefined): string[] {
  if (!header) {
    return [];
  }

  return header
    .split(/,(?=\s*[^;,=\s]+=[^;,]*;)/u)
    .map((cookie) => cookie.trim())
    .filter(Boolean);
}

function dedupeCookieFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const deduped: Finding[] = [];

  for (const finding of findings) {
    if (seen.has(finding.id)) {
      continue;
    }

    seen.add(finding.id);
    deduped.push(finding);
  }

  return deduped;
}
