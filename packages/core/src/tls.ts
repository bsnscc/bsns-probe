import tls from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";

import { resolvePublicAddresses } from "./domain.js";
import type { AddressResolver, LookupAddress, NormalizedTarget } from "./domain.js";
import { pinnedNodeLookup } from "./network-lookup.js";
import type { Finding } from "./types.js";

export interface TlsInspector {
  inspect(
    hostname: string,
    options: { addressResolver?: AddressResolver; timeoutMs: number }
  ): Promise<TlsInspection>;
}

export interface TlsCheckOptions {
  addressResolver?: AddressResolver;
  inspector?: TlsInspector;
  now?: Date;
  timeoutMs?: number;
}

export interface TlsCheckResult {
  findings: Finding[];
  raw: TlsRawResult;
}

export interface TlsRawResult extends TlsInspection {
  hostname: string;
  checkedAt: string;
}

export interface TlsInspection {
  handshake: boolean;
  chainTrusted: boolean;
  authorizationError?: string;
  negotiatedProtocol?: string | null;
  certificate?: TlsCertificateInfo;
  error?: {
    code: string;
    message: string;
  };
}

export interface TlsCertificateInfo {
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  validFrom: string;
  validTo: string;
  subjectAltNames: string[];
  fingerprint256?: string;
}

const DEFAULT_TIMEOUT_MS = 8000;

const DEFAULT_TLS_INSPECTOR: TlsInspector = {
  async inspect(hostname, options) {
    return inspectTlsLive(hostname, options.timeoutMs, options.addressResolver);
  }
};

export async function checkTls(
  target: NormalizedTarget,
  options: TlsCheckOptions = {}
): Promise<TlsCheckResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = options.now ?? new Date();
  const inspection = await (options.inspector ?? DEFAULT_TLS_INSPECTOR).inspect(
    target.asciiHostname,
    { addressResolver: options.addressResolver, timeoutMs }
  );
  const raw: TlsRawResult = {
    hostname: target.asciiHostname,
    checkedAt: new Date().toISOString(),
    ...inspection
  };

  return {
    findings: buildTlsFindings(raw, target, now),
    raw
  };
}

function buildTlsFindings(
  raw: TlsRawResult,
  target: NormalizedTarget,
  now: Date
): Finding[] {
  const findings: Finding[] = [];

  if (!raw.handshake) {
    findings.push({
      id: "tls.handshake_failed",
      category: "tls",
      status: "fail",
      severity: "high",
      title: "TLS handshake failed",
      summary: `TLS did not complete for ${target.asciiHostname}.`,
      evidence: raw.error ? { error: raw.error } : undefined,
      whyItMatters: "A failed TLS handshake prevents browsers from opening the HTTPS site.",
      fix: "Check the web server, certificate installation, and TLS listener on port 443."
    });
    return findings;
  }

  if (!raw.chainTrusted) {
    findings.push({
      id: "tls.untrusted_chain",
      category: "tls",
      status: "fail",
      severity: "high",
      title: "Certificate chain is not trusted",
      summary: "The TLS certificate chain was not accepted by the runtime trust store.",
      evidence: { authorizationError: raw.authorizationError },
      whyItMatters: "Browsers may show a certificate warning when the chain is untrusted.",
      fix: "Install a certificate chain from a trusted certificate authority, including intermediates."
    });
  }

  const certificate = raw.certificate;
  if (!certificate) {
    findings.push({
      id: "tls.certificate.missing",
      category: "tls",
      status: "fail",
      severity: "high",
      title: "No certificate was presented",
      summary: "The TLS handshake completed without a readable peer certificate.",
      whyItMatters: "HTTPS requires a certificate browsers can inspect.",
      fix: "Install a certificate for this hostname."
    });
    return findings;
  }

  const expiresAt = new Date(certificate.validTo);
  const daysRemaining = Math.ceil((expiresAt.getTime() - now.getTime()) / 86_400_000);

  if (daysRemaining < 0) {
    findings.push({
      id: "tls.expired",
      category: "tls",
      status: "fail",
      severity: "critical",
      title: "TLS certificate is expired",
      summary: `The certificate expired ${Math.abs(daysRemaining)} day(s) ago.`,
      evidence: { validTo: certificate.validTo, daysRemaining },
      whyItMatters: "Expired certificates trigger browser warnings and can break integrations.",
      fix: "Renew and install a current certificate for this hostname."
    });
  } else if (daysRemaining < 30) {
    findings.push({
      id: "tls.expiring_soon",
      category: "tls",
      status: "warn",
      severity: daysRemaining < 7 ? "critical" : daysRemaining < 14 ? "high" : "medium",
      title: "TLS certificate expires soon",
      summary: `The certificate expires in ${daysRemaining} day(s).`,
      evidence: { validTo: certificate.validTo, daysRemaining },
      whyItMatters: "Certificate renewals are easiest to fix before they become outages.",
      fix: "Renew the certificate and verify auto-renewal is working."
    });
  }

  if (!certificateMatchesHostname(certificate, target.asciiHostname)) {
    findings.push({
      id: "tls.hostname_mismatch",
      category: "tls",
      status: "fail",
      severity: "high",
      title: "Certificate hostname does not match",
      summary: `The certificate does not cover ${target.asciiHostname}.`,
      evidence: { subjectAltNames: certificate.subjectAltNames },
      whyItMatters: "Browsers reject certificates that do not cover the requested hostname.",
      fix: "Install a certificate whose SAN list includes this hostname."
    });
  }

  if (isLegacyProtocol(raw.negotiatedProtocol)) {
    findings.push({
      id: "tls.legacy_protocol",
      category: "tls",
      status: "warn",
      severity: "medium",
      title: "Legacy TLS protocol negotiated",
      summary: `The handshake negotiated ${raw.negotiatedProtocol}.`,
      evidence: { negotiatedProtocol: raw.negotiatedProtocol },
      whyItMatters: "TLS versions below 1.2 are obsolete and broadly unsupported.",
      fix: "Disable TLS 1.0 and TLS 1.1 on the server."
    });
  }

  const hasBlockingIssue = findings.some(
    (finding) =>
      finding.id === "tls.expired" ||
      finding.id === "tls.hostname_mismatch" ||
      finding.id === "tls.untrusted_chain"
  );

  if (!hasBlockingIssue) {
    findings.unshift({
      id: "tls.valid",
      category: "tls",
      status: "pass",
      severity: "info",
      title: "TLS certificate is valid",
      summary: `The certificate is trusted and covers ${target.asciiHostname}.`,
      evidence: {
        validTo: certificate.validTo,
        issuer: certificate.issuer,
        negotiatedProtocol: raw.negotiatedProtocol
      }
    });
  }

  return findings;
}

export function createGuardedTlsInspector(addressResolver?: AddressResolver): TlsInspector {
  return {
    inspect(hostname, options) {
      return inspectTlsLive(hostname, options.timeoutMs, addressResolver ?? options.addressResolver);
    }
  };
}

async function inspectTlsLive(
  hostname: string,
  timeoutMs: number,
  addressResolver: AddressResolver | undefined
): Promise<TlsInspection> {
  let resolvedAddresses: LookupAddress[];
  try {
    resolvedAddresses = await resolvePublicAddresses(hostname, addressResolver);
  } catch (error) {
    return {
      handshake: false,
      chainTrusted: false,
      error: {
        code: getErrorCode(error),
        message: error instanceof Error ? error.message : "TLS address validation failed."
      }
    };
  }

  try {
    return await connectAndInspect(hostname, timeoutMs, true, resolvedAddresses);
  } catch (strictError) {
    try {
      const fallback = await connectAndInspect(hostname, timeoutMs, false, resolvedAddresses);
      return {
        ...fallback,
        chainTrusted: false,
        authorizationError: strictError instanceof Error ? strictError.message : "TLS chain error"
      };
    } catch (fallbackError) {
      return {
        handshake: false,
        chainTrusted: false,
        error: {
          code: getErrorCode(fallbackError),
          message: fallbackError instanceof Error ? fallbackError.message : "TLS handshake failed."
        }
      };
    }
  }
}

function connectAndInspect(
  hostname: string,
  timeoutMs: number,
  rejectUnauthorized: boolean,
  resolvedAddresses: LookupAddress[]
): Promise<TlsInspection> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized,
      timeout: timeoutMs,
      lookup(lookupHostname, lookupOptions, callback) {
        if (String(lookupHostname) !== hostname) {
          callback(new Error("Resolved hostname did not match the validated TLS hostname."), "", 0);
          return;
        }

        pinnedNodeLookup(resolvedAddresses, lookupOptions, callback);
      }
    });

    socket.once("secureConnect", () => {
      const certificate = normalizeCertificate(socket.getPeerCertificate(true));
      const result: TlsInspection = {
        handshake: true,
        chainTrusted: socket.authorized,
        authorizationError:
          typeof socket.authorizationError === "string" ? socket.authorizationError : undefined,
        negotiatedProtocol: socket.getProtocol(),
        certificate
      };
      socket.end();
      resolve(result);
    });

    socket.once("timeout", () => {
      socket.destroy(new Error("TLS handshake timed out."));
    });

    socket.once("error", (error) => {
      reject(error);
    });
  });
}

function normalizeCertificate(
  certificate: DetailedPeerCertificate | Record<string, never>
): TlsCertificateInfo | undefined {
  if (!("valid_to" in certificate) || typeof certificate.valid_to !== "string") {
    return undefined;
  }

  return {
    subject: normalizeNameObject(certificate.subject),
    issuer: normalizeNameObject(certificate.issuer),
    validFrom: certificate.valid_from,
    validTo: certificate.valid_to,
    subjectAltNames: parseSubjectAltNames(certificate.subjectaltname),
    fingerprint256: certificate.fingerprint256
  };
}

function normalizeNameObject(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }

  const normalized: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string") {
      normalized[key] = entry;
    }
  }

  return normalized;
}

function parseSubjectAltNames(value: unknown): string[] {
  if (typeof value !== "string") {
    return [];
  }

  return value
    .split(",")
    .map((entry) => entry.trim())
    .map((entry) => entry.replace(/^DNS:/u, "").toLowerCase())
    .filter(Boolean);
}

function certificateMatchesHostname(
  certificate: TlsCertificateInfo,
  hostname: string
): boolean {
  const names = certificate.subjectAltNames.length > 0
    ? certificate.subjectAltNames
    : certificate.subject?.CN
      ? [certificate.subject.CN.toLowerCase()]
      : [];

  return names.some((name) => hostnameMatchesPattern(hostname, name));
}

function hostnameMatchesPattern(hostname: string, pattern: string): boolean {
  if (pattern === hostname) {
    return true;
  }

  if (!pattern.startsWith("*.")) {
    return false;
  }

  const suffix = pattern.slice(1);
  return hostname.endsWith(suffix) && hostname.split(".").length === pattern.split(".").length;
}

function isLegacyProtocol(protocol: string | null | undefined): boolean {
  return protocol === "TLSv1" || protocol === "TLSv1.1" || protocol === "SSLv3";
}

function getErrorCode(error: unknown): string {
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && code.length > 0) {
      return code;
    }
  }

  if (error instanceof Error && error.name) {
    return error.name;
  }

  return "UNKNOWN";
}
