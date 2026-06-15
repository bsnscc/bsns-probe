import http from "node:http";
import https from "node:https";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";

import {
  ProbeInputError,
  isBlockedIp,
  normalizeDomainInput,
  resolvePublicAddresses
} from "./domain.js";
import type { AddressResolver, LookupAddress, NormalizedTarget } from "./domain.js";
import { pinnedNodeLookup } from "./network-lookup.js";
import type { Finding } from "./types.js";

export interface HttpClient {
  fetch(
    url: URL,
    options: { resolvedAddresses?: LookupAddress[]; signal: AbortSignal }
  ): Promise<HttpClientResponse>;
}

export interface HttpClientResponse {
  status: number;
  statusText?: string;
  headers: HeadersLike;
  body?: {
    cancel(): Promise<unknown> | unknown;
    text?(limitBytes: number): Promise<string>;
  } | null;
}

export interface HeadersLike {
  get(name: string): string | null;
  entries(): IterableIterator<[string, string]> | Iterable<[string, string]>;
}

export interface HttpCheckOptions {
  addressResolver?: AddressResolver;
  client?: HttpClient;
  maxRedirects?: number;
  timeoutMs?: number;
}

export interface HttpCheckResult {
  findings: Finding[];
  raw: HttpRawResult;
}

export interface HttpRawResult {
  hostname: string;
  checkedAt: string;
  https: HttpFetchResult;
  http: HttpFetchResult;
}

export interface HttpFetchResult {
  startUrl: string;
  status: "ok" | "error" | "loop" | "blocked" | "too_many_redirects";
  attempts: HttpAttempt[];
  finalUrl?: string;
  finalStatus?: number;
  finalHeaders?: Record<string, string>;
  finalHostname?: string;
  finalProtocol?: "http:" | "https:";
  totalTimeMs: number;
}

export interface HttpAttempt {
  url: string;
  hostname: string;
  status?: number;
  responseTimeMs?: number;
  headers?: Record<string, string>;
  redirectTo?: string;
  error?: NormalizedHttpError;
}

export interface NormalizedHttpError {
  code: string;
  kind: "blocked" | "timeout" | "network" | "invalid_redirect" | "other";
  message: string;
}

const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT_MS = 8000;
const HEADER_ALLOWLIST = new Set([
  "cache-control",
  "content-security-policy",
  "content-encoding",
  "content-length",
  "content-type",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "date",
  "location",
  "permissions-policy",
  "referrer-policy",
  "server",
  "set-cookie",
  "strict-transport-security",
  "vary",
  "x-content-type-options",
  "x-frame-options",
  "x-powered-by"
]);

export async function checkHttp(
  target: NormalizedTarget,
  options: HttpCheckOptions = {}
): Promise<HttpCheckResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const client = options.client ?? createGuardedHttpClient(options.addressResolver);

  const [https, http] = await Promise.all([
    fetchWithRedirects(new URL(`https://${target.asciiHostname}/`), {
      addressResolver: options.addressResolver,
      client,
      maxRedirects,
      timeoutMs
    }),
    fetchWithRedirects(new URL(`http://${target.asciiHostname}/`), {
      addressResolver: options.addressResolver,
      client,
      maxRedirects,
      timeoutMs
    })
  ]);

  const raw: HttpRawResult = {
    hostname: target.asciiHostname,
    checkedAt: new Date().toISOString(),
    https,
    http
  };

  return {
    findings: buildHttpFindings(raw, target),
    raw
  };
}

async function fetchWithRedirects(
  startUrl: URL,
  options: Required<Pick<HttpCheckOptions, "client" | "maxRedirects" | "timeoutMs">> &
    Pick<HttpCheckOptions, "addressResolver">
): Promise<HttpFetchResult> {
  const attempts: HttpAttempt[] = [];
  const seen = new Set<string>();
  const startedAt = Date.now();
  let current = startUrl;

  for (let redirects = 0; redirects <= options.maxRedirects; redirects += 1) {
    const currentUrl = canonicalFetchUrl(current);

    if (seen.has(currentUrl)) {
      return {
        startUrl: startUrl.toString(),
        status: "loop",
        attempts,
        totalTimeMs: Date.now() - startedAt
      };
    }
    seen.add(currentUrl);

    const validation = await validateFetchUrl(current, options.addressResolver);
    if ("error" in validation) {
      attempts.push({
        url: current.toString(),
        hostname: current.hostname,
        error: validation.error
      });

      return {
        startUrl: startUrl.toString(),
        status: validation.error.kind === "blocked" ? "blocked" : "error",
        attempts,
        totalTimeMs: Date.now() - startedAt
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
    const attemptStartedAt = Date.now();

    try {
      const response = await options.client.fetch(current, {
        resolvedAddresses: validation.resolvedAddresses,
        signal: controller.signal
      });
      const responseTimeMs = Date.now() - attemptStartedAt;
      const headers = selectHeaders(response.headers);
      await response.body?.cancel();

      const attempt: HttpAttempt = {
        url: current.toString(),
        hostname: current.hostname,
        status: response.status,
        responseTimeMs,
        headers
      };

      if (isRedirectStatus(response.status)) {
        const location = response.headers.get("location");
        const next = buildRedirectUrl(location, current);

        if (!next) {
          attempt.error = {
            code: "INVALID_REDIRECT",
            kind: "invalid_redirect",
            message: "Redirect response did not include a usable Location header."
          };
          attempts.push(attempt);

          return {
            startUrl: startUrl.toString(),
            status: "error",
            attempts,
            totalTimeMs: Date.now() - startedAt
          };
        }

        attempt.redirectTo = next.toString();
        attempts.push(attempt);

        if (redirects === options.maxRedirects) {
          return {
            startUrl: startUrl.toString(),
            status: "too_many_redirects",
            attempts,
            totalTimeMs: Date.now() - startedAt
          };
        }

        current = next;
        continue;
      }

      attempts.push(attempt);

      return {
        startUrl: startUrl.toString(),
        status: "ok",
        attempts,
        finalUrl: current.toString(),
        finalStatus: response.status,
        finalHeaders: headers,
        finalHostname: current.hostname,
        finalProtocol: current.protocol === "https:" ? "https:" : "http:",
        totalTimeMs: Date.now() - startedAt
      };
    } catch (error) {
      const normalizedError = normalizeHttpError(error);
      attempts.push({
        url: current.toString(),
        hostname: current.hostname,
        responseTimeMs: Date.now() - attemptStartedAt,
        error: normalizedError
      });

      return {
        startUrl: startUrl.toString(),
        status: normalizedError.kind === "blocked" ? "blocked" : "error",
        attempts,
        totalTimeMs: Date.now() - startedAt
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    startUrl: startUrl.toString(),
    status: "too_many_redirects",
    attempts,
    totalTimeMs: Date.now() - startedAt
  };
}

export function createGuardedHttpClient(addressResolver?: AddressResolver): HttpClient {
  return {
    async fetch(url, options) {
      const resolvedAddresses =
        options.resolvedAddresses ?? (await resolvePublicAddresses(url.hostname, addressResolver));
      assertPublicResolvedAddresses(resolvedAddresses);
      return fetchWithNodeHttp(url, options.signal, resolvedAddresses);
    }
  };
}

function assertPublicResolvedAddresses(resolvedAddresses: LookupAddress[]): void {
  if (resolvedAddresses.length === 0) {
    throw new ProbeInputError(
      "DNS_NO_PUBLIC_ADDRESSES",
      "That domain did not resolve to any public addresses."
    );
  }

  if (resolvedAddresses.some((entry) => isBlockedIp(entry.address))) {
    throw new ProbeInputError(
      "BLOCKED_DNS_ADDRESS",
      "That domain resolves to a private or reserved network address."
    );
  }
}

function fetchWithNodeHttp(
  url: URL,
  signal: AbortSignal,
  resolvedAddresses: LookupAddress[]
): Promise<HttpClientResponse> {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const request = transport.request(
      {
        hostname: url.hostname,
        method: "GET",
        path: `${url.pathname}${url.search}`,
        port: url.protocol === "https:" ? 443 : 80,
        protocol: url.protocol,
        servername: url.hostname,
        lookup(hostname, lookupOptions, callback) {
          if (String(hostname) !== url.hostname) {
            callback(new Error("Resolved hostname did not match the validated request hostname."), "", 0);
            return;
          }

          pinnedNodeLookup(resolvedAddresses, lookupOptions, callback);
        }
      },
      (response) => {
        resolve({
          status: response.statusCode ?? 0,
          statusText: response.statusMessage,
          headers: headersFromIncoming(response.headers),
          body: {
            cancel() {
              response.destroy();
            },
            text(limitBytes) {
              return readResponseText(response, limitBytes);
            }
          }
        });
      }
    );

    request.once("error", reject);

    if (signal.aborted) {
      request.destroy(createAbortError());
      return;
    }

    signal.addEventListener(
      "abort",
      () => {
        request.destroy(createAbortError());
      },
      { once: true }
    );

    request.end();
  });
}

function headersFromIncoming(headers: IncomingHttpHeaders): Headers {
  const result = new Headers();

  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        result.append(key, item);
      }
    } else if (typeof value === "string") {
      result.set(key, value);
    }
  }

  return result;
}

function createAbortError(): Error {
  const error = new Error("HTTP request timed out.");
  error.name = "AbortError";
  return error;
}

function readResponseText(response: IncomingMessage, limitBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;

    response.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buffer.length;

      if (totalBytes > limitBytes) {
        response.destroy(new Error("Response body exceeded size limit."));
        return;
      }

      chunks.push(buffer);
    });

    response.once("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    response.once("error", reject);
  });
}

async function validateFetchUrl(
  url: URL,
  addressResolver: AddressResolver | undefined
): Promise<{ resolvedAddresses: LookupAddress[] } | { error: NormalizedHttpError }> {
  try {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return {
        error: {
          code: "INVALID_PROTOCOL",
          kind: "invalid_redirect",
          message: "Only http and https redirect targets are allowed."
        }
      };
    }

    if (url.port) {
      return {
        error: {
          code: "INVALID_PORT",
          kind: "invalid_redirect",
          message: "Redirect targets cannot include a custom port."
        }
      };
    }

    const target = normalizeDomainInput(url.toString());
    const resolvedAddresses = await resolvePublicAddresses(target.asciiHostname, addressResolver);
    return { resolvedAddresses };
  } catch (error) {
    return {
      error: {
        code: getErrorCode(error),
        kind: "blocked",
        message: error instanceof Error ? error.message : "Fetch target was blocked."
      }
    };
  }
}

function buildRedirectUrl(location: string | null, current: URL): URL | null {
  if (!location) {
    return null;
  }

  try {
    return new URL(location, current);
  } catch {
    return null;
  }
}

function canonicalFetchUrl(url: URL): string {
  return `${url.protocol}//${url.hostname}${url.pathname}${url.search}`;
}

function isRedirectStatus(status: number): boolean {
  return status === 300 || status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function selectHeaders(headers: HeadersLike): Record<string, string> {
  const selected: Record<string, string> = {};

  for (const [key, value] of headers.entries()) {
    const normalized = key.toLowerCase();
    if (HEADER_ALLOWLIST.has(normalized)) {
      selected[normalized] = value;
    }
  }

  return selected;
}

function buildHttpFindings(raw: HttpRawResult, target: NormalizedTarget): Finding[] {
  const findings: Finding[] = [];

  if (raw.https.status === "ok") {
    findings.push({
      id: "web.https.ok",
      category: "web",
      status: "pass",
      severity: "info",
      title: "HTTPS is reachable",
      summary: `https://${target.asciiHostname} returned HTTP ${raw.https.finalStatus}.`,
      evidence: summarizeFetchResult(raw.https)
    });
  } else {
    findings.push({
      id: "web.https.unreachable",
      category: "web",
      status: "fail",
      severity: "high",
      title: "HTTPS is not reachable",
      summary: `https://${target.asciiHostname} did not return a final response.`,
      evidence: summarizeFetchResult(raw.https),
      whyItMatters: "HTTPS should be the primary public entry point for modern websites.",
      fix: "Make sure the domain serves HTTPS on port 443 with a valid web server and certificate."
    });
  }

  if (raw.https.status === "loop" || raw.http.status === "loop") {
    findings.push({
      id: "web.redirect.loop",
      category: "web",
      status: "fail",
      severity: "high",
      title: "Redirect loop detected",
      summary: "A redirect chain loops back to a URL already visited.",
      evidence: {
        https: summarizeFetchResult(raw.https),
        http: summarizeFetchResult(raw.http)
      },
      whyItMatters: "Redirect loops prevent users and crawlers from reaching the site.",
      fix: "Update redirect rules so each chain ends at one canonical HTTPS URL."
    });
  }

  if (raw.https.status === "blocked" || raw.http.status === "blocked") {
    findings.push({
      id: "web.redirect.blocked",
      category: "web",
      status: "fail",
      severity: "high",
      title: "Redirect target was blocked",
      summary: "A fetch or redirect target resolved to a blocked hostname or address.",
      evidence: {
        https: summarizeFetchResult(raw.https),
        http: summarizeFetchResult(raw.http)
      },
      whyItMatters: "The public scanner refuses private, local, and reserved network targets.",
      fix: "Remove redirects to private, local, or reserved network destinations."
    });
  }

  if (redirectedFromHttpsToHttp(raw.https)) {
    findings.push({
      id: "web.redirect.to_http",
      category: "web",
      status: "fail",
      severity: "high",
      title: "HTTPS redirects to HTTP",
      summary: "The HTTPS entry point redirects to an unencrypted HTTP URL.",
      evidence: summarizeFetchResult(raw.https),
      whyItMatters: "HTTPS-to-HTTP downgrades remove transport protection.",
      fix: "Change redirects so HTTPS remains HTTPS through the final canonical URL."
    });
  }

  if (raw.http.status === "ok" && raw.http.finalProtocol === "https:") {
    findings.push({
      id: "web.http.redirects_to_https",
      category: "web",
      status: "pass",
      severity: "info",
      title: "HTTP redirects to HTTPS",
      summary: `http://${target.asciiHostname} redirects to HTTPS.`,
      evidence: summarizeFetchResult(raw.http)
    });
  } else if (raw.http.status === "ok" && raw.http.finalProtocol === "http:") {
    findings.push({
      id: "web.http.no_https_redirect",
      category: "web",
      status: "warn",
      severity: "medium",
      title: "HTTP does not redirect to HTTPS",
      summary: `http://${target.asciiHostname} returns a final HTTP response.`,
      evidence: summarizeFetchResult(raw.http),
      whyItMatters: "Redirecting HTTP to HTTPS gives users a safer default path.",
      fix: "Add an HTTP-to-HTTPS redirect for the domain."
    });
  }

  const finalStatus = raw.https.finalStatus ?? raw.http.finalStatus;
  if (typeof finalStatus === "number") {
    findings.push({
      id: finalStatus >= 400 ? "web.status.error" : "web.status.ok",
      category: "web",
      status: finalStatus >= 400 ? "warn" : "pass",
      severity: finalStatus >= 500 ? "high" : finalStatus >= 400 ? "medium" : "info",
      title: finalStatus >= 400 ? "Final status is an error" : "Final status is OK",
      summary: `The final web response returned HTTP ${finalStatus}.`,
      evidence: { status: finalStatus },
      whyItMatters: finalStatus >= 400 ? "Users may see an error page." : undefined,
      fix: finalStatus >= 400 ? "Update the web server or redirect target so the final URL returns a successful status." : undefined
    });
  }

  const canonicalFinding = buildCanonicalFinding(raw, target);
  if (canonicalFinding) {
    findings.push(canonicalFinding);
  }

  return findings;
}

function buildCanonicalFinding(raw: HttpRawResult, target: NormalizedTarget): Finding | null {
  const finalHostname = raw.https.finalHostname ?? raw.http.finalHostname;
  if (!finalHostname || finalHostname === target.asciiHostname) {
    return null;
  }

  const finalTarget = normalizeDomainInput(finalHostname);
  const sameRegistrable =
    target.registrableDomain !== null &&
    finalTarget.registrableDomain === target.registrableDomain;

  return {
    id: "web.canonical.www_mismatch",
    category: "web",
    status: "info",
    severity: sameRegistrable ? "info" : "medium",
    title: "Canonical hostname differs",
    summary: `${target.asciiHostname} ends at ${finalHostname}.`,
    evidence: { inputHostname: target.asciiHostname, finalHostname },
    whyItMatters: "A single canonical hostname makes redirects and certificates easier to reason about.",
    fix: sameRegistrable ? undefined : "Verify the redirect target is the intended canonical hostname."
  };
}

function redirectedFromHttpsToHttp(result: HttpFetchResult): boolean {
  return result.attempts.some((attempt) => {
    if (!attempt.redirectTo) {
      return false;
    }

    return attempt.url.startsWith("https://") && attempt.redirectTo.startsWith("http://");
  });
}

function summarizeFetchResult(result: HttpFetchResult) {
  return {
    status: result.status,
    finalUrl: result.finalUrl,
    finalStatus: result.finalStatus,
    totalTimeMs: result.totalTimeMs,
    chain: result.attempts.map((attempt) => ({
      url: attempt.url,
      status: attempt.status,
      redirectTo: attempt.redirectTo,
      error: attempt.error
    }))
  };
}

function normalizeHttpError(error: unknown): NormalizedHttpError {
  const code = getErrorCode(error);

  return {
    code,
    kind: classifyHttpError(code),
    message: error instanceof Error ? error.message : "HTTP request failed."
  };
}

function classifyHttpError(code: string): NormalizedHttpError["kind"] {
  if (code === "AbortError") {
    return "timeout";
  }

  if (
    code === "BLOCKED_HOSTNAME" ||
    code === "BLOCKED_IP" ||
    code === "BLOCKED_DNS_ADDRESS" ||
    code === "DNS_NO_PUBLIC_ADDRESSES"
  ) {
    return "blocked";
  }

  return "network";
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
