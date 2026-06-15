import { describe, expect, it } from "vitest";

import { checkHttp, createGuardedHttpClient } from "./http.js";
import type { HttpClient, HttpClientResponse } from "./http.js";
import type { AddressResolver, LookupAddress, NormalizedTarget } from "./domain.js";

const TARGET: NormalizedTarget = {
  input: "example.com",
  hostname: "example.com",
  asciiHostname: "example.com",
  registrableDomain: "example.com"
};

describe("checkHttp", () => {
  it("detects reachable HTTPS and HTTP-to-HTTPS redirects", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(200, { "content-type": "text/html" }),
        "http://example.com/": response(301, { location: "https://example.com/" })
      })
    });

    expect(findingIds(result.findings)).toContain("web.https.ok");
    expect(findingIds(result.findings)).toContain("web.http.redirects_to_https");
    expect(findingIds(result.findings)).toContain("web.status.ok");
    expect(result.raw.http.attempts).toHaveLength(2);
  });

  it("reports HTTPS unreachable", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": networkError("ECONNREFUSED"),
        "http://example.com/": response(200)
      })
    });

    expect(result.findings.find((item) => item.id === "web.https.unreachable")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("detects HTTP responses that do not redirect to HTTPS", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(200),
        "http://example.com/": response(200)
      })
    });

    expect(result.findings.find((item) => item.id === "web.http.no_https_redirect")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
  });

  it("detects redirect loops", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(302, { location: "/again" }),
        "https://example.com/again": response(302, { location: "/" }),
        "http://example.com/": response(301, { location: "https://example.com/" })
      })
    });

    expect(result.findings.find((item) => item.id === "web.redirect.loop")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("detects HTTPS-to-HTTP downgrades", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(301, { location: "http://example.com/" }),
        "http://example.com/": response(200)
      })
    });

    expect(result.findings.find((item) => item.id === "web.redirect.to_http")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("blocks redirects to private or reserved hosts before fetching them", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(302, { location: "http://127.0.0.1/" }),
        "http://example.com/": response(301, { location: "https://example.com/" })
      })
    });

    expect(result.findings.find((item) => item.id === "web.redirect.blocked")).toMatchObject({
      status: "fail",
      severity: "high"
    });
    expect(result.raw.https.attempts.some((attempt) => attempt.hostname === "127.0.0.1")).toBe(
      true
    );
  });

  it("blocks private addresses during the guarded client connection lookup", async () => {
    const client = createGuardedHttpClient(privateAddressResolver());
    const controller = new AbortController();

    await expect(
      client.fetch(new URL("http://example.com/"), {
        signal: controller.signal
      })
    ).rejects.toMatchObject({
      code: "BLOCKED_DNS_ADDRESS"
    });
  });

  it("passes validation-time public addresses into each client fetch", async () => {
    const seen: Array<{ addresses: LookupAddress[] | undefined; url: string }> = [];

    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: {
        async fetch(url, options) {
          seen.push({
            addresses: options.resolvedAddresses,
            url: url.toString()
          });

          if (url.protocol === "http:") {
            return response(301, { location: "https://example.com/" });
          }

          return response(200);
        }
      }
    });

    expect(result.raw.https.status).toBe("ok");
    expect(result.raw.http.status).toBe("ok");
    expect(seen).toHaveLength(3);
    expect(seen.every((item) => item.addresses?.[0]?.address === "93.184.216.34")).toBe(true);
    expect(seen.map((item) => item.url).sort()).toEqual([
      "http://example.com/",
      "https://example.com/",
      "https://example.com/"
    ]);
  });

  it("rejects manually supplied private pinned addresses", async () => {
    const client = createGuardedHttpClient(publicAddressResolver());
    const controller = new AbortController();

    await expect(
      client.fetch(new URL("http://example.com/"), {
        resolvedAddresses: [{ address: "127.0.0.1", family: 4 }],
        signal: controller.signal
      })
    ).rejects.toMatchObject({
      code: "BLOCKED_DNS_ADDRESS"
    });
  });

  it("reports connection-time DNS blocks as blocked fetches", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: {
        async fetch() {
          throw networkError("BLOCKED_DNS_ADDRESS");
        }
      }
    });

    expect(result.findings.find((item) => item.id === "web.redirect.blocked")).toMatchObject({
      status: "fail",
      severity: "high"
    });
    expect(result.raw.https.status).toBe("blocked");
  });

  it("reports final 5xx status as a high-severity status warning", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(503),
        "http://example.com/": response(301, { location: "https://example.com/" })
      })
    });

    expect(result.findings.find((item) => item.id === "web.status.error")).toMatchObject({
      status: "warn",
      severity: "high"
    });
  });

  it("reports canonical hostname changes", async () => {
    const result = await checkHttp(TARGET, {
      addressResolver: publicAddressResolver(),
      client: routeClient({
        "https://example.com/": response(301, { location: "https://www.example.com/" }),
        "https://www.example.com/": response(200),
        "http://example.com/": response(301, { location: "https://www.example.com/" })
      })
    });

    expect(result.findings.find((item) => item.id === "web.canonical.www_mismatch")).toMatchObject({
      status: "info",
      severity: "info"
    });
  });
});

function findingIds(findings: Array<{ id: string }>): string[] {
  return findings.map((finding) => finding.id);
}

function routeClient(routes: Record<string, HttpClientResponse | Error>): HttpClient {
  return {
    async fetch(url) {
      const route = routes[url.toString()];

      if (!route) {
        throw networkError("ENOTFOUND");
      }

      if (route instanceof Error) {
        throw route;
      }

      return route;
    }
  };
}

function response(status: number, headers: Record<string, string> = {}): HttpClientResponse {
  return {
    status,
    headers: new Headers(headers),
    body: {
      cancel() {
        return undefined;
      }
    }
  };
}

function networkError(code: string): Error {
  const error = new Error(`mock HTTP ${code}`);
  Object.assign(error, { code });
  return error;
}

function publicAddressResolver(): AddressResolver {
  return {
    async lookup() {
      return [{ address: "93.184.216.34", family: 4 }];
    }
  };
}

function privateAddressResolver(): AddressResolver {
  return {
    async lookup() {
      return [{ address: "127.0.0.1", family: 4 }];
    }
  };
}
