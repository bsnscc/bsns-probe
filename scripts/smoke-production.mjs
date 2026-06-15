#!/usr/bin/env node

const baseUrl = normalizeBaseUrl(process.env.PROBE_SMOKE_BASE_URL ?? process.argv[2] ?? "https://tools.bsns.cc");

await checkRoot();
await checkProbeRedirect();
await checkDiscoveryRoutes();
await checkBlockedLocalhost();
await checkOversizedRequest();
await checkExampleScan();
await checkHostedScanSummary();

console.log(`production smoke passed: ${baseUrl}`);

async function checkRoot() {
  const response = await fetchWithTimeout(baseUrl);
  assert(response.status === 200, `GET / expected 200, got ${response.status}`);
  assertSecurityHeaders(response.headers);

  const html = await response.text();

  assert(html.includes("bsns probe"), "GET / did not include the probe heading.");
  assert(
    html.includes("https://github.com/bsnscc/bsns-probe"),
    "GET / did not include the source repo link."
  );
  assert(html.includes('autoCapitalize="none"'), "GET / did not disable input autocapitalization.");
  assert(html.includes("/icon.svg"), "GET / did not include the configured icon.");
  assert(html.includes("View sample report"), "GET / did not include the sample report link.");
  assert(html.includes("Advanced email checks"), "GET / did not include advanced email checks.");
  assert(html.includes("Domain health for bsns.cc"), "GET / did not include the sample report.");
  assert(html.includes("Raw records"), "GET / did not include full sample raw records.");
  assert(html.includes("Copy Markdown"), "GET / did not include sample export actions.");
  assert(html.includes("DKIM selector record found"), "GET / did not include full sample findings.");
}

async function checkDiscoveryRoutes() {
  const privacy = await fetchWithTimeout(`${baseUrl}/privacy`);
  assert(privacy.status === 200, `GET /privacy expected 200, got ${privacy.status}`);

  const security = await fetchWithTimeout(`${baseUrl}/security`);
  assert(security.status === 200, `GET /security expected 200, got ${security.status}`);

  const robots = await fetchWithTimeout(`${baseUrl}/robots.txt`);
  assert(robots.status === 200, `GET /robots.txt expected 200, got ${robots.status}`);
  assert((await robots.text()).includes("Sitemap:"), "robots.txt did not include a sitemap.");

  const sitemap = await fetchWithTimeout(`${baseUrl}/sitemap.xml`);
  assert(sitemap.status === 200, `GET /sitemap.xml expected 200, got ${sitemap.status}`);
  assert((await sitemap.text()).includes(`${baseUrl}/`), "sitemap.xml did not include root URL.");

  const securityTxt = await fetchWithTimeout(`${baseUrl}/.well-known/security.txt`);
  assert(
    securityTxt.status === 200,
    `GET /.well-known/security.txt expected 200, got ${securityTxt.status}`
  );
  assert(
    (await securityTxt.text()).includes("security@bsns.cc"),
    "security.txt did not include security contact."
  );
}

async function checkProbeRedirect() {
  const response = await fetchWithTimeout(`${baseUrl}/probe`, {
    redirect: "manual"
  });

  assert(
    response.status === 308 || response.status === 307,
    `GET /probe expected a redirect, got ${response.status}`
  );
  assert(response.headers.get("location") === "/", "GET /probe did not redirect to /.");
}

async function checkBlockedLocalhost() {
  const { body, status } = await postScan({ domain: "localhost", includeRaw: true });
  assert(status === 400, `localhost scan expected HTTP 400, got ${status}`);
  assert(body.ok === false, "localhost scan should be rejected.");
  assert(
    body.error?.code === "BLOCKED_HOSTNAME",
    `localhost scan expected BLOCKED_HOSTNAME, got ${body.error?.code ?? "none"}`
  );
  assert(
    body.error?.message === "Enter a public domain name, not a local or reserved hostname.",
    "localhost scan returned an unexpected validation message."
  );
}

async function checkOversizedRequest() {
  const { body, status } = await postScan(
    {
      domain: "example.com",
      includeRaw: false,
      padding: "x".repeat(5000)
    },
    [413]
  );

  assert(status === 413, `oversized scan expected HTTP 413, got ${status}`);
  assert(body.ok === false, "oversized scan should be rejected.");
  assert(
    body.error?.code === "REQUEST_TOO_LARGE",
    `oversized scan expected REQUEST_TOO_LARGE, got ${body.error?.code ?? "none"}`
  );
}

async function checkExampleScan() {
  const { body } = await postScan({ domain: "example.com", includeRaw: false });
  assert(body.ok === true, "example.com scan should succeed.");

  const findingIds = new Set(body.report.findings.map((finding) => finding.id));
  assert(findingIds.has("web.https.ok"), "example.com scan did not include web.https.ok.");
  assert(findingIds.has("tls.valid"), "example.com scan did not include tls.valid.");
}

async function checkHostedScanSummary() {
  const hostname = new URL(baseUrl).hostname;
  const { body } = await postScan({ domain: hostname, includeRaw: false });
  assert(body.ok === true, `${hostname} scan should succeed.`);

  assert(
    body.report.summary.topFixes.includes("No urgent fixes found in the checks that completed."),
    `${hostname} should not show low-priority polish as urgent fixes.`
  );
}

async function postScan(body, expectedStatuses = [200, 400]) {
  const response = await fetchWithTimeout(`${baseUrl}/api/probe/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });

  assert(
    expectedStatuses.includes(response.status),
    `scan returned HTTP ${response.status}; expected ${expectedStatuses.join(" or ")}`
  );
  assertScanApiHeaders(response.headers);

  return {
    body: await response.json(),
    headers: response.headers,
    status: response.status
  };
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeBaseUrl(value) {
  return value.replace(/\/+$/u, "");
}

function assertSecurityHeaders(headers) {
  const expected = [
    "content-security-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options"
  ];

  for (const header of expected) {
    assert(headers.has(header), `GET / missing ${header} header.`);
  }
}

function assertScanApiHeaders(headers) {
  assert(headers.get("cache-control")?.includes("no-store"), "scan API missing no-store cache control.");

  const expected = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"];
  for (const header of expected) {
    assert(headers.has(header), `scan API missing ${header} header.`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
