import type { Metadata } from "next";

import type { ProbeReport } from "@bsns/probe-core";

import { BrandFooter, BrandHeader } from "./brand";
import { ProbeRunner, ReportPreview } from "./probe/ProbeRunner";

export const metadata: Metadata = {
  title: "bsns probe | bsns tools",
  description: "Check a domain's DNS, website, TLS, headers, and email setup."
};

export default function HomePage() {
  return (
    <main className="page-shell">
      <BrandHeader />

      <section className="hero single-column">
        <div className="hero-copy">
          <p className="eyebrow">bsns probe</p>
          <h1>Check your domain&apos;s DNS, website, TLS, headers, and email setup.</h1>
          <p className="subhead">Free, open source, no account, no ads.</p>
        </div>

        <ProbeRunner />
      </section>

      <SampleReport />

      <BrandFooter />
    </main>
  );
}

function SampleReport() {
  return (
    <section className="sample-report" id="sample-report" aria-labelledby="sample-report-heading">
      <div className="sample-intro">
        <p className="eyebrow">Sample report</p>
        <h2 id="sample-report-heading">Domain health for bsns.cc</h2>
        <p>
          A healthy report leads with the operator work that matters most, then keeps the raw
          evidence available for someone technical.
        </p>
      </div>

      <ReportPreview report={SAMPLE_REPORT} compact={false} />
    </section>
  );
}

const SAMPLE_REPORT: ProbeReport = {
  schemaVersion: "1.0",
  target: {
    input: "bsns.cc",
    hostname: "bsns.cc",
    asciiHostname: "bsns.cc",
    registrableDomain: "bsns.cc",
    scannedAt: "2026-06-15T06:27:27.380Z"
  },
  score: {
    total: 96,
    grade: "A",
    categories: {
      dns: { score: 20, max: 20 },
      web: { score: 30, max: 30 },
      email: { score: 30, max: 30 },
      headers: { score: 13, max: 15 },
      performance: { score: 3, max: 5 }
    }
  },
  summary: {
    headline: "Scan complete with 2 warnings.",
    topFixes: ["No urgent fixes found in the checks that completed."],
    counts: {
      pass: 11,
      warn: 2,
      fail: 0,
      info: 1,
      skip: 0
    }
  },
  findings: [
    {
      id: "dns.resolve.ok",
      category: "dns",
      status: "pass",
      severity: "info",
      title: "Domain resolves",
      summary: "bsns.cc has public address records.",
      evidence: {
        a: [
          { address: "216.150.16.1", ttl: 1800 },
          { address: "216.150.1.1", ttl: 1800 }
        ],
        aaaa: []
      }
    },
    {
      id: "dns.aaaa.missing",
      category: "dns",
      status: "info",
      severity: "low",
      title: "No AAAA records found",
      summary: "bsns.cc does not publish IPv6 AAAA records.",
      whyItMatters: "IPv6 is useful but not required for most small-business sites.",
      fix: "Add an AAAA record when your hosting provider supports IPv6."
    },
    {
      id: "dns.ns.present",
      category: "dns",
      status: "pass",
      severity: "info",
      title: "Name servers found",
      summary: "bsns.cc publishes NS records.",
      evidence: { ns: ["ns2.vercel-dns.com", "ns1.vercel-dns.com"] }
    },
    {
      id: "dns.caa.present",
      category: "dns",
      status: "pass",
      severity: "info",
      title: "CAA records found",
      summary: "bsns.cc publishes CAA records.",
      evidence: {
        caa: [
          { critical: 0, type: "CAA", issue: "pki.goog" },
          { critical: 0, type: "CAA", issue: "sectigo.com" },
          { critical: 0, type: "CAA", issue: "letsencrypt.org" }
        ]
      },
      whyItMatters: "CAA records can limit which certificate authorities may issue certificates."
    },
    {
      id: "web.https.ok",
      category: "web",
      status: "pass",
      severity: "info",
      title: "HTTPS is reachable",
      summary: "https://bsns.cc returned HTTP 200.",
      evidence: { finalUrl: "https://bsns.cc/", status: 200 }
    },
    {
      id: "web.http.redirects_to_https",
      category: "web",
      status: "pass",
      severity: "info",
      title: "HTTP redirects to HTTPS",
      summary: "http://bsns.cc redirects to HTTPS.",
      evidence: {
        chain: [
          { url: "http://bsns.cc/", status: 308, redirectTo: "https://bsns.cc/" },
          { url: "https://bsns.cc/", status: 200 }
        ]
      }
    },
    {
      id: "tls.valid",
      category: "tls",
      status: "pass",
      severity: "info",
      title: "TLS certificate is valid",
      summary: "The certificate is trusted and covers bsns.cc.",
      evidence: {
        validTo: "Sep 10 21:27:50 2026 GMT",
        issuer: { O: "Let's Encrypt", CN: "YR2" },
        negotiatedProtocol: "TLSv1.3"
      }
    },
    {
      id: "email.spf.present",
      category: "email",
      status: "pass",
      severity: "info",
      title: "SPF record found",
      summary: "bsns.cc publishes one SPF record.",
      evidence: { record: "v=spf1 include:_spf.google.com include:_spf.resend.com ~all" }
    },
    {
      id: "email.dmarc.enforcing_policy",
      category: "email",
      status: "pass",
      severity: "info",
      title: "DMARC enforcing policy found",
      summary: "bsns.cc uses DMARC p=reject.",
      evidence: { policy: "reject", subdomainPolicy: "none" },
      whyItMatters: "An enforcing DMARC policy can reduce successful direct domain spoofing."
    },
    {
      id: "email.dkim.selector_found",
      category: "email",
      status: "pass",
      severity: "info",
      title: "DKIM selector record found",
      summary: "Found a DKIM record for selector google.",
      evidence: { selectors: [{ selector: "google", hostname: "google._domainkey.bsns.cc" }] },
      whyItMatters: "DKIM lets receivers verify that signed mail was authorized by the domain."
    },
    {
      id: "headers.hsts.present",
      category: "headers",
      status: "pass",
      severity: "info",
      title: "HSTS is present",
      summary: "The final HTTPS response includes Strict-Transport-Security.",
      evidence: { maxAge: 31536000 }
    },
    {
      id: "headers.csp.unsafe_inline",
      category: "headers",
      status: "warn",
      severity: "low",
      title: "CSP allows unsafe inline code",
      summary: "Content-Security-Policy contains 'unsafe-inline'.",
      evidence: { directives: ["script-src", "style-src"] },
      whyItMatters: "Allowing inline scripts weakens CSP as an injection risk reducer.",
      fix: "Move inline scripts/styles to nonces, hashes, or external files where practical."
    },
    {
      id: "perf.response.fast",
      category: "performance",
      status: "pass",
      severity: "info",
      title: "Initial response is acceptable",
      summary: "The final HTTPS response took about 913 ms.",
      evidence: { finalUrl: "https://bsns.cc/", responseTimeMs: 913, totalTimeMs: 947 }
    },
    {
      id: "perf.compression.missing",
      category: "performance",
      status: "warn",
      severity: "low",
      title: "Compression was not visible",
      summary: "The sampled text response did not show a content-encoding header.",
      whyItMatters: "Compression can reduce transfer size for text responses.",
      fix: "Confirm compression is enabled for HTML, CSS, JavaScript, and JSON responses."
    }
  ],
  raw: {
    dns: {
      a: [
        { address: "216.150.16.1", ttl: 1800 },
        { address: "216.150.1.1", ttl: 1800 }
      ],
      aaaa: [],
      ns: ["ns2.vercel-dns.com", "ns1.vercel-dns.com"],
      mx: [{ priority: 1, exchange: "smtp.google.com" }],
      caa: [
        { critical: 0, type: "CAA", issue: "pki.goog" },
        { critical: 0, type: "CAA", issue: "sectigo.com" },
        { critical: 0, type: "CAA", issue: "letsencrypt.org" }
      ]
    },
    http: {
      https: { status: "ok", finalStatus: 200, finalUrl: "https://bsns.cc/" },
      http: {
        status: "ok",
        finalStatus: 200,
        finalUrl: "https://bsns.cc/",
        redirects: [
          { url: "http://bsns.cc/", status: 308, redirectTo: "https://bsns.cc/" },
          { url: "https://bsns.cc/", status: 200 }
        ]
      }
    },
    tls: {
      handshake: true,
      validForHostname: true,
      chainTrusted: true,
      issuer: "Let's Encrypt",
      negotiatedProtocol: "TLSv1.3",
      validTo: "Sep 10 21:27:50 2026 GMT"
    },
    email: {
      spf: { records: ["v=spf1 include:_spf.google.com include:_spf.resend.com ~all"], lookupCount: 2 },
      dmarc: { records: ["v=DMARC1; p=reject; pct=100; sp=none; aspf=r;"] },
      dkim: { checkedSelectors: ["google", "selector1"], foundSelectors: ["google"] }
    },
    performance: {
      responseTimeMs: 913,
      totalTimeMs: 947,
      contentType: "text/html; charset=utf-8",
      contentEncoding: null
    }
  }
};
