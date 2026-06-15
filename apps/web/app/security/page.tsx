import type { Metadata } from "next";

import { BrandFooter, BrandHeader } from "../brand";

export const metadata: Metadata = {
  title: "Security | bsns tools",
  description: "How to report security issues in bsns probe."
};

export default function SecurityPage() {
  return (
    <main className="page-shell">
      <BrandHeader />

      <article className="content-page">
        <p className="eyebrow">Security</p>
        <h1>Report security issues to security@bsns.cc.</h1>
        <div className="content-body">
          <p>
            Useful reports include SSRF bypasses, DNS rebinding issues, redirect validation
            bypasses, XSS through DNS records or HTTP headers, dependency vulnerabilities with
            practical exploit paths, and parser bugs that cause crashes or misleading findings.
          </p>
          <p>
            The project is pre-1.0. Security fixes target the default branch until versioned
            releases are published.
          </p>
          <p>
            We aim to acknowledge reports promptly, reproduce the issue, scope impact, and publish
            a fix before disclosing technical details publicly.
          </p>
        </div>
      </article>

      <BrandFooter />
    </main>
  );
}
