import type { Metadata } from "next";

import { BrandFooter, BrandHeader } from "../brand";

export const metadata: Metadata = {
  title: "Privacy | bsns tools",
  description: "How bsns probe handles submitted domains and generated reports."
};

export default function PrivacyPage() {
  return (
    <main className="page-shell">
      <BrandHeader />

      <article className="content-page">
        <p className="eyebrow">Privacy</p>
        <h1>bsns tools are designed to work without accounts, ads, or telemetry.</h1>
        <div className="content-body">
          <p>No account is required. No ads. No third-party analytics.</p>
          <p>
            The server sees the domain you submit because it must perform DNS, HTTP, TLS,
            header, and email checks. On tools.bsns.cc, reports are not stored.
          </p>
          <p>
            The submitted domain may appear in short-lived server logs used for abuse prevention
            and reliability. Standard server logs may also contain your IP address and user agent.
          </p>
          <p>Self-hosted deployments control their own logging and retention.</p>
          <p>If hosted sharing is added later, it will be opt-in.</p>
        </div>
      </article>

      <BrandFooter />
    </main>
  );
}
