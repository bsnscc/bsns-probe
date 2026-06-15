import type { Metadata } from "next";

import { BrandFooter, BrandHeader } from "../brand";
import { AccessibilityRunner } from "./AccessibilityRunner";

export const metadata: Metadata = {
  title: "Accessibility check | bsns tools",
  description:
    "Free, automated website accessibility check. Flags machine-detectable WCAG issues like missing alt text, unlabeled forms, and blocked zoom — no account, no ads."
};

export default function AccessibilityPage() {
  return (
    <main className="page-shell">
      <BrandHeader />

      <section className="hero single-column">
        <div className="hero-copy">
          <p className="eyebrow">bsns accessibility</p>
          <h1>Check your website for common accessibility problems.</h1>
          <p className="subhead">
            Free, open source, no account. Catches the machine-detectable issues behind most web
            accessibility complaints.
          </p>
        </div>

        <AccessibilityRunner />
      </section>

      <section className="sample-report" aria-labelledby="a11y-about-heading">
        <div className="sample-intro">
          <p className="eyebrow">What this checks</p>
          <h2 id="a11y-about-heading">A starting point, not a certification</h2>
          <p>
            This scan reads each page&apos;s HTML and flags issues automated testing can catch:
            images without alt text, form fields without labels, links and buttons with no name,
            missing page titles or language, skipped headings, and viewport settings that block
            zoom. It checks the page you enter plus a few key linked pages (contact, menu, booking).
          </p>
          <p>
            Automated testing finds only part of what matters. It is not a substitute for a manual
            audit or testing with real assistive technology, and it is not a legal compliance
            certification. Use it to fix the obvious problems and to prioritize a deeper review.
          </p>
        </div>
      </section>

      <BrandFooter />
    </main>
  );
}
