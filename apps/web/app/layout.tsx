import type { Metadata } from "next";
import type { ReactNode } from "react";

import { satoshi } from "./fonts";
import "./styles.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://tools.bsns.cc"),
  applicationName: "bsns probe",
  title: {
    default: "bsns probe | bsns tools",
    template: "%s | bsns tools"
  },
  description: "Check a domain's DNS, website, TLS, headers, and email setup.",
  alternates: {
    canonical: "/"
  },
  icons: {
    icon: [{ url: "/icon.svg", type: "image/svg+xml" }],
    shortcut: [{ url: "/icon.svg", type: "image/svg+xml" }]
  },
  manifest: "/manifest.webmanifest",
  openGraph: {
    title: "bsns probe",
    description: "Check a domain's DNS, website, TLS, headers, and email setup.",
    url: "https://tools.bsns.cc",
    siteName: "bsns tools",
    type: "website"
  },
  twitter: {
    card: "summary_large_image",
    title: "bsns probe",
    description: "Check a domain's DNS, website, TLS, headers, and email setup."
  }
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className={satoshi.variable}>{children}</body>
    </html>
  );
}
