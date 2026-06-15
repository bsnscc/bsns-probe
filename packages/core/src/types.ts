import type { DnsResolver } from "./dns.js";
import type { AddressResolver } from "./domain.js";
import type { HttpClient } from "./http.js";
import type { TlsInspector } from "./tls.js";

export type FindingStatus = "pass" | "warn" | "fail" | "info" | "skip";

export type FindingSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info";

export type FindingCategory =
  | "dns"
  | "email"
  | "web"
  | "tls"
  | "headers"
  | "performance"
  | "meta";

export interface Finding {
  id: string;
  category: FindingCategory;
  status: FindingStatus;
  severity: FindingSeverity;
  title: string;
  summary: string;
  evidence?: Record<string, unknown>;
  whyItMatters?: string;
  fix?: string;
  references?: Array<{ label: string; url: string }>;
}

export interface ScoreCategory {
  score: number;
  max: number;
}

export type ReportGrade = "A" | "B" | "C" | "D" | "F";

export interface ProbeReport {
  schemaVersion: "1.0";
  target: {
    input: string;
    hostname: string;
    asciiHostname: string;
    registrableDomain: string | null;
    scannedAt: string;
  };
  score: {
    total: number;
    grade: ReportGrade;
    categories: Record<string, ScoreCategory>;
  };
  summary: {
    headline: string;
    topFixes: string[];
    counts: Record<FindingStatus, number>;
  };
  findings: Finding[];
  raw: {
    dns?: unknown;
    http?: unknown;
    tls?: unknown;
    email?: unknown;
    performance?: unknown;
    timings?: unknown;
  };
}

export interface ScanOptions {
  addressResolver?: AddressResolver;
  dkimSelectors?: string[];
  dnsResolver?: DnsResolver;
  httpClient?: HttpClient;
  includeRaw?: boolean;
  tlsInspector?: TlsInspector;
  timeoutMs?: number;
}
