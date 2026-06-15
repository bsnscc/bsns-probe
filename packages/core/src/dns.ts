import dns from "node:dns/promises";
import type { CaaRecord, MxRecord, RecordWithTtl } from "node:dns";

import { ProbeInputError, isBlockedIp } from "./domain.js";
import type { NormalizedTarget } from "./domain.js";
import type { Finding } from "./types.js";

export interface DnsResolver {
  resolve4(hostname: string, options: { ttl: true }): Promise<RecordWithTtl[]>;
  resolve6(hostname: string, options: { ttl: true }): Promise<RecordWithTtl[]>;
  resolveCname(hostname: string): Promise<string[]>;
  resolveNs(hostname: string): Promise<string[]>;
  resolveMx(hostname: string): Promise<MxRecord[]>;
  resolveTxt(hostname: string): Promise<string[][]>;
  resolveCaa(hostname: string): Promise<CaaRecord[]>;
}

export interface DnsCheckResult {
  findings: Finding[];
  raw: DnsRawResult | DnsPartialRawResult;
}

export interface DnsRawResult {
  hostname: string;
  registrableDomain: string | null;
  checkedAt: string;
  records: {
    target: {
      a: DnsLookupResult<RecordWithTtl>;
      aaaa: DnsLookupResult<RecordWithTtl>;
      cnameChain: CnameChainResult;
    };
    registrableDomain?: {
      a: DnsLookupResult<RecordWithTtl>;
      aaaa: DnsLookupResult<RecordWithTtl>;
      ns: DnsLookupResult<string>;
      mx: DnsLookupResult<MxRecord>;
      txt: DnsLookupResult<string[]>;
      caa: DnsLookupResult<CaaRecord>;
    };
    www?: {
      hostname: string;
      a: DnsLookupResult<RecordWithTtl>;
      aaaa: DnsLookupResult<RecordWithTtl>;
      cnameChain: CnameChainResult;
    };
  };
}

export interface DnsPartialRawResult {
  hostname: string;
  registrableDomain: string | null;
  checkedAt: string;
  status: "timeout" | "error";
  timeoutMs: number;
  error?: {
    code: string;
    message: string;
  };
}

export interface DnsLookupResult<T> {
  status: "ok" | "empty" | "error";
  records: T[];
  error?: NormalizedDnsError;
}

export interface NormalizedDnsError {
  code: string;
  kind: "not_found" | "no_records" | "servfail" | "timeout" | "refused" | "other";
  message: string;
}

export interface CnameChainResult {
  status: "ok" | "loop" | "error";
  chain: string[];
  error?: NormalizedDnsError;
}

const DEFAULT_DNS_RESOLVER: DnsResolver = {
  resolve4: dns.resolve4,
  resolve6: dns.resolve6,
  resolveCname: dns.resolveCname,
  resolveNs: dns.resolveNs,
  resolveMx: dns.resolveMx,
  resolveTxt: dns.resolveTxt,
  resolveCaa: dns.resolveCaa
};

const MAX_CNAME_DEPTH = 8;

export async function checkDns(
  target: NormalizedTarget,
  resolver: DnsResolver = DEFAULT_DNS_RESOLVER
): Promise<DnsCheckResult> {
  const hostname = target.asciiHostname;
  const registrableDomain = target.registrableDomain;
  const wwwHostname =
    registrableDomain && hostname === registrableDomain ? `www.${registrableDomain}` : null;

  const [a, aaaa, cnameChain, registrableRecords, wwwRecords] = await Promise.all([
    lookupRecords(() => resolver.resolve4(hostname, { ttl: true })),
    lookupRecords(() => resolver.resolve6(hostname, { ttl: true })),
    resolveCnameChain(hostname, resolver),
    registrableDomain ? lookupRegistrableDomainRecords(registrableDomain, resolver) : undefined,
    wwwHostname ? lookupWwwRecords(wwwHostname, resolver) : undefined
  ]);

  assertNoBlockedTargetAddresses([...a.records, ...aaaa.records]);

  const raw: DnsRawResult = {
    hostname,
    registrableDomain,
    checkedAt: new Date().toISOString(),
    records: {
      target: {
        a,
        aaaa,
        cnameChain
      },
      ...(registrableRecords ? { registrableDomain: registrableRecords } : {}),
      ...(wwwRecords ? { www: wwwRecords } : {})
    }
  };

  return {
    findings: buildDnsFindings(raw),
    raw
  };
}

function assertNoBlockedTargetAddresses(records: RecordWithTtl[]): void {
  const blockedAddresses = records
    .map((record) => record.address)
    .filter((address) => isBlockedIp(address));

  if (blockedAddresses.length > 0) {
    throw new ProbeInputError(
      "BLOCKED_DNS_ADDRESS",
      "That domain resolves to a private or reserved network address."
    );
  }
}

async function lookupRegistrableDomainRecords(
  domain: string,
  resolver: DnsResolver
): Promise<NonNullable<DnsRawResult["records"]["registrableDomain"]>> {
  const [a, aaaa, ns, mx, txt, caa] = await Promise.all([
    lookupRecords(() => resolver.resolve4(domain, { ttl: true })),
    lookupRecords(() => resolver.resolve6(domain, { ttl: true })),
    lookupRecords(() => resolver.resolveNs(domain)),
    lookupRecords(() => resolver.resolveMx(domain)),
    lookupRecords(() => resolver.resolveTxt(domain)),
    lookupRecords(() => resolver.resolveCaa(domain))
  ]);

  return { a, aaaa, ns, mx, txt, caa };
}

async function lookupWwwRecords(
  hostname: string,
  resolver: DnsResolver
): Promise<NonNullable<DnsRawResult["records"]["www"]>> {
  const [a, aaaa, cnameChain] = await Promise.all([
    lookupRecords(() => resolver.resolve4(hostname, { ttl: true })),
    lookupRecords(() => resolver.resolve6(hostname, { ttl: true })),
    resolveCnameChain(hostname, resolver)
  ]);

  return { hostname, a, aaaa, cnameChain };
}

async function lookupRecords<T>(lookup: () => Promise<T[]>): Promise<DnsLookupResult<T>> {
  try {
    const records = await lookup();
    return {
      status: records.length > 0 ? "ok" : "empty",
      records
    };
  } catch (error) {
    const normalized = normalizeDnsError(error);

    if (normalized.kind === "no_records" || normalized.kind === "not_found") {
      return {
        status: "empty",
        records: [],
        error: normalized
      };
    }

    return {
      status: "error",
      records: [],
      error: normalized
    };
  }
}

async function resolveCnameChain(
  hostname: string,
  resolver: DnsResolver
): Promise<CnameChainResult> {
  const seen = new Set<string>();
  const chain = [hostname];
  let current = hostname;

  for (let depth = 0; depth < MAX_CNAME_DEPTH; depth += 1) {
    seen.add(current);

    try {
      const records = await resolver.resolveCname(current);
      const next = records[0]?.replace(/\.$/u, "").toLowerCase();

      if (!next) {
        return { status: "ok", chain };
      }

      chain.push(next);

      if (seen.has(next)) {
        return { status: "loop", chain };
      }

      current = next;
    } catch (error) {
      const normalized = normalizeDnsError(error);

      if (normalized.kind === "no_records" || normalized.kind === "not_found") {
        return { status: "ok", chain };
      }

      return { status: "error", chain, error: normalized };
    }
  }

  return { status: "loop", chain };
}

function buildDnsFindings(raw: DnsRawResult): Finding[] {
  const findings: Finding[] = [];
  const targetHasAddress =
    raw.records.target.a.records.length > 0 || raw.records.target.aaaa.records.length > 0;

  if (raw.records.target.cnameChain.status === "loop") {
    findings.push({
      id: "dns.cname.loop",
      category: "dns",
      status: "fail",
      severity: "high",
      title: "CNAME loop detected",
      summary: `${raw.hostname} has a CNAME chain that loops back on itself.`,
      evidence: { chain: raw.records.target.cnameChain.chain },
      whyItMatters: "A CNAME loop prevents resolvers from reaching a final address.",
      fix: "Update DNS so the CNAME chain ends at a hostname with A or AAAA records."
    });
  }

  if (targetHasAddress) {
    findings.push({
      id: "dns.resolve.ok",
      category: "dns",
      status: "pass",
      severity: "info",
      title: "Domain resolves",
      summary: `${raw.hostname} has public address records.`,
      evidence: {
        a: raw.records.target.a.records,
        aaaa: raw.records.target.aaaa.records
      }
    });
  } else {
    const error = raw.records.target.a.error ?? raw.records.target.aaaa.error;
    findings.push({
      id: "dns.resolve.error",
      category: "dns",
      status: "fail",
      severity: "high",
      title: "Domain does not resolve to an address",
      summary: `${raw.hostname} did not return A or AAAA records.`,
      evidence: error ? { error } : undefined,
      whyItMatters: "Browsers and mail providers need DNS address records to reach a host.",
      fix: "Add an A record, an AAAA record, or a valid CNAME target with address records."
    });
  }

  if (raw.records.target.a.records.length === 0) {
    findings.push({
      id: "dns.a.missing",
      category: "dns",
      status: "warn",
      severity: "medium",
      title: "No A records found",
      summary: `${raw.hostname} does not publish IPv4 A records.`,
      evidence: raw.records.target.a.error ? { error: raw.records.target.a.error } : undefined,
      whyItMatters: "Most clients still expect IPv4 reachability.",
      fix: "Add an A record if this hostname should serve a website or receive direct traffic."
    });
  }

  if (raw.records.target.aaaa.records.length === 0) {
    findings.push({
      id: "dns.aaaa.missing",
      category: "dns",
      status: "info",
      severity: "low",
      title: "No AAAA records found",
      summary: `${raw.hostname} does not publish IPv6 AAAA records.`,
      evidence: raw.records.target.aaaa.error
        ? { error: raw.records.target.aaaa.error }
        : undefined,
      whyItMatters: "IPv6 is useful but not required for most small-business sites.",
      fix: "Add an AAAA record when your hosting provider supports IPv6."
    });
  }

  const registrable = raw.records.registrableDomain;

  if (registrable) {
    if (registrable.ns.records.length > 0) {
      findings.push({
        id: "dns.ns.present",
        category: "dns",
        status: "pass",
        severity: "info",
        title: "Name servers found",
        summary: `${raw.registrableDomain} publishes NS records.`,
        evidence: { ns: registrable.ns.records }
      });
    } else {
      findings.push({
        id: "dns.ns.missing",
        category: "dns",
        status: "fail",
        severity: "high",
        title: "No NS records found",
        summary: `${raw.registrableDomain} did not return NS records.`,
        evidence: registrable.ns.error ? { error: registrable.ns.error } : undefined,
        whyItMatters: "NS records delegate a domain to authoritative name servers.",
        fix: "Configure name servers at the registrar or DNS provider for this domain."
      });
    }

    if (registrable.mx.records.length === 0) {
      findings.push({
        id: "dns.mx.missing",
        category: "dns",
        status: "info",
        severity: "info",
        title: "No MX records found",
        summary: `${raw.registrableDomain} did not return MX records.`,
        evidence: registrable.mx.error ? { error: registrable.mx.error } : undefined,
        whyItMatters:
          "MX records are needed only when this domain is intended to receive email.",
        fix: "Add MX records if this domain should receive email."
      });
    }

    if (registrable.caa.records.length > 0) {
      findings.push({
        id: "dns.caa.present",
        category: "dns",
        status: "pass",
        severity: "info",
        title: "CAA records found",
        summary: `${raw.registrableDomain} publishes CAA records.`,
        evidence: { caa: registrable.caa.records },
        whyItMatters: "CAA records can limit which certificate authorities may issue certificates."
      });
    } else {
      findings.push({
        id: "dns.caa.missing",
        category: "dns",
        status: "info",
        severity: "low",
        title: "No CAA records found",
        summary: `${raw.registrableDomain} did not return CAA records.`,
        evidence: registrable.caa.error ? { error: registrable.caa.error } : undefined,
        whyItMatters: "CAA is optional, but it can reduce certificate issuance risk.",
        fix: "Add CAA records if you want to restrict certificate issuance."
      });
    }
  }

  const www = raw.records.www;
  if (www) {
    const wwwHasAddress = www.a.records.length > 0 || www.aaaa.records.length > 0;
    findings.push({
      id: wwwHasAddress ? "dns.www.present" : "dns.www.missing",
      category: "dns",
      status: "info",
      severity: "info",
      title: wwwHasAddress ? "www hostname resolves" : "www hostname not found",
      summary: wwwHasAddress
        ? `${www.hostname} has address records.`
        : `${www.hostname} did not return A or AAAA records.`,
      evidence: {
        a: www.a.records,
        aaaa: www.aaaa.records,
        cnameChain: www.cnameChain.chain
      },
      whyItMatters: "Many users still try both the apex domain and the www hostname.",
      fix: wwwHasAddress
        ? undefined
        : "Add www DNS records or redirect www traffic if that hostname should work."
    });
  }

  return findings;
}

function normalizeDnsError(error: unknown): NormalizedDnsError {
  const code = getErrorCode(error);
  const message = error instanceof Error ? error.message : "DNS lookup failed.";

  return {
    code,
    kind: classifyDnsError(code),
    message
  };
}

function getErrorCode(error: unknown): string {
  if (error && typeof error === "object" && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && code.length > 0) {
      return code;
    }
  }

  return "UNKNOWN";
}

function classifyDnsError(code: string): NormalizedDnsError["kind"] {
  switch (code) {
    case "ENOTFOUND":
    case "ENODATA":
      return "no_records";
    case "ENOTIMP":
    case "ENONAME":
      return "not_found";
    case "ESERVFAIL":
      return "servfail";
    case "ETIMEOUT":
    case "ECANCELLED":
      return "timeout";
    case "EREFUSED":
      return "refused";
    default:
      return "other";
  }
}
