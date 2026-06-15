import type { DnsResolver, NormalizedDnsError } from "./dns.js";
import type { AddressResolver, NormalizedTarget } from "./domain.js";
import { createGuardedHttpClient } from "./http.js";
import type { HttpClient } from "./http.js";
import type { Finding } from "./types.js";

export type EmailDnsResolver = Pick<DnsResolver, "resolveTxt">;

export interface EmailCheckOptions {
  addressResolver?: AddressResolver;
  httpClient?: HttpClient;
  resolver?: EmailDnsResolver;
  selectors?: string[];
  timeoutMs?: number;
}

export interface EmailCheckResult {
  findings: Finding[];
  raw: EmailRawResult | EmailPartialRawResult;
}

export interface EmailRawResult {
  domain: string;
  checkedAt: string;
  spf: {
    lookup: TxtLookupResult;
    records: string[];
    parsed?: SpfRecord;
    lookupCount?: SpfLookupCountResult;
  };
  dmarc: {
    hostname: string;
    lookup: TxtLookupResult;
    records: string[];
    parsed?: DmarcRecord;
  };
  dkim: {
    checkedSelectors: string[];
    selectors: DkimSelectorResult[];
  };
  mtaSts: {
    hostname: string;
    lookup: TxtLookupResult;
    present: boolean;
    policy?: MtaStsPolicyFetchResult;
  };
  tlsRpt: {
    hostname: string;
    lookup: TxtLookupResult;
    present: boolean;
  };
}

export interface EmailPartialRawResult {
  domain: string;
  checkedAt: string;
  status: "timeout" | "error" | "skipped";
  timeoutMs?: number;
  reason?: string;
  error?: {
    code: string;
    message: string;
  };
}

export interface TxtLookupResult {
  status: "ok" | "empty" | "error";
  records: string[];
  error?: NormalizedDnsError;
}

export interface SpfRecord {
  raw: string;
  mechanisms: SpfMechanism[];
  modifiers: SpfModifier[];
  terminalAll?: {
    qualifier: SpfQualifier;
    raw: string;
  };
}

export type SpfQualifier = "+" | "-" | "~" | "?";

export interface SpfMechanism {
  raw: string;
  qualifier: SpfQualifier;
  name: string;
  value?: string;
}

export interface SpfModifier {
  raw: string;
  name: string;
  value: string;
}

export interface SpfLookupCountResult {
  count: number;
  mechanisms: Array<{ domain: string; term: string; count: number }>;
  errors: Array<{ domain: string; message: string }>;
}

export interface DmarcRecord {
  raw: string;
  tags: Record<string, string>;
}

export interface DkimSelectorResult {
  selector: string;
  hostname: string;
  lookup: TxtLookupResult;
  record?: DkimRecord;
}

export interface DkimRecord {
  raw: string;
  tags: Record<string, string>;
}

export interface MtaStsPolicyFetchResult {
  url: string;
  status: "ok" | "error";
  httpStatus?: number;
  parsed?: MtaStsPolicy;
  error?: {
    code: string;
    message: string;
  };
}

export interface MtaStsPolicy {
  version?: string;
  mode?: string;
  maxAge?: number;
  mx: string[];
}

const COMMON_DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "mail",
  "dkim"
];

const DNS_LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);

export async function checkEmail(
  target: NormalizedTarget,
  options: EmailCheckOptions = {}
): Promise<EmailCheckResult> {
  const resolver = options.resolver ?? DEFAULT_EMAIL_RESOLVER;
  const httpClient = options.httpClient ?? createGuardedHttpClient(options.addressResolver);
  const domain = target.registrableDomain ?? target.asciiHostname;
  const selectors = normalizeSelectors(options.selectors);

  const [spfLookup, dmarcLookup, dkimSelectors, mtaStsLookup, tlsRptLookup] = await Promise.all([
    lookupTxt(domain, resolver),
    lookupTxt(`_dmarc.${domain}`, resolver),
    lookupDkimSelectors(domain, selectors, resolver),
    lookupTxt(`_mta-sts.${domain}`, resolver),
    lookupTxt(`_smtp._tls.${domain}`, resolver)
  ]);

  const spfRecords = spfLookup.records.filter(isSpfRecord);
  const spfRecord = spfRecords.length === 1 ? spfRecords[0] : undefined;
  const parsedSpf = spfRecord ? parseSpfRecord(spfRecord) : undefined;
  const lookupCount = parsedSpf
    ? await countSpfDnsLookups(domain, parsedSpf, resolver)
    : undefined;

  const dmarcRecords = dmarcLookup.records.filter(isDmarcRecord);
  const dmarcRecord = dmarcRecords.length === 1 ? dmarcRecords[0] : undefined;
  const parsedDmarc = dmarcRecord ? parseDmarcRecord(dmarcRecord) : undefined;
  const mtaStsPresent = mtaStsLookup.records.some(isMtaStsRecord);
  const mtaStsPolicy = mtaStsPresent
    ? await fetchMtaStsPolicy(domain, httpClient, options.timeoutMs ?? 8000)
    : undefined;
  const raw: EmailRawResult = {
    domain,
    checkedAt: new Date().toISOString(),
    spf: {
      lookup: spfLookup,
      records: spfRecords,
      ...(parsedSpf ? { parsed: parsedSpf } : {}),
      ...(lookupCount ? { lookupCount } : {})
    },
    dmarc: {
      hostname: `_dmarc.${domain}`,
      lookup: dmarcLookup,
      records: dmarcRecords,
      ...(parsedDmarc ? { parsed: parsedDmarc } : {})
    },
    dkim: {
      checkedSelectors: selectors,
      selectors: dkimSelectors
    },
    mtaSts: {
      hostname: `_mta-sts.${domain}`,
      lookup: mtaStsLookup,
      present: mtaStsPresent,
      ...(mtaStsPolicy ? { policy: mtaStsPolicy } : {})
    },
    tlsRpt: {
      hostname: `_smtp._tls.${domain}`,
      lookup: tlsRptLookup,
      present: tlsRptLookup.records.some(isTlsRptRecord)
    }
  };

  return {
    findings: buildEmailFindings(raw),
    raw
  };
}

export function parseSpfRecord(raw: string): SpfRecord {
  const terms = raw.trim().split(/\s+/u).slice(1);
  const mechanisms: SpfMechanism[] = [];
  const modifiers: SpfModifier[] = [];

  for (const term of terms) {
    if (!term) {
      continue;
    }

    const modifierMatch = /^([a-z][a-z0-9_-]*)=(.+)$/iu.exec(term);
    if (modifierMatch?.[1] && modifierMatch[2]) {
      modifiers.push({
        raw: term,
        name: modifierMatch[1].toLowerCase(),
        value: modifierMatch[2]
      });
      continue;
    }

    const firstChar = term.charAt(0);
    const qualifier = isSpfQualifier(firstChar) ? firstChar : "+";
    const body = isSpfQualifier(firstChar) ? term.slice(1) : term;
    const mechanismMatch = /^([a-z][a-z0-9_-]*)(?::([^/]+))?(?:\/.+)?$/iu.exec(body);

    if (!mechanismMatch?.[1]) {
      continue;
    }

    mechanisms.push({
      raw: term,
      qualifier,
      name: mechanismMatch[1].toLowerCase(),
      ...(mechanismMatch[2] ? { value: mechanismMatch[2] } : {})
    });
  }

  const terminalAll = [...mechanisms]
    .reverse()
    .find((mechanism) => mechanism.name === "all");

  return {
    raw,
    mechanisms,
    modifiers,
    ...(terminalAll ? { terminalAll: { qualifier: terminalAll.qualifier, raw: terminalAll.raw } } : {})
  };
}

export function parseDmarcRecord(raw: string): DmarcRecord {
  return {
    raw,
    tags: parseTagList(raw)
  };
}

export function parseDkimRecord(raw: string): DkimRecord {
  return {
    raw,
    tags: parseTagList(raw)
  };
}

export function parseMtaStsPolicy(raw: string): MtaStsPolicy {
  const policy: MtaStsPolicy = {
    mx: []
  };

  for (const line of raw.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separator = trimmed.indexOf(":");
    if (separator === -1) {
      continue;
    }

    const key = trimmed.slice(0, separator).trim().toLowerCase();
    const value = trimmed.slice(separator + 1).trim();

    if (key === "version") {
      policy.version = value;
    } else if (key === "mode") {
      policy.mode = value;
    } else if (key === "max_age") {
      const parsed = Number.parseInt(value, 10);
      if (Number.isFinite(parsed) && parsed >= 0) {
        policy.maxAge = parsed;
      }
    } else if (key === "mx") {
      policy.mx.push(value);
    }
  }

  return policy;
}

async function fetchMtaStsPolicy(
  domain: string,
  httpClient: HttpClient,
  timeoutMs: number
): Promise<MtaStsPolicyFetchResult> {
  const url = new URL(`https://mta-sts.${domain}/.well-known/mta-sts.txt`);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await httpClient.fetch(url, {
      signal: controller.signal
    });
    const text = response.body?.text ? await response.body.text(64 * 1024) : "";
    await response.body?.cancel();

    return {
      url: url.toString(),
      status: response.status === 200 ? "ok" : "error",
      httpStatus: response.status,
      ...(response.status === 200 && text ? { parsed: parseMtaStsPolicy(text) } : {})
    };
  } catch (error) {
    return {
      url: url.toString(),
      status: "error",
      error: {
        code: getErrorCode(error),
        message: error instanceof Error ? error.message : "MTA-STS policy fetch failed."
      }
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function lookupDkimSelectors(
  domain: string,
  selectors: string[],
  resolver: EmailDnsResolver
): Promise<DkimSelectorResult[]> {
  return Promise.all(
    selectors.map(async (selector) => {
      const hostname = `${selector}._domainkey.${domain}`;
      const lookup = await lookupTxt(hostname, resolver);
      const record = lookup.records.find(isDkimRecord);

      return {
        selector,
        hostname,
        lookup,
        ...(record ? { record: parseDkimRecord(record) } : {})
      };
    })
  );
}

async function countSpfDnsLookups(
  domain: string,
  record: SpfRecord,
  resolver: EmailDnsResolver,
  seen: Set<string> = new Set()
): Promise<SpfLookupCountResult> {
  const result: SpfLookupCountResult = {
    count: 0,
    mechanisms: [],
    errors: []
  };
  const normalizedDomain = domain.toLowerCase();

  if (seen.has(normalizedDomain)) {
    result.errors.push({
      domain,
      message: "SPF include or redirect loop detected."
    });
    return result;
  }

  const nextSeen = new Set(seen);
  nextSeen.add(normalizedDomain);

  for (const mechanism of record.mechanisms) {
    if (!DNS_LOOKUP_MECHANISMS.has(mechanism.name)) {
      continue;
    }

    result.count += 1;
    result.mechanisms.push({ domain, term: mechanism.raw, count: 1 });

    if (mechanism.name === "include" && mechanism.value) {
      const nested = await lookupSingleSpfRecord(mechanism.value, resolver);
      if (nested.record) {
        mergeLookupCount(
          result,
          await countSpfDnsLookups(mechanism.value, nested.record, resolver, nextSeen)
        );
      } else if (nested.error) {
        result.errors.push(nested.error);
      }
    }
  }

  const redirect = record.modifiers.find((modifier) => modifier.name === "redirect");
  if (redirect) {
    result.count += 1;
    result.mechanisms.push({ domain, term: redirect.raw, count: 1 });
    const nested = await lookupSingleSpfRecord(redirect.value, resolver);

    if (nested.record) {
      mergeLookupCount(
        result,
        await countSpfDnsLookups(redirect.value, nested.record, resolver, nextSeen)
      );
    } else if (nested.error) {
      result.errors.push(nested.error);
    }
  }

  return result;
}

async function lookupSingleSpfRecord(
  domain: string,
  resolver: EmailDnsResolver
): Promise<{ record?: SpfRecord; error?: { domain: string; message: string } }> {
  const lookup = await lookupTxt(domain, resolver);
  const records = lookup.records.filter(isSpfRecord);
  const record = records.length === 1 ? records[0] : undefined;

  if (record) {
    return { record: parseSpfRecord(record) };
  }

  if (records.length > 1) {
    return {
      error: {
        domain,
        message: "Nested SPF lookup returned multiple SPF records."
      }
    };
  }

  return {
    error: {
      domain,
      message: lookup.error?.message ?? "Nested SPF lookup did not return an SPF record."
    }
  };
}

function mergeLookupCount(target: SpfLookupCountResult, source: SpfLookupCountResult): void {
  target.count += source.count;
  target.mechanisms.push(...source.mechanisms);
  target.errors.push(...source.errors);
}

async function lookupTxt(hostname: string, resolver: EmailDnsResolver): Promise<TxtLookupResult> {
  try {
    const records = await resolver.resolveTxt(hostname);
    const flattened = records.map((chunks) => chunks.join(""));

    return {
      status: flattened.length > 0 ? "ok" : "empty",
      records: flattened
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

function buildEmailFindings(raw: EmailRawResult): Finding[] {
  return [
    ...buildSpfFindings(raw),
    ...buildDmarcFindings(raw),
    ...buildDkimFindings(raw),
    ...buildMtaStsFindings(raw),
    ...buildTlsRptFindings(raw)
  ];
}

function buildSpfFindings(raw: EmailRawResult): Finding[] {
  const findings: Finding[] = [];
  const { spf } = raw;

  if (spf.lookup.status === "error") {
    findings.push({
      id: "email.spf.lookup_error",
      category: "email",
      status: "warn",
      severity: "low",
      title: "SPF lookup failed",
      summary: `TXT lookup for ${raw.domain} failed while checking SPF.`,
      evidence: spf.lookup.error ? { error: spf.lookup.error } : undefined,
      whyItMatters: "Temporary DNS errors can hide the current SPF policy.",
      fix: "Retry the check and confirm the domain's DNS provider is responding."
    });
    return findings;
  }

  if (spf.records.length === 0) {
    findings.push({
      id: "email.spf.missing",
      category: "email",
      status: "warn",
      severity: "medium",
      title: "No SPF record found",
      summary: `${raw.domain} does not publish an SPF record.`,
      whyItMatters:
        "SPF helps receiving mail systems identify which servers are allowed to send for a domain.",
      fix: "Publish one SPF TXT record at the domain if this domain sends email."
    });
    return findings;
  }

  if (spf.records.length > 1) {
    findings.push({
      id: "email.spf.multiple_records",
      category: "email",
      status: "fail",
      severity: "high",
      title: "Multiple SPF records found",
      summary: `${raw.domain} publishes more than one SPF record.`,
      evidence: { records: spf.records },
      whyItMatters: "SPF requires exactly one SPF record; multiple records can cause SPF evaluation to fail.",
      fix: "Merge the SPF mechanisms into one TXT record that starts with v=spf1."
    });
    return findings;
  }

  findings.push({
    id: "email.spf.present",
    category: "email",
    status: "pass",
    severity: "info",
    title: "SPF record found",
    summary: `${raw.domain} publishes one SPF record.`,
    evidence: {
      record: spf.records[0],
      lookupCount: spf.lookupCount?.count ?? 0
    }
  });

  const parsed = spf.parsed;
  if (!parsed) {
    return findings;
  }

  const terminalAll = parsed.terminalAll;
  if (terminalAll?.qualifier === "+") {
    findings.push({
      id: "email.spf.permissive_all",
      category: "email",
      status: "fail",
      severity: "high",
      title: "SPF allows every sender",
      summary: `${raw.domain} ends its SPF policy with ${terminalAll.raw}, which allows any server to send mail for the domain.`,
      evidence: { record: parsed.raw },
      whyItMatters: "A permissive SPF policy removes most of SPF's anti-spoofing value.",
      fix: "Replace +all with -all or ~all after confirming the authorized senders are listed."
    });
  } else if (!terminalAll) {
    findings.push({
      id: "email.spf.missing_terminal_all",
      category: "email",
      status: "warn",
      severity: "medium",
      title: "SPF has no terminal all mechanism",
      summary: `${raw.domain}'s SPF record does not end with an all mechanism.`,
      evidence: { record: parsed.raw },
      whyItMatters: "An explicit all mechanism makes the fallback policy clear to receivers.",
      fix: "Add -all or ~all at the end of the SPF record after confirming legitimate senders."
    });
  } else if (terminalAll.qualifier === "?") {
    findings.push({
      id: "email.spf.neutral_all",
      category: "email",
      status: "warn",
      severity: "low",
      title: "SPF ends with neutral all",
      summary: `${raw.domain}'s SPF policy ends with ?all, which tells receivers not to draw a strong conclusion.`,
      evidence: { record: parsed.raw },
      whyItMatters: "Neutral SPF policies are useful during setup but weak for long-term spoofing resistance.",
      fix: "Move to ~all or -all after validating legitimate mail flows."
    });
  }

  const lookupCount = spf.lookupCount?.count ?? 0;
  if (lookupCount > 10) {
    findings.push({
      id: "email.spf.lookup_limit_exceeded",
      category: "email",
      status: "fail",
      severity: "high",
      title: "SPF DNS lookup limit exceeded",
      summary: `${raw.domain}'s SPF policy uses about ${lookupCount} DNS lookups, which exceeds the SPF limit of 10.`,
      evidence: {
        count: lookupCount,
        mechanisms: spf.lookupCount?.mechanisms,
        errors: spf.lookupCount?.errors
      },
      whyItMatters: "Receivers can return a permanent SPF error when the policy exceeds the DNS lookup limit.",
      fix: "Remove unused include, a, mx, exists, or redirect terms until SPF needs 10 or fewer DNS lookups."
    });
  } else if (lookupCount >= 8) {
    findings.push({
      id: "email.spf.lookup_limit_near",
      category: "email",
      status: "warn",
      severity: "medium",
      title: "SPF DNS lookup count is high",
      summary: `${raw.domain}'s SPF policy uses about ${lookupCount} DNS lookups.`,
      evidence: {
        count: lookupCount,
        mechanisms: spf.lookupCount?.mechanisms,
        errors: spf.lookupCount?.errors
      },
      whyItMatters: "SPF allows at most 10 DNS lookups during evaluation.",
      fix: "Flatten or remove unused SPF includes before adding more mail providers."
    });
  }

  return findings;
}

function buildDmarcFindings(raw: EmailRawResult): Finding[] {
  const findings: Finding[] = [];
  const { dmarc } = raw;

  if (dmarc.lookup.status === "error") {
    return [
      {
        id: "email.dmarc.lookup_error",
        category: "email",
        status: "warn",
        severity: "low",
        title: "DMARC lookup failed",
        summary: `TXT lookup for ${dmarc.hostname} failed.`,
        evidence: dmarc.lookup.error ? { error: dmarc.lookup.error } : undefined,
        whyItMatters: "Temporary DNS errors can hide the current DMARC policy.",
        fix: "Retry the check and confirm the domain's DNS provider is responding."
      }
    ];
  }

  if (dmarc.records.length === 0) {
    return [
      {
        id: "email.dmarc.missing",
        category: "email",
        status: "warn",
        severity: "medium",
        title: "No DMARC record found",
        summary: `${dmarc.hostname} does not publish a DMARC record.`,
        whyItMatters:
          "DMARC tells receivers how to handle mail that fails SPF or DKIM alignment.",
        fix: `Publish a DMARC TXT record at ${dmarc.hostname}, starting with p=none while monitoring legitimate mail.`
      }
    ];
  }

  if (dmarc.records.length > 1) {
    return [
      {
        id: "email.dmarc.multiple_records",
        category: "email",
        status: "fail",
        severity: "high",
        title: "Multiple DMARC records found",
        summary: `${dmarc.hostname} publishes more than one DMARC record.`,
        evidence: { records: dmarc.records },
        whyItMatters: "DMARC requires a single policy record at the _dmarc hostname.",
        fix: "Merge the DMARC policy into one TXT record."
      }
    ];
  }

  const policy = dmarc.parsed?.tags.p?.toLowerCase();
  if (policy === "reject" || policy === "quarantine") {
    findings.push({
      id: "email.dmarc.enforcing_policy",
      category: "email",
      status: "pass",
      severity: "info",
      title: "DMARC enforcing policy found",
      summary: `${raw.domain} uses DMARC p=${policy}.`,
      evidence: { record: dmarc.records[0] },
      whyItMatters: "An enforcing DMARC policy can reduce successful direct domain spoofing."
    });
  } else if (policy === "none") {
    findings.push({
      id: "email.dmarc.none_policy",
      category: "email",
      status: "warn",
      severity: "low",
      title: "DMARC is in monitoring mode",
      summary: `${raw.domain} uses DMARC p=none.`,
      evidence: { record: dmarc.records[0] },
      whyItMatters:
        "p=none is useful for visibility, but it does not ask receivers to quarantine or reject failing mail.",
      fix: "Review aggregate reports, then consider p=quarantine or p=reject once legitimate mail is aligned."
    });
  } else {
    findings.push({
      id: "email.dmarc.invalid_policy",
      category: "email",
      status: "warn",
      severity: "medium",
      title: "DMARC policy is missing or invalid",
      summary: `${dmarc.hostname} has a DMARC record, but the p tag was not recognized.`,
      evidence: { record: dmarc.records[0] },
      whyItMatters: "Receivers need a valid p tag to understand the requested DMARC policy.",
      fix: "Set the DMARC p tag to none, quarantine, or reject."
    });
  }

  if (!dmarc.parsed?.tags.rua) {
    findings.push({
      id: "email.dmarc.missing_rua",
      category: "email",
      status: "warn",
      severity: "low",
      title: "DMARC aggregate reports are not configured",
      summary: `${dmarc.hostname} does not include a rua reporting address.`,
      evidence: { record: dmarc.records[0] },
      whyItMatters: "Aggregate reports show which systems are sending mail for the domain.",
      fix: "Add a rua tag after choosing where DMARC aggregate reports should be delivered."
    });
  }

  return findings;
}

function buildDkimFindings(raw: EmailRawResult): Finding[] {
  const found = raw.dkim.selectors.filter((selector) => selector.record);

  if (found.length > 0) {
    return [
      {
        id: "email.dkim.selector_found",
        category: "email",
        status: "pass",
        severity: "info",
        title: "DKIM selector record found",
        summary:
          found.length === 1
            ? `Found a DKIM record for selector ${found[0]?.selector}.`
            : `Found DKIM records for ${found.length} selectors.`,
        evidence: {
          selectors: found.map((selector) => ({
            selector: selector.selector,
            hostname: selector.hostname,
            tags: selector.record?.tags
          }))
        },
        whyItMatters: "DKIM lets receivers verify that signed mail was authorized by the domain."
      }
    ];
  }

  return [
    {
      id: "email.dkim.no_known_selector_found",
      category: "email",
      status: "info",
      severity: "info",
      title: "No DKIM record found for checked selectors",
      summary:
        "No DKIM record was found for the selectors checked. DKIM selectors are arbitrary, so this is not proof that DKIM is missing.",
      evidence: { selectors: raw.dkim.checkedSelectors },
      whyItMatters: "DKIM records can only be checked when a selector is known or guessed.",
      fix: "If you know your mail provider's DKIM selector, rerun the check with that selector."
    }
  ];
}

function buildMtaStsFindings(raw: EmailRawResult): Finding[] {
  if (raw.mtaSts.present) {
    const findings: Finding[] = [
      {
        id: "email.mta_sts.present",
        category: "email",
        status: "pass",
        severity: "info",
        title: "MTA-STS policy record found",
        summary: `${raw.mtaSts.hostname} publishes an MTA-STS TXT record.`,
        evidence: { records: raw.mtaSts.lookup.records },
        whyItMatters: "MTA-STS can help receiving mail servers require TLS for inbound mail."
      }
    ];

    if (raw.mtaSts.policy?.status === "ok" && isValidMtaStsPolicy(raw.mtaSts.policy.parsed)) {
      findings.push({
        id: "email.mta_sts.policy_found",
        category: "email",
        status: "pass",
        severity: "info",
        title: "MTA-STS policy file found",
        summary: `https://mta-sts.${raw.domain}/.well-known/mta-sts.txt returned a valid policy shape.`,
        evidence: {
          url: raw.mtaSts.policy.url,
          httpStatus: raw.mtaSts.policy.httpStatus,
          policy: raw.mtaSts.policy.parsed
        },
        whyItMatters: "The TXT record points receivers to this HTTPS policy file."
      });
    } else if (raw.mtaSts.policy?.status === "ok") {
      findings.push({
        id: "email.mta_sts.policy_invalid",
        category: "email",
        status: "warn",
        severity: "low",
        title: "MTA-STS policy file is incomplete",
        summary: "The MTA-STS policy file was reachable but did not include the expected fields.",
        evidence: {
          url: raw.mtaSts.policy.url,
          httpStatus: raw.mtaSts.policy.httpStatus,
          policy: raw.mtaSts.policy.parsed
        },
        whyItMatters: "Receivers need version, mode, max_age, and at least one mx entry.",
        fix: "Update the MTA-STS policy file with version, mode, mx, and max_age fields."
      });
    } else if (raw.mtaSts.policy) {
      findings.push({
        id: "email.mta_sts.policy_unreachable",
        category: "email",
        status: "warn",
        severity: "low",
        title: "MTA-STS policy file was not reachable",
        summary: "The MTA-STS TXT record exists, but the HTTPS policy file could not be fetched.",
        evidence: {
          url: raw.mtaSts.policy.url,
          httpStatus: raw.mtaSts.policy.httpStatus,
          error: raw.mtaSts.policy.error
        },
        whyItMatters: "MTA-STS requires both the DNS TXT record and the HTTPS policy file.",
        fix: `Serve the policy at https://mta-sts.${raw.domain}/.well-known/mta-sts.txt.`
      });
    }

    return findings;
  }

  return [
    {
      id: "email.mta_sts.missing",
      category: "email",
      status: "info",
      severity: "low",
      title: "No MTA-STS record found",
      summary: `${raw.mtaSts.hostname} does not publish an MTA-STS TXT record.`,
      evidence: raw.mtaSts.lookup.error ? { error: raw.mtaSts.lookup.error } : undefined,
      whyItMatters: "MTA-STS is optional, but it can improve inbound mail transport security.",
      fix: "Consider MTA-STS after confirming inbound mail is reliably available over TLS."
    }
  ];
}

function isValidMtaStsPolicy(policy: MtaStsPolicy | undefined): boolean {
  if (!policy) {
    return false;
  }

  return (
    policy.version === "STSv1" &&
    (policy.mode === "enforce" || policy.mode === "testing" || policy.mode === "none") &&
    typeof policy.maxAge === "number" &&
    policy.mx.length > 0
  );
}

function buildTlsRptFindings(raw: EmailRawResult): Finding[] {
  if (raw.tlsRpt.present) {
    return [
      {
        id: "email.tls_rpt.present",
        category: "email",
        status: "pass",
        severity: "info",
        title: "SMTP TLS reporting record found",
        summary: `${raw.tlsRpt.hostname} publishes a TLS-RPT TXT record.`,
        evidence: { records: raw.tlsRpt.lookup.records },
        whyItMatters: "SMTP TLS reporting can show delivery issues related to encrypted mail transport."
      }
    ];
  }

  return [
    {
      id: "email.tls_rpt.missing",
      category: "email",
      status: "info",
      severity: "low",
      title: "No SMTP TLS reporting record found",
      summary: `${raw.tlsRpt.hostname} does not publish a TLS-RPT TXT record.`,
      evidence: raw.tlsRpt.lookup.error ? { error: raw.tlsRpt.lookup.error } : undefined,
      whyItMatters: "TLS-RPT is optional, but it helps monitor inbound mail TLS problems.",
      fix: "Consider TLS-RPT if you enable MTA-STS or want visibility into inbound mail TLS failures."
    }
  ];
}

function normalizeSelectors(selectors: string[] | undefined): string[] {
  const normalized = [...(selectors ?? []), ...COMMON_DKIM_SELECTORS]
    .map((selector) => selector.trim().toLowerCase())
    .filter((selector) => /^[a-z0-9._-]+$/u.test(selector));

  return [...new Set(normalized)];
}

function parseTagList(raw: string): Record<string, string> {
  const tags: Record<string, string> = {};

  for (const part of raw.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    const value = valueParts.join("=").trim();

    if (!name || !value) {
      continue;
    }

    tags[name.toLowerCase()] = value;
  }

  return tags;
}

function isSpfRecord(record: string): boolean {
  return /^v=spf1(?:\s|$)/iu.test(record.trim());
}

function isDmarcRecord(record: string): boolean {
  return /^v=dmarc1(?:\s*;|$)/iu.test(record.trim());
}

function isDkimRecord(record: string): boolean {
  const tags = parseTagList(record);
  return tags.v?.toUpperCase() === "DKIM1" && typeof tags.p === "string";
}

function isMtaStsRecord(record: string): boolean {
  return /^v=STSv1(?:\s*;|$)/iu.test(record.trim());
}

function isTlsRptRecord(record: string): boolean {
  return /^v=TLSRPTv1(?:\s*;|$)/iu.test(record.trim());
}

function isSpfQualifier(value: string): value is SpfQualifier {
  return value === "+" || value === "-" || value === "~" || value === "?";
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

const DEFAULT_EMAIL_RESOLVER: EmailDnsResolver = {
  async resolveTxt(hostname: string) {
    const dns = await import("node:dns/promises");
    return dns.resolveTxt(hostname);
  }
};
