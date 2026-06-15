import { lookup as nodeLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII, domainToUnicode } from "node:url";

import { parse } from "tldts";

export type ProbeInputErrorCode =
  | "INVALID_DOMAIN"
  | "BLOCKED_HOSTNAME"
  | "BLOCKED_IP"
  | "BLOCKED_DNS_ADDRESS"
  | "DNS_NO_PUBLIC_ADDRESSES";

export class ProbeInputError extends Error {
  readonly code: ProbeInputErrorCode;

  constructor(code: ProbeInputErrorCode, message: string) {
    super(message);
    this.name = "ProbeInputError";
    this.code = code;
  }
}

export interface NormalizedTarget {
  input: string;
  hostname: string;
  asciiHostname: string;
  registrableDomain: string | null;
}

export interface LookupAddress {
  address: string;
  family: 4 | 6;
}

export interface AddressResolver {
  lookup(
    hostname: string,
    options: { all: true; verbatim: true }
  ): Promise<LookupAddress[]>;
}

const BLOCKED_HOST_SUFFIXES = new Set([
  "localhost",
  "local",
  "internal",
  "test",
  "example",
  "invalid",
  "onion"
]);

const LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const BLOCKED_IPV4_RANGES: Array<[number, number]> = [
  [ipv4ToNumber("0.0.0.0"), 8],
  [ipv4ToNumber("10.0.0.0"), 8],
  [ipv4ToNumber("100.64.0.0"), 10],
  [ipv4ToNumber("127.0.0.0"), 8],
  [ipv4ToNumber("169.254.0.0"), 16],
  [ipv4ToNumber("172.16.0.0"), 12],
  [ipv4ToNumber("192.0.0.0"), 24],
  [ipv4ToNumber("192.0.2.0"), 24],
  [ipv4ToNumber("192.88.99.0"), 24],
  [ipv4ToNumber("192.168.0.0"), 16],
  [ipv4ToNumber("198.18.0.0"), 15],
  [ipv4ToNumber("198.51.100.0"), 24],
  [ipv4ToNumber("203.0.113.0"), 24],
  [ipv4ToNumber("224.0.0.0"), 4],
  [ipv4ToNumber("240.0.0.0"), 4]
];

const BLOCKED_IPV6_RANGES: Array<[bigint, number]> = [
  [ipv6ToBigInt("::"), 128],
  [ipv6ToBigInt("::1"), 128],
  [ipv6ToBigInt("::ffff:0:0"), 96],
  [ipv6ToBigInt("64:ff9b::"), 96],
  [ipv6ToBigInt("64:ff9b:1::"), 48],
  [ipv6ToBigInt("100::"), 64],
  [ipv6ToBigInt("2001::"), 23],
  [ipv6ToBigInt("2001:db8::"), 32],
  [ipv6ToBigInt("2002::"), 16],
  [ipv6ToBigInt("fc00::"), 7],
  [ipv6ToBigInt("fe80::"), 10],
  [ipv6ToBigInt("fec0::"), 10],
  [ipv6ToBigInt("ff00::"), 8]
];

const DEFAULT_ADDRESS_RESOLVER: AddressResolver = {
  async lookup(hostname, options) {
    const addresses = await nodeLookup(hostname, options);
    return addresses.map((entry) => ({
      address: entry.address,
      family: entry.family === 6 ? 6 : 4
    }));
  }
};

export function normalizeDomainInput(input: string): NormalizedTarget {
  const originalInput = input;
  const trimmed = input.trim();

  if (!trimmed) {
    throw new ProbeInputError(
      "INVALID_DOMAIN",
      "Enter a public domain name, not an IP address or local hostname."
    );
  }

  const hostname = extractHostname(trimmed);
  const withoutTrailingDot = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  const asciiHostname = domainToASCII(withoutTrailingDot).toLowerCase();

  if (!asciiHostname) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  assertPublicHostname(asciiHostname);
  assertValidHostnameSyntax(asciiHostname);

  const parsed = parse(asciiHostname, {
    allowPrivateDomains: true,
    validateHostname: true
  });

  if (!parsed.publicSuffix) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a domain with a public suffix.");
  }

  return {
    input: originalInput,
    hostname: domainToUnicode(asciiHostname).toLowerCase(),
    asciiHostname,
    registrableDomain: parsed.domain ?? null
  };
}

export function assertPublicHostname(hostname: string): void {
  const asciiHostname = domainToASCII(hostname.trim().replace(/\.$/u, "")).toLowerCase();

  if (!asciiHostname) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  if (isIP(stripIpv6Brackets(asciiHostname)) !== 0) {
    throw new ProbeInputError(
      "BLOCKED_IP",
      "Enter a public domain name, not an IP address."
    );
  }

  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (asciiHostname === suffix || asciiHostname.endsWith(`.${suffix}`)) {
      throw new ProbeInputError(
        "BLOCKED_HOSTNAME",
        "Enter a public domain name, not a local or reserved hostname."
      );
    }
  }
}

export function isBlockedIp(ip: string): boolean {
  const withoutBrackets = stripIpv6Brackets(ip.trim());
  const family = isIP(withoutBrackets);

  if (family === 4) {
    const numeric = ipv4ToNumber(withoutBrackets);
    return BLOCKED_IPV4_RANGES.some(([base, prefix]) =>
      isIpv4InCidr(numeric, base, prefix)
    );
  }

  if (family === 6) {
    const numeric = ipv6ToBigInt(withoutBrackets);
    return BLOCKED_IPV6_RANGES.some(([base, prefix]) =>
      isIpv6InCidr(numeric, base, prefix)
    );
  }

  return true;
}

export async function resolvePublicAddresses(
  hostname: string,
  resolver: AddressResolver = DEFAULT_ADDRESS_RESOLVER
): Promise<LookupAddress[]> {
  const target = normalizeDomainInput(hostname);
  const addresses = await resolver.lookup(target.asciiHostname, {
    all: true,
    verbatim: true
  });

  if (addresses.length === 0) {
    throw new ProbeInputError(
      "DNS_NO_PUBLIC_ADDRESSES",
      "That domain did not resolve to any public addresses."
    );
  }

  const blocked = addresses.filter((entry) => isBlockedIp(entry.address));

  if (blocked.length > 0) {
    throw new ProbeInputError(
      "BLOCKED_DNS_ADDRESS",
      "That domain resolves to a private or reserved network address."
    );
  }

  return addresses;
}

function extractHostname(input: string): string {
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//iu.test(input);
  const candidate = hasScheme ? input : `https://${input}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ProbeInputError("INVALID_DOMAIN", "Only http and https URLs can be pasted.");
  }

  if (parsed.username || parsed.password) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a domain name without credentials.");
  }

  if (parsed.port) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a domain name without a custom port.");
  }

  return parsed.hostname;
}

function assertValidHostnameSyntax(hostname: string): void {
  if (hostname.length > 253) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  const labels = hostname.split(".");

  if (labels.length < 2) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a domain with a public suffix.");
  }

  for (const label of labels) {
    if (!LABEL_PATTERN.test(label)) {
      throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
    }
  }
}

function stripIpv6Brackets(ip: string): string {
  return ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip;
}

function ipv4ToNumber(ip: string): number {
  const octets = ip.split(".").map((part) => Number.parseInt(part, 10));

  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  return (
    ((octets[0] ?? 0) * 2 ** 24) +
    ((octets[1] ?? 0) * 2 ** 16) +
    ((octets[2] ?? 0) * 2 ** 8) +
    (octets[3] ?? 0)
  ) >>> 0;
}

function isIpv4InCidr(value: number, base: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function ipv6ToBigInt(ip: string): bigint {
  const normalized = normalizeIpv6(ip);
  return normalized.reduce((accumulator, part) => (accumulator << 16n) + BigInt(part), 0n);
}

function normalizeIpv6(ip: string): number[] {
  const embeddedIpv4 = ip.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/u);
  let working = ip;
  let embeddedParts: number[] = [];

  if (embeddedIpv4?.[1]) {
    const numeric = ipv4ToNumber(embeddedIpv4[1]);
    embeddedParts = [(numeric >>> 16) & 0xffff, numeric & 0xffff];
    working = working.slice(0, -embeddedIpv4[1].length);

    if (working.endsWith(":") && !working.endsWith("::")) {
      working = working.slice(0, -1);
    }
  }

  const halves = working.split("::");

  if (halves.length > 2) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  const head = parseIpv6PartList(halves[0] ?? "");
  const tail = parseIpv6PartList(halves[1] ?? "");
  const missing = 8 - embeddedParts.length - head.length - tail.length;

  if (missing < 0 || (halves.length === 1 && missing !== 0)) {
    throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
  }

  return [...head, ...Array.from({ length: missing }, () => 0), ...tail, ...embeddedParts];
}

function parseIpv6PartList(value: string): number[] {
  if (!value) {
    return [];
  }

  return value.split(":").map((part) => {
    if (!/^[0-9a-f]{1,4}$/iu.test(part)) {
      throw new ProbeInputError("INVALID_DOMAIN", "Enter a valid public domain name.");
    }

    return Number.parseInt(part, 16);
  });
}

function isIpv6InCidr(value: bigint, base: bigint, prefix: number): boolean {
  const bits = 128n;
  const prefixBits = BigInt(prefix);
  const mask = prefix === 0 ? 0n : ((1n << prefixBits) - 1n) << (bits - prefixBits);
  return (value & mask) === (base & mask);
}
