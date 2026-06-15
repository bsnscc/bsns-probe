import { describe, expect, it } from "vitest";

import {
  ProbeInputError,
  isBlockedIp,
  normalizeDomainInput,
  resolvePublicAddresses
} from "./domain.js";
import type { AddressResolver } from "./domain.js";

describe("normalizeDomainInput", () => {
  it("normalizes pasted https URLs to a hostname", () => {
    const target = normalizeDomainInput(" https://Example.COM/some/path?x=1 ");

    expect(target.hostname).toBe("example.com");
    expect(target.asciiHostname).toBe("example.com");
    expect(target.registrableDomain).toBe("example.com");
  });

  it("converts IDNs to ASCII while preserving a readable hostname", () => {
    const target = normalizeDomainInput("BÜCHER.de");

    expect(target.hostname).toBe("bücher.de");
    expect(target.asciiHostname).toBe("xn--bcher-kva.de");
    expect(target.registrableDomain).toBe("xn--bcher-kva.de");
  });

  it("accepts a trailing DNS root dot", () => {
    const target = normalizeDomainInput("example.com.");

    expect(target.asciiHostname).toBe("example.com");
  });

  it.each([
    "localhost",
    "service.local",
    "service.internal",
    "example.test",
    "example.invalid",
    "example.onion"
  ])("rejects local or reserved hostname %s", (input) => {
    expect(() => normalizeDomainInput(input)).toThrow(ProbeInputError);
  });

  it.each([
    "127.0.0.1",
    "http://127.0.0.1",
    "http://[::1]",
    "2130706433",
    "bad_domain.com",
    "https://user:pass@example.com",
    "https://example.com:8443"
  ])("rejects invalid or unsafe input %s", (input) => {
    expect(() => normalizeDomainInput(input)).toThrow(ProbeInputError);
  });
});

describe("isBlockedIp", () => {
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "192.0.2.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1"
  ])("blocks reserved IPv4 address %s", (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each(["8.8.8.8", "1.1.1.1", "172.32.0.1"])(
    "allows public IPv4 address %s",
    (ip) => {
      expect(isBlockedIp(ip)).toBe(false);
    }
  );

  it.each([
    "::",
    "::1",
    "::ffff:192.168.1.1",
    "64:ff9b::1",
    "100::1",
    "2001:db8::1",
    "2002::1",
    "fc00::1",
    "fe80::1",
    "fec0::1",
    "ff02::1"
  ])("blocks reserved IPv6 address %s", (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });

  it.each(["2606:4700:4700::1111", "2001:4860:4860::8888"])(
    "allows public IPv6 address %s",
    (ip) => {
      expect(isBlockedIp(ip)).toBe(false);
    }
  );
});

describe("resolvePublicAddresses", () => {
  it("returns public addresses from a resolver", async () => {
    let seenHostname = "";
    const resolver: AddressResolver = {
      async lookup(hostname) {
        seenHostname = hostname;
        return [
          { address: "93.184.216.34", family: 4 },
          { address: "2606:4700:4700::1111", family: 6 }
        ];
      }
    };

    const addresses = await resolvePublicAddresses("Example.com", resolver);

    expect(seenHostname).toBe("example.com");
    expect(addresses).toHaveLength(2);
  });

  it("resolves IDNs using the ASCII hostname", async () => {
    let seenHostname = "";
    const resolver: AddressResolver = {
      async lookup(hostname) {
        seenHostname = hostname;
        return [{ address: "93.184.216.34", family: 4 }];
      }
    };

    await resolvePublicAddresses("bücher.de", resolver);

    expect(seenHostname).toBe("xn--bcher-kva.de");
  });

  it("rejects hostnames that resolve to a blocked address", async () => {
    const resolver: AddressResolver = {
      async lookup() {
        return [{ address: "10.0.0.5", family: 4 }];
      }
    };

    await expect(resolvePublicAddresses("example.com", resolver)).rejects.toMatchObject({
      code: "BLOCKED_DNS_ADDRESS"
    });
  });

  it("rejects mixed public and blocked answers", async () => {
    const resolver: AddressResolver = {
      async lookup() {
        return [
          { address: "93.184.216.34", family: 4 },
          { address: "127.0.0.1", family: 4 }
        ];
      }
    };

    await expect(resolvePublicAddresses("example.com", resolver)).rejects.toMatchObject({
      code: "BLOCKED_DNS_ADDRESS"
    });
  });

  it("rejects empty DNS responses", async () => {
    const resolver: AddressResolver = {
      async lookup() {
        return [];
      }
    };

    await expect(resolvePublicAddresses("example.com", resolver)).rejects.toMatchObject({
      code: "DNS_NO_PUBLIC_ADDRESSES"
    });
  });
});
