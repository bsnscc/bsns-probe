import { describe, expect, it } from "vitest";

import { checkTls } from "./tls.js";
import type { TlsInspection, TlsInspector } from "./tls.js";
import type { AddressResolver, NormalizedTarget } from "./domain.js";

const TARGET: NormalizedTarget = {
  input: "example.com",
  hostname: "example.com",
  asciiHostname: "example.com",
  registrableDomain: "example.com"
};

const NOW = new Date("2026-06-15T00:00:00.000Z");

describe("checkTls", () => {
  it("passes a trusted, matching, current certificate", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector(validInspection()),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.valid")).toMatchObject({
      status: "pass"
    });
  });

  it("reports expired certificates", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector(
        validInspection({
          certificate: certificate({ validTo: "2026-06-01T00:00:00.000Z" })
        })
      ),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.expired")).toMatchObject({
      status: "fail",
      severity: "critical"
    });
  });

  it("reports certificates expiring soon with threshold severity", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector(
        validInspection({
          certificate: certificate({ validTo: "2026-06-20T00:00:00.000Z" })
        })
      ),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.expiring_soon")).toMatchObject({
      status: "warn",
      severity: "critical"
    });
  });

  it("reports hostname mismatches", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector(
        validInspection({
          certificate: certificate({ subjectAltNames: ["www.example.com"] })
        })
      ),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.hostname_mismatch")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("accepts wildcard SAN matches for one label", async () => {
    const result = await checkTls(
      {
        ...TARGET,
        hostname: "www.example.com",
        asciiHostname: "www.example.com"
      },
      {
        inspector: inspector(
          validInspection({
            certificate: certificate({ subjectAltNames: ["*.example.com"] })
          })
        ),
        now: NOW
      }
    );

    expect(result.findings.find((item) => item.id === "tls.hostname_mismatch")).toBeUndefined();
    expect(result.findings.find((item) => item.id === "tls.valid")).toBeDefined();
  });

  it("reports untrusted chains", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector(
        validInspection({
          chainTrusted: false,
          authorizationError: "self-signed certificate"
        })
      ),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.untrusted_chain")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("reports legacy TLS protocols", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector(
        validInspection({
          negotiatedProtocol: "TLSv1.1"
        })
      ),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.legacy_protocol")).toMatchObject({
      status: "warn",
      severity: "medium"
    });
  });

  it("reports TLS handshake failures", async () => {
    const result = await checkTls(TARGET, {
      inspector: inspector({
        handshake: false,
        chainTrusted: false,
        error: {
          code: "ECONNREFUSED",
          message: "connection refused"
        }
      }),
      now: NOW
    });

    expect(result.findings.find((item) => item.id === "tls.handshake_failed")).toMatchObject({
      status: "fail",
      severity: "high"
    });
  });

  it("blocks private addresses during the live TLS connection lookup", async () => {
    const result = await checkTls(TARGET, {
      addressResolver: privateAddressResolver(),
      now: NOW,
      timeoutMs: 100
    });

    expect(result.findings.find((item) => item.id === "tls.handshake_failed")).toMatchObject({
      status: "fail",
      severity: "high"
    });
    expect(result.raw.error).toMatchObject({
      code: "BLOCKED_DNS_ADDRESS"
    });
  });
});

function inspector(inspection: TlsInspection): TlsInspector {
  return {
    async inspect() {
      return inspection;
    }
  };
}

function validInspection(overrides: Partial<TlsInspection> = {}): TlsInspection {
  return {
    handshake: true,
    chainTrusted: true,
    negotiatedProtocol: "TLSv1.3",
    certificate: certificate(),
    ...overrides
  };
}

function certificate(
  overrides: Partial<NonNullable<TlsInspection["certificate"]>> = {}
): NonNullable<TlsInspection["certificate"]> {
  return {
    subject: { CN: "example.com" },
    issuer: { CN: "Test CA" },
    validFrom: "2026-01-01T00:00:00.000Z",
    validTo: "2026-12-31T00:00:00.000Z",
    subjectAltNames: ["example.com"],
    fingerprint256: "00:11",
    ...overrides
  };
}

function privateAddressResolver(): AddressResolver {
  return {
    async lookup() {
      return [{ address: "127.0.0.1", family: 4 }];
    }
  };
}
