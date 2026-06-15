import { describe, expect, it } from "vitest";

import type { AddressResolver, LookupAddress } from "./domain.js";
import { guardedNodeLookup, pinnedNodeLookup } from "./network-lookup.js";

const publicAddresses: LookupAddress[] = [
  { address: "93.184.216.34", family: 4 },
  { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }
];

const resolver: AddressResolver = {
  async lookup() {
    return publicAddresses;
  }
};

describe("guardedNodeLookup", () => {
  it("uses the single-address callback shape by default", async () => {
    const result = await runLookup({ family: 4 });

    expect(result).toEqual([null, "93.184.216.34", 4]);
  });

  it("uses the all-addresses callback shape when Node requests all addresses", async () => {
    const result = await runLookup({ all: true });

    expect(result).toEqual([null, publicAddresses, undefined]);
  });

  it("filters all-addresses responses by requested family", async () => {
    const result = await runLookup({ all: true, family: 6 });

    expect(result).toEqual([
      null,
      [{ address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }],
      undefined
    ]);
  });
});

describe("pinnedNodeLookup", () => {
  it("returns only the pinned address set without resolving again", async () => {
    const result = await runPinnedLookup(publicAddresses, { all: true });

    expect(result).toEqual([null, publicAddresses, undefined]);
  });

  it("uses the single-address callback shape from a pinned address set", async () => {
    const result = await runPinnedLookup(publicAddresses, { family: 6 });

    expect(result).toEqual([null, "2606:2800:220:1:248:1893:25c8:1946", 6]);
  });
});

function runLookup(options: { all?: boolean; family?: number }) {
  return new Promise<[Error | null, string | LookupAddress[], number | undefined]>((resolve) => {
    guardedNodeLookup(
      "example.com",
      options,
      (error, addressOrAddresses, family) => resolve([error, addressOrAddresses, family]),
      resolver
    );
  });
}

function runPinnedLookup(addresses: LookupAddress[], options: { all?: boolean; family?: number }) {
  return new Promise<[Error | null, string | LookupAddress[], number | undefined]>((resolve) => {
    pinnedNodeLookup(addresses, options, (error, addressOrAddresses, family) =>
      resolve([error, addressOrAddresses, family])
    );
  });
}
