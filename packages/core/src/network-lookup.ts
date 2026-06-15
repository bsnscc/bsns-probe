import type { AddressResolver, LookupAddress } from "./domain.js";
import { resolvePublicAddresses } from "./domain.js";

export interface NodeLookupOptions {
  all?: boolean;
  family?: number | "IPv4" | "IPv6";
}

export type NodeLookupCallback = (
  error: Error | null,
  addressOrAddresses: string | LookupAddress[],
  family?: number
) => void;

export function guardedNodeLookup(
  hostname: string,
  lookupOptions: NodeLookupOptions,
  callback: NodeLookupCallback,
  addressResolver?: AddressResolver
): void {
  void resolvePublicAddresses(hostname, addressResolver)
    .then((addresses) => {
      pinnedNodeLookup(addresses, lookupOptions, callback);
    })
    .catch((error: unknown) => {
      callback(error instanceof Error ? error : new Error("DNS lookup failed."), "", 0);
    });
}

export function pinnedNodeLookup(
  addresses: LookupAddress[],
  lookupOptions: NodeLookupOptions,
  callback: NodeLookupCallback
): void {
  const preferredFamily = lookupFamily(lookupOptions.family);
  const filteredAddresses =
    preferredFamily === null
      ? addresses
      : addresses.filter((address) => address.family === preferredFamily);
  const candidates = filteredAddresses.length > 0 ? filteredAddresses : addresses;
  const selected = candidates[0];

  if (!selected) {
    callback(new Error("That domain did not resolve to any public addresses."), "", 0);
    return;
  }

  if (lookupOptions.all) {
    callback(null, candidates);
    return;
  }

  callback(null, selected.address, selected.family);
}

function lookupFamily(family: NodeLookupOptions["family"]): 4 | 6 | null {
  if (family === 6 || family === "IPv6") {
    return 6;
  }

  if (family === 4 || family === "IPv4") {
    return 4;
  }

  return null;
}
