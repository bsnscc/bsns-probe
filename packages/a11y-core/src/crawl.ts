import { attr, elementsByTag, parseDocument, visibleText } from "./html.js";

/** Path/label keywords that mark a page as worth checking, highest value first. */
const KEY_PAGE_KEYWORDS: Array<{ pattern: RegExp; weight: number }> = [
  { pattern: /contact/iu, weight: 100 },
  { pattern: /\b(book|reserv|appointment|schedul)/iu, weight: 95 },
  { pattern: /\b(order|menu|shop|store|cart|checkout)/iu, weight: 90 },
  { pattern: /\b(service|offer)/iu, weight: 80 },
  { pattern: /\b(hour|location|find-us|directions)/iu, weight: 75 },
  { pattern: /\babout/iu, weight: 60 },
  { pattern: /\b(accessib|account|sign-?in|log-?in|register)/iu, weight: 55 }
];

const SKIP_EXTENSION = /\.(?:pdf|jpe?g|png|gif|svg|webp|zip|docx?|xlsx?|mp4|mp3|css|js|ico)$/iu;

/**
 * Discover up to `limit` additional same-host pages worth scanning, by reading
 * the seed page's links and ranking them by how operationally important they
 * look (contact, booking, ordering, etc.). The homepage is always included.
 */
export function discoverPages(seedHtml: string, seedUrl: string, limit: number): string[] {
  if (limit <= 0) {
    return [];
  }

  const seed = new URL(seedUrl);
  const seedKey = pageKey(seed);
  const candidates = new Map<string, { url: string; weight: number; order: number }>();
  let order = 0;

  const consider = (rawHref: string | undefined, label: string, baseWeight: number) => {
    if (!rawHref) {
      return;
    }
    const resolved = resolveSameHost(rawHref, seed);
    if (!resolved) {
      return;
    }
    const key = pageKey(resolved);
    if (key === seedKey || candidates.has(key)) {
      return;
    }
    candidates.set(key, {
      url: resolved.toString(),
      weight: baseWeight + keywordWeight(`${resolved.pathname} ${label}`),
      order: (order += 1)
    });
  };

  // Always try the homepage.
  consider("/", "home", 70);

  const { root } = parseDocument(seedHtml);
  for (const link of elementsByTag(root, "a")) {
    consider(attr(link, "href"), visibleText(link), 0);
  }

  return Array.from(candidates.values())
    .filter((candidate) => candidate.weight > 0)
    .sort((a, b) => b.weight - a.weight || a.order - b.order)
    .slice(0, limit)
    .map((candidate) => candidate.url);
}

function resolveSameHost(href: string, base: URL): URL | null {
  const trimmed = href.trim();
  if (!trimmed || trimmed.startsWith("#") || /^(?:mailto:|tel:|javascript:|data:)/iu.test(trimmed)) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(trimmed, base);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null;
  }
  if (url.hostname !== base.hostname) {
    return null;
  }
  if (SKIP_EXTENSION.test(url.pathname)) {
    return null;
  }
  return url;
}

function keywordWeight(text: string): number {
  for (const { pattern, weight } of KEY_PAGE_KEYWORDS) {
    if (pattern.test(text)) {
      return weight;
    }
  }
  return 0;
}

/** Identity for a page: host + path, ignoring query and fragment. */
function pageKey(url: URL): string {
  const path = url.pathname.replace(/\/+$/u, "") || "/";
  return `${url.hostname}${path}`;
}
