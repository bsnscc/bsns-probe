import { type HTMLElement, parse } from "node-html-parser";

export type { HTMLElement } from "node-html-parser";

export interface ParsedDocument {
  root: HTMLElement;
}

/**
 * Parse a page's HTML into a queryable tree. We keep comments and the raw
 * attribute casing off the hot path; rules read attributes case-insensitively.
 */
export function parseDocument(html: string): ParsedDocument {
  const root = parse(html, {
    lowerCaseTagName: true,
    comment: false,
    blockTextElements: {
      script: false,
      noscript: false,
      style: false,
      pre: true
    }
  });

  return { root };
}

/** All elements matching any of the given lowercase tag names. */
export function elementsByTag(root: HTMLElement, ...tags: string[]): HTMLElement[] {
  const wanted = new Set(tags.map((tag) => tag.toLowerCase()));
  return root.querySelectorAll("*").filter((el) => wanted.has(el.rawTagName?.toLowerCase() ?? ""));
}

/** Case-insensitive attribute read that treats empty-string as present. */
export function attr(el: HTMLElement, name: string): string | undefined {
  const attrs = el.attributes;
  const lowered = name.toLowerCase();
  for (const key of Object.keys(attrs)) {
    if (key.toLowerCase() === lowered) {
      return attrs[key];
    }
  }
  return undefined;
}

export function hasAttr(el: HTMLElement, name: string): boolean {
  return attr(el, name) !== undefined;
}

/** Visible text content, collapsed to single spaces. */
export function visibleText(el: HTMLElement): string {
  return el.text.replace(/\s+/gu, " ").trim();
}

/**
 * Whether an element is hidden from the accessibility tree in a way a static
 * scan can detect: aria-hidden, the hidden attribute, or inline display:none.
 * (Stylesheet-driven hiding needs a rendered scan and is out of scope.)
 */
export function isStaticallyHidden(el: HTMLElement): boolean {
  if (attr(el, "aria-hidden") === "true") {
    return true;
  }
  if (hasAttr(el, "hidden")) {
    return true;
  }
  if (attr(el, "type")?.toLowerCase() === "hidden") {
    return true;
  }
  const style = attr(el, "style")?.replace(/\s+/gu, "").toLowerCase();
  if (style && (style.includes("display:none") || style.includes("visibility:hidden"))) {
    return true;
  }
  return false;
}

/**
 * Compute the accessible name of an interactive element from the parts a static
 * scan can see: aria-label, aria-labelledby (resolved against the document),
 * the title attribute, an alt on a sole child image, and visible text.
 */
export function accessibleName(el: HTMLElement, root: HTMLElement): string {
  const ariaLabel = attr(el, "aria-label")?.trim();
  if (ariaLabel) {
    return ariaLabel;
  }

  const labelledBy = attr(el, "aria-labelledby")?.trim();
  if (labelledBy) {
    const resolved = labelledBy
      .split(/\s+/u)
      .map((id) => root.querySelector(`#${cssEscapeId(id)}`))
      .filter((node): node is HTMLElement => Boolean(node))
      .map((node) => visibleText(node))
      .filter(Boolean)
      .join(" ")
      .trim();
    if (resolved) {
      return resolved;
    }
  }

  const text = visibleText(el);
  if (text) {
    return text;
  }

  const childImgAlt = el
    .querySelectorAll("img")
    .map((img) => attr(img, "alt")?.trim())
    .find((value) => value);
  if (childImgAlt) {
    return childImgAlt;
  }

  const title = attr(el, "title")?.trim();
  if (title) {
    return title;
  }

  return "";
}

/** Escape an id for use in a `#id` selector (node-html-parser is permissive but quirky). */
function cssEscapeId(id: string): string {
  return id.replace(/["\\\]]/gu, "\\$&");
}
