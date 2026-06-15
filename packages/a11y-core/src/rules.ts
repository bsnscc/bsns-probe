import {
  type HTMLElement,
  accessibleName,
  attr,
  elementsByTag,
  hasAttr,
  isStaticallyHidden,
  parseDocument,
  visibleText
} from "./html.js";
import type { A11yCategory, A11yFinding } from "./types.js";

/** Generic, unhelpful link/button text that fails out of context. */
const GENERIC_LINK_TEXT = new Set([
  "click here",
  "click",
  "here",
  "read more",
  "more",
  "learn more",
  "link",
  "this",
  "details",
  "go"
]);

const MAX_EXAMPLES = 5;

/**
 * Parse a page's HTML and run every static accessibility rule against it.
 * Returns one finding per rule outcome (a single aggregated finding per rule,
 * with a count and a few examples, rather than one finding per element).
 */
export function runRules(html: string): A11yFinding[] {
  const { root } = parseDocument(html);
  return [
    ...checkLanguage(root),
    ...checkTitle(root),
    ...checkViewport(root),
    ...checkImages(root),
    ...checkFormLabels(root),
    ...checkHeadings(root),
    ...checkLandmarks(root),
    ...checkLinksAndButtons(root),
    ...checkTables(root),
    ...checkDuplicateIds(root)
  ];
}

function checkLanguage(root: HTMLElement): A11yFinding[] {
  const html = root.querySelector("html");
  const lang = html ? attr(html, "lang")?.trim() : undefined;

  if (!lang) {
    return [
      finding({
        id: "a11y.language.html_lang_missing",
        category: "language",
        status: "fail",
        severity: "high",
        title: "Page language is not set",
        summary: "The <html> element has no lang attribute.",
        whyItMatters:
          "Screen readers use the page language to choose the right voice and pronunciation. Without it, content can be read with the wrong accent or rules.",
        fix: 'Add a language to the page, e.g. <html lang="en">.'
      })
    ];
  }

  return [
    finding({
      id: "a11y.language.html_lang_present",
      category: "language",
      status: "pass",
      severity: "info",
      title: "Page language is set",
      summary: `The page declares lang="${lang}".`,
      evidence: { lang }
    })
  ];
}

function checkTitle(root: HTMLElement): A11yFinding[] {
  const title = root.querySelector("title");
  const text = title ? visibleText(title) : "";

  if (!text) {
    return [
      finding({
        id: "a11y.language.title_missing",
        category: "language",
        status: "fail",
        severity: "high",
        title: "Page has no title",
        summary: "The page is missing a non-empty <title> element.",
        whyItMatters:
          "The title is the first thing a screen reader announces and is how users tell tabs and history entries apart.",
        fix: "Add a descriptive <title> to the page <head>."
      })
    ];
  }

  return [
    finding({
      id: "a11y.language.title_present",
      category: "language",
      status: "pass",
      severity: "info",
      title: "Page has a title",
      summary: `The page title is "${text}".`,
      evidence: { title: text }
    })
  ];
}

function checkViewport(root: HTMLElement): A11yFinding[] {
  const viewport = elementsByTag(root, "meta").find(
    (meta) => attr(meta, "name")?.toLowerCase() === "viewport"
  );
  const content = viewport ? attr(viewport, "content")?.toLowerCase() ?? "" : "";

  const blocksZoom =
    /user-scalable\s*=\s*(no|0)/u.test(content) ||
    (() => {
      const match = content.match(/maximum-scale\s*=\s*([0-9.]+)/u);
      return match ? Number.parseFloat(match[1] ?? "") < 2 : false;
    })();

  if (blocksZoom) {
    return [
      finding({
        id: "a11y.language.viewport_blocks_zoom",
        category: "language",
        status: "fail",
        severity: "high",
        title: "Pinch-to-zoom is disabled",
        summary: "The viewport meta tag prevents users from zooming the page.",
        evidence: { content },
        whyItMatters:
          "Many people enlarge pages to read them. Blocking zoom is a direct WCAG failure (1.4.4 Resize Text).",
        fix: "Remove user-scalable=no and maximum-scale from the viewport meta tag."
      })
    ];
  }

  return [];
}

function checkImages(root: HTMLElement): A11yFinding[] {
  const findings: A11yFinding[] = [];
  const missing: string[] = [];

  for (const img of elementsByTag(root, "img")) {
    if (isStaticallyHidden(img)) {
      continue;
    }
    // A present (even empty) alt is intentional; a missing alt is the failure.
    if (!hasAttr(img, "alt")) {
      missing.push(describe(img, attr(img, "src")));
    }
  }

  for (const input of elementsByTag(root, "input")) {
    if (attr(input, "type")?.toLowerCase() === "image" && !attr(input, "alt")?.trim()) {
      missing.push(describe(input, attr(input, "src")));
    }
  }

  if (missing.length > 0) {
    findings.push(
      finding({
        id: "a11y.images.alt_missing",
        category: "images",
        status: "fail",
        severity: "high",
        title: `${missing.length} image${missing.length === 1 ? "" : "s"} missing alt text`,
        summary:
          "Images without an alt attribute are announced by their file name or skipped entirely.",
        evidence: { count: missing.length, examples: missing.slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Screen-reader users rely on alt text to know what an image conveys. Decorative images should use an empty alt=\"\".",
        fix: 'Add alt text describing each image\'s purpose, or alt="" if it is purely decorative.'
      })
    );
  } else {
    findings.push(
      finding({
        id: "a11y.images.alt_ok",
        category: "images",
        status: "pass",
        severity: "info",
        title: "Images have alt text",
        summary: "Every visible image declares an alt attribute."
      })
    );
  }

  return findings;
}

function checkFormLabels(root: HTMLElement): A11yFinding[] {
  const labelTargets = new Set(
    elementsByTag(root, "label")
      .map((label) => attr(label, "for")?.trim())
      .filter((value): value is string => Boolean(value))
  );

  const unlabeled: string[] = [];

  for (const control of elementsByTag(root, "input", "select", "textarea")) {
    const type = attr(control, "type")?.toLowerCase();
    if (
      isStaticallyHidden(control) ||
      type === "hidden" ||
      type === "submit" ||
      type === "button" ||
      type === "reset" ||
      type === "image"
    ) {
      continue;
    }

    const id = attr(control, "id")?.trim();
    const labelled =
      Boolean(attr(control, "aria-label")?.trim()) ||
      Boolean(attr(control, "aria-labelledby")?.trim()) ||
      Boolean(attr(control, "title")?.trim()) ||
      (id ? labelTargets.has(id) : false) ||
      hasWrappingLabel(control);

    if (!labelled) {
      unlabeled.push(describe(control, attr(control, "name") ?? type));
    }
  }

  if (unlabeled.length > 0) {
    return [
      finding({
        id: "a11y.forms.label_missing",
        category: "forms",
        status: "fail",
        severity: "high",
        title: `${unlabeled.length} form field${unlabeled.length === 1 ? "" : "s"} without a label`,
        summary: "Form controls without an associated label are hard to identify by voice or screen reader.",
        evidence: { count: unlabeled.length, examples: unlabeled.slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Without a programmatic label, assistive tech cannot tell the user what a field is for, and voice control cannot target it.",
        fix: "Associate a <label for> with each field, or add aria-label / aria-labelledby."
      })
    ];
  }

  return [
    finding({
      id: "a11y.forms.label_ok",
      category: "forms",
      status: "pass",
      severity: "info",
      title: "Form fields are labeled",
      summary: "Every visible form control has an associated label."
    })
  ];
}

function checkHeadings(root: HTMLElement): A11yFinding[] {
  const headings = elementsByTag(root, "h1", "h2", "h3", "h4", "h5", "h6").filter(
    (h) => !isStaticallyHidden(h)
  );
  const levels = headings.map((h) => Number.parseInt(h.rawTagName.slice(1), 10));
  const findings: A11yFinding[] = [];

  const h1Count = levels.filter((level) => level === 1).length;
  if (h1Count === 0) {
    findings.push(
      finding({
        id: "a11y.structure.h1_missing",
        category: "structure",
        status: "warn",
        severity: "medium",
        title: "No top-level heading",
        summary: "The page has no <h1>.",
        whyItMatters:
          "Screen-reader users navigate by headings; a single clear <h1> tells them what the page is about.",
        fix: "Add one <h1> that names the page's main topic."
      })
    );
  }

  const skips: string[] = [];
  let previous = 0;
  for (const level of levels) {
    if (previous && level > previous + 1) {
      skips.push(`h${previous} → h${level}`);
    }
    previous = level;
  }

  if (skips.length > 0) {
    findings.push(
      finding({
        id: "a11y.structure.heading_skip",
        category: "structure",
        status: "warn",
        severity: "low",
        title: "Heading levels skip",
        summary: "Heading levels jump by more than one, which breaks the document outline.",
        evidence: { skips: skips.slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Skipped levels make the heading outline confusing to navigate with a screen reader.",
        fix: "Use heading levels in order (h1, then h2, then h3) without skipping."
      })
    );
  }

  if (findings.length === 0 && headings.length > 0) {
    findings.push(
      finding({
        id: "a11y.structure.headings_ok",
        category: "structure",
        status: "pass",
        severity: "info",
        title: "Heading structure looks sound",
        summary: "The page has a single top-level heading and a consistent outline."
      })
    );
  }

  return findings;
}

function checkLandmarks(root: HTMLElement): A11yFinding[] {
  const findings: A11yFinding[] = [];
  const hasMain =
    elementsByTag(root, "main").length > 0 ||
    elementsByTag(root, "div", "section").some((el) => attr(el, "role")?.toLowerCase() === "main");

  if (!hasMain) {
    findings.push(
      finding({
        id: "a11y.structure.main_missing",
        category: "structure",
        status: "warn",
        severity: "low",
        title: "No main landmark",
        summary: 'The page has no <main> element or role="main".',
        whyItMatters:
          "A main landmark lets screen-reader users skip straight to the primary content.",
        fix: "Wrap the primary content in a <main> element."
      })
    );
  }

  return findings;
}

function checkLinksAndButtons(root: HTMLElement): A11yFinding[] {
  const findings: A11yFinding[] = [];
  const nameless: string[] = [];
  const generic: string[] = [];

  for (const link of elementsByTag(root, "a")) {
    if (isStaticallyHidden(link) || !hasAttr(link, "href")) {
      continue;
    }
    const name = accessibleName(link, root).toLowerCase();
    if (!name) {
      nameless.push(describe(link, attr(link, "href")));
    } else if (GENERIC_LINK_TEXT.has(name)) {
      generic.push(name);
    }
  }

  for (const button of buttonLikeElements(root)) {
    if (isStaticallyHidden(button)) {
      continue;
    }
    const type = attr(button, "type")?.toLowerCase();
    const name =
      button.rawTagName.toLowerCase() === "input"
        ? attr(button, "value")?.trim() || accessibleName(button, root)
        : accessibleName(button, root);
    if (!name) {
      nameless.push(describe(button, type ?? button.rawTagName));
    }
  }

  if (nameless.length > 0) {
    findings.push(
      finding({
        id: "a11y.links.name_missing",
        category: "links",
        status: "fail",
        severity: "high",
        title: `${nameless.length} link${nameless.length === 1 ? "" : "s"} or button${
          nameless.length === 1 ? "" : "s"
        } with no text`,
        summary: "Links and buttons with no accessible name cannot be understood or activated by name.",
        evidence: { count: nameless.length, examples: nameless.slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Icon-only or empty controls are announced as just \"link\" or \"button\", giving the user no idea what they do.",
        fix: "Add visible text, or an aria-label, to every link and button (icon links especially)."
      })
    );
  }

  if (generic.length > 0) {
    findings.push(
      finding({
        id: "a11y.links.generic_text",
        category: "links",
        status: "warn",
        severity: "low",
        title: "Vague link text",
        summary: 'Some links use generic text like "click here" or "read more".',
        evidence: { examples: Array.from(new Set(generic)).slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Screen-reader users often pull up a list of links out of context; vague text tells them nothing.",
        fix: "Make link text describe its destination (e.g. \"View the lunch menu\")."
      })
    );
  }

  if (findings.length === 0) {
    findings.push(
      finding({
        id: "a11y.links.ok",
        category: "links",
        status: "pass",
        severity: "info",
        title: "Links and buttons have names",
        summary: "Every link and button exposes descriptive text."
      })
    );
  }

  return findings;
}

function checkTables(root: HTMLElement): A11yFinding[] {
  const offenders: string[] = [];

  for (const table of elementsByTag(root, "table")) {
    if (isStaticallyHidden(table) || attr(table, "role")?.toLowerCase() === "presentation") {
      continue;
    }
    const rows = table.querySelectorAll("tr").length;
    const headerCells = table.querySelectorAll("th").length;
    // Only flag tables that look like data tables (more than one row).
    if (rows > 1 && headerCells === 0) {
      offenders.push(describe(table, `${rows} rows`));
    }
  }

  if (offenders.length > 0) {
    return [
      finding({
        id: "a11y.tables.headers_missing",
        category: "tables",
        status: "warn",
        severity: "medium",
        title: `${offenders.length} data table${offenders.length === 1 ? "" : "s"} without headers`,
        summary: "Data tables without <th> header cells are hard to interpret with a screen reader.",
        evidence: { count: offenders.length, examples: offenders.slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Header cells let assistive tech announce which column and row a value belongs to.",
        fix: "Mark column and row headers with <th> and a scope attribute."
      })
    ];
  }

  return [];
}

function checkDuplicateIds(root: HTMLElement): A11yFinding[] {
  const seen = new Map<string, number>();
  for (const el of root.querySelectorAll("*")) {
    const id = attr(el, "id")?.trim();
    if (id) {
      seen.set(id, (seen.get(id) ?? 0) + 1);
    }
  }

  const duplicates = Array.from(seen.entries())
    .filter(([, count]) => count > 1)
    .map(([id, count]) => `#${id} (${count}×)`);

  if (duplicates.length > 0) {
    return [
      finding({
        id: "a11y.structure.duplicate_ids",
        category: "structure",
        status: "warn",
        severity: "low",
        title: "Duplicate id values",
        summary: "The same id is used more than once on the page.",
        evidence: { examples: duplicates.slice(0, MAX_EXAMPLES) },
        whyItMatters:
          "Labels and ARIA references point at a single id; duplicates make those associations ambiguous.",
        fix: "Make every id on the page unique."
      })
    ];
  }

  return [];
}

function buttonLikeElements(root: HTMLElement): HTMLElement[] {
  const buttons = elementsByTag(root, "button");
  const inputs = elementsByTag(root, "input").filter((input) => {
    const type = attr(input, "type")?.toLowerCase();
    return type === "button" || type === "submit" || type === "reset";
  });
  const roleButtons = root
    .querySelectorAll("*")
    .filter((el) => attr(el, "role")?.toLowerCase() === "button");
  return [...buttons, ...inputs, ...roleButtons];
}

function hasWrappingLabel(el: HTMLElement): boolean {
  let parent = el.parentNode as HTMLElement | null;
  while (parent) {
    if (parent.rawTagName?.toLowerCase() === "label") {
      return true;
    }
    parent = parent.parentNode as HTMLElement | null;
  }
  return false;
}

/** A short, privacy-safe description of an element for use in finding evidence. */
function describe(el: HTMLElement, hint?: string): string {
  const tag = el.rawTagName?.toLowerCase() ?? "node";
  const trimmedHint = hint?.trim();
  if (trimmedHint) {
    const short = trimmedHint.length > 60 ? `${trimmedHint.slice(0, 57)}…` : trimmedHint;
    return `<${tag}> ${short}`;
  }
  return `<${tag}>`;
}

function finding(input: A11yFinding): A11yFinding {
  return input;
}
