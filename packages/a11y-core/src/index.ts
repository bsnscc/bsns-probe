export { scanAccessibility } from "./scan.js";
export { runRules } from "./rules.js";
export { discoverPages } from "./crawl.js";
export { createGuardedPageFetcher, PageFetchError } from "./fetch-page.js";
export {
  buildHeadline,
  buildReportScore,
  buildTopFixes,
  countFindings,
  scorePage
} from "./score.js";
export { renderA11yJson, renderA11yMarkdown, renderA11yText } from "./report.js";
export { A11Y_DISCLAIMER } from "./types.js";
export type {
  A11yCategory,
  A11yFinding,
  A11yPageResult,
  A11yReport,
  A11yScanOptions,
  A11yScoreCategory,
  FetchedPage,
  Finding,
  FindingStatus,
  PageFetcher,
  ReportGrade
} from "./types.js";
