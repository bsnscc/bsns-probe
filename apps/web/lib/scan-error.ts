export interface ScanApiErrorBody {
  ok: false;
  error?: {
    code: string;
    message: string;
  };
}

export interface ScanUiError {
  title: string;
  message: string;
  detail?: string;
}

interface ScanErrorContext {
  body: ScanApiErrorBody;
  headers: Headers;
  status: number;
}

export function buildScanUiError({ body, headers, status }: ScanErrorContext): ScanUiError {
  const code = body.error?.code ?? "SCAN_FAILED";
  const message = body.error?.message ?? fallbackMessageForStatus(status);

  if (code === "RATE_LIMITED") {
    return {
      title: "Too many checks",
      message,
      detail: formatRetryAfter(headers.get("retry-after")) ?? "Try again in about a minute."
    };
  }

  if (code === "SCANNER_BUSY") {
    return {
      title: "Scanner is busy",
      message,
      detail: formatRetryAfter(headers.get("retry-after")) ?? "Try again in a few seconds."
    };
  }

  if (code === "SCAN_TIMEOUT") {
    return {
      title: "The scan timed out",
      message,
      detail: "The public web check has a 15 second limit. Try again shortly if the domain is slow."
    };
  }

  if (code === "INVALID_REQUEST" || code === "INVALID_DOMAIN") {
    return {
      title: "Check the domain",
      message
    };
  }

  if (code === "BLOCKED_HOSTNAME" || code === "BLOCKED_IP" || code === "BLOCKED_DNS_ADDRESS") {
    return {
      title: "Use a public domain",
      message,
      detail:
        "For safety, the public scanner does not connect to local, private, reserved, or IP-address targets."
    };
  }

  return {
    title: status >= 500 ? "Scan failed" : "Unable to scan that domain",
    message
  };
}

export function networkScanUiError(): ScanUiError {
  return {
    title: "Could not reach the scanner",
    message: "Check your connection and try again."
  };
}

export function unreadableScanResponseError(status: number): ScanApiErrorBody {
  if (status === 429) {
    return {
      ok: false,
      error: {
        code: "RATE_LIMITED",
        message: fallbackMessageForStatus(status)
      }
    };
  }

  return {
    ok: false,
    error: {
      code: "INVALID_RESPONSE",
      message: `The scanner returned HTTP ${status}. Try again in a moment.`
    }
  };
}

function formatRetryAfter(value: string | null): string | undefined {
  const retryAfterSeconds = parseRetryAfterSeconds(value);

  if (retryAfterSeconds === undefined) {
    return undefined;
  }

  return `Try again in about ${formatDuration(retryAfterSeconds)}.`;
}

function parseRetryAfterSeconds(value: string | null): number | undefined {
  if (!value) {
    return undefined;
  }

  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds > 0) {
    return Math.ceil(seconds);
  }

  const dateMs = Date.parse(value);
  if (Number.isNaN(dateMs)) {
    return undefined;
  }

  return Math.max(1, Math.ceil((dateMs - Date.now()) / 1000));
}

function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${seconds} ${seconds === 1 ? "second" : "seconds"}`;
  }

  const minutes = Math.ceil(seconds / 60);
  return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

function fallbackMessageForStatus(status: number): string {
  if (status === 504) {
    return "The scan timed out. Try again shortly.";
  }

  if (status === 429) {
    return "Too many scan requests. Try again shortly.";
  }

  return "The scan request failed. Try again in a moment.";
}
