/** ADR-0314 WebView observation. liskov-rs owns these rules. */

const WEBVIEW_STATUSES = ["observed", "unavailable", "failed"] as const;
const WEBVIEW_ERROR_CODES = [
  "webview_api_absent",
  "tab_open_failed",
  "debug_url_unavailable",
  "devtools_unreachable",
  "version_unparsed",
  "timed_out"
] as const;
const WEBVIEW_FIELDS = new Set(["version", "status", "chromeVersion", "errorCode", "durationMs"]);
const FAILURE_CODES = new Set<string>(WEBVIEW_ERROR_CODES.filter((code) => code !== "webview_api_absent"));
const CHROME_PART_MAX_DIGITS = [4, 6, 6, 6] as const;
const MAX_DURATION_MS = 20_000;

export type WebViewStatus = (typeof WEBVIEW_STATUSES)[number];
export type WebViewErrorCode = (typeof WEBVIEW_ERROR_CODES)[number];

export interface WebViewRuntimeV1 {
  version: 1;
  status: WebViewStatus;
  chromeVersion?: string;
  errorCode?: WebViewErrorCode;
  durationMs: number;
}

export function normalizeWebViewRuntime(value: unknown): WebViewRuntimeV1 {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    refuse("must be an object");
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!WEBVIEW_FIELDS.has(key)) refuse("unknown field");
  }
  if (record.version !== 1) refuse("version must be 1");
  const durationMs = boundedDuration(record.durationMs);
  if (!isStatus(record.status)) refuse("status is unsupported");
  const chromeVersion = optionalField(record, "chromeVersion");
  const errorCode = optionalField(record, "errorCode");
  if (record.status === "observed") return observed(chromeVersion, errorCode, durationMs);
  if (record.status === "unavailable") return unavailable(chromeVersion, errorCode, durationMs);
  return failed(chromeVersion, errorCode, durationMs);
}

function observed(chromeVersion: unknown, errorCode: unknown, durationMs: number): WebViewRuntimeV1 {
  if (errorCode !== undefined || typeof chromeVersion !== "string" || !validChromeVersion(chromeVersion)) {
    refuse("observed requires a valid chromeVersion and no errorCode");
  }
  return { version: 1, status: "observed", chromeVersion, durationMs };
}

function unavailable(chromeVersion: unknown, errorCode: unknown, durationMs: number): WebViewRuntimeV1 {
  if (chromeVersion !== undefined || errorCode !== "webview_api_absent") {
    refuse("unavailable requires webview_api_absent and no chromeVersion");
  }
  return { version: 1, status: "unavailable", errorCode, durationMs };
}

function failed(chromeVersion: unknown, errorCode: unknown, durationMs: number): WebViewRuntimeV1 {
  if (chromeVersion !== undefined || typeof errorCode !== "string" || !FAILURE_CODES.has(errorCode)) {
    refuse("failed requires a failure errorCode and no chromeVersion");
  }
  return { version: 1, status: "failed", errorCode: errorCode as WebViewErrorCode, durationMs };
}

function optionalField(record: Record<string, unknown>, key: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(record, key)) return undefined;
  const value = record[key];
  // serde's present() rejects null. Omitting the key is the only absence.
  if (value === null) refuse(`${key} must be omitted or a value`);
  return value;
}

function boundedDuration(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > MAX_DURATION_MS) {
    refuse("durationMs must be at most 20000");
  }
  return value;
}

function validChromeVersion(version: string): boolean {
  const parts = version.split(".");
  if (parts.length !== CHROME_PART_MAX_DIGITS.length) return false;
  return parts.every((part, index) => {
    const maxDigits = CHROME_PART_MAX_DIGITS[index]!;
    return part.length >= 1
      && part.length <= maxDigits
      && (part.length === 1 || !part.startsWith("0"))
      && /^[0-9]+$/u.test(part);
  });
}

function isStatus(value: unknown): value is WebViewStatus {
  return typeof value === "string" && (WEBVIEW_STATUSES as readonly string[]).includes(value);
}

function refuse(message: string): never {
  throw new Error(`webview: ${message}`);
}
