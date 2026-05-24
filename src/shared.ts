import { Buffer } from "node:buffer";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";

export type RuntimeRandomBytes = (size: number) => Uint8Array;

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortJson);
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, sortJson(item)])
  );
}

export function parseJson(raw: string, label = "JSON"): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    throw new Error(`${label} could not be parsed: ${safeErrorMessage(error)}`);
  }
}

export function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function recordOrUndefined(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function requiredString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

export function optionalString(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function requiredStringAlias(record: Record<string, unknown>, ...fields: string[]): string {
  for (const field of fields) {
    const value = optionalString(record, field);
    if (value !== undefined) return value;
  }
  throw new Error(`${fields.join(" or ")} is required`);
}

export function requiredBoolean(record: Record<string, unknown>, field: string): boolean {
  const value = record[field];
  if (typeof value !== "boolean") throw new Error(`${field} must be a boolean`);
  return value;
}

export function optionalBoolean(record: Record<string, unknown>, field: string): boolean | undefined {
  const value = record[field];
  return typeof value === "boolean" ? value : undefined;
}

export function requiredNumber(record: Record<string, unknown>, field: string): number {
  const value = record[field];
  if (!Number.isSafeInteger(value)) throw new Error(`${field} must be a safe integer`);
  return Number(value);
}

export function integerTimestamp(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
  return Number(value);
}

export function requireNonEmpty(value: string | undefined, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

export function normalizePolicyDigest(value: string): string {
  const digest = stripDigestPrefix(requireNonEmpty(value, "policyDigest").trim().toLowerCase());
  if (!/^[0-9a-f]{64}$/u.test(digest)) throw new Error("policyDigest must be a SHA-256 hex digest");
  return digest;
}

export function normalizeRequestedSecretIds(values: readonly string[]): string[] {
  const normalized = [...new Set(values.map((value) => requireNonEmpty(value, "requestedSecretIds[]").trim()))]
    .filter(Boolean)
    .sort((left, right) => left.localeCompare(right));
  if (normalized.length === 0) throw new Error("requestedSecretIds must not be empty");
  return normalized;
}

export function parseStringArrayOrCsv(value: unknown, label: string): string[] {
  if (Array.isArray(value)) return normalizeRequestedSecretIds(value.map((item) => String(item)));
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required`);
  const trimmed = value.trim();
  if (trimmed.startsWith("[")) {
    const parsed = parseJson(trimmed, label);
    if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) {
      throw new Error(`${label} JSON must be a string array`);
    }
    return normalizeRequestedSecretIds(parsed);
  }
  return normalizeRequestedSecretIds(trimmed.split(",").map((item) => item.trim()).filter(Boolean));
}

export function stringRecord(record: Record<string, unknown>, label: string): Record<string, string> {
  return Object.fromEntries(Object.entries(record).map(([key, value]) => {
    if (typeof value !== "string") throw new Error(`${label}.${key} must be a string`);
    return [key, value];
  }));
}

export function normalizeHex(value: string): string {
  const hex = stripHexPrefix(value).toLowerCase();
  if (!/^[0-9a-f]+$/u.test(hex)) throw new Error("expected a hex string");
  return `0x${hex}`;
}

export function normalizeHexNoPrefix(value: string): string {
  const hex = stripHexPrefix(value).toLowerCase();
  if (!/^[0-9a-f]+$/u.test(hex)) throw new Error("expected a hex string");
  return hex;
}

export function stripHexPrefix(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}

export function stripDigestPrefix(value: string): string {
  return value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
}

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256Digest(value: string | Uint8Array): string {
  return `sha256:${sha256Hex(value)}`;
}

export function digestMatches(value: string | Uint8Array, digest: string): boolean {
  const expected = stripDigestPrefix(digest.toLowerCase());
  return /^[0-9a-f]{64}$/u.test(expected) && sha256Hex(value) === expected;
}

export function randomHex(bytes = 16, randomBytes: RuntimeRandomBytes = nodeRandomBytes): string {
  return Buffer.from(randomBytes(bytes)).toString("hex");
}

export function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function assertSecureRuntimeUrl(url: URL, allowInsecureHttp: boolean | undefined, label: string): void {
  if (url.protocol === "https:") return;
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
  if (local || allowInsecureHttp === true) return;
  throw new Error(`${label} must use HTTPS outside explicit local/test opt-in`);
}

export function validEnvName(name: string): string {
  const value = requireNonEmpty(name, "env name");
  if (!/^[A-Z_][A-Z0-9_]*$/u.test(value)) throw new Error(`Invalid env name ${value}`);
  return value;
}
