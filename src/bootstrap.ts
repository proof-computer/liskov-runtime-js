import { Buffer } from "node:buffer";

import type { RuntimeIdentityProvider } from "./acurast.js";
import {
  getRuntimeEnvValue,
  optionalBooleanEnv,
  optionalIntegerEnv,
  type RuntimeEnvLookupOptions
} from "./env.js";
import type { LockboxRuntimeSecretConfig } from "./lockbox.js";
import type { SlipwayRuntimeEnvConfig } from "./runtime-env.js";
import {
  asRecord,
  assertSecureRuntimeUrl,
  canonicalJson,
  integerTimestamp,
  normalizeHexNoPrefix,
  normalizePolicyDigest,
  normalizeRequestedSecretIds,
  optionalBoolean,
  optionalString,
  parseJson,
  randomHex,
  recordOrUndefined,
  requiredString,
  type RuntimeRandomBytes
} from "./shared.js";

export const LISKOV_RUNTIME_BOOTSTRAP_REQUEST_DOMAIN = "proof.liskov.runtime-bootstrap-request.v1";
export const LISKOV_SECRET_BOOTSTRAP_REQUEST_DOMAIN = "proof.liskov.secret-bootstrap-request.v1";
export const LISKOV_RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN = "proof.liskov.runtime-bootstrap-response.v1";
export const LISKOV_SECRET_BOOTSTRAP_RESPONSE_DOMAIN = "proof.liskov.secret-bootstrap-response.v1";
export const DEFAULT_LISKOV_CORE_URL = "https://liskov.proof.computer";
export const DEFAULT_LISKOV_SECRETS_URL = "https://secrets.liskov.proof.computer";
export const DEFAULT_LISKOV_BOOTSTRAP_REQUEST_TTL_MS = 60_000;
export const DEFAULT_LISKOV_BOOTSTRAP_RETRY_INITIAL_DELAY_MS = 250;
export const DEFAULT_LISKOV_BOOTSTRAP_RETRY_INTERVAL_MS = 2_000;
export const DEFAULT_LISKOV_BOOTSTRAP_RETRY_MAX_ELAPSED_MS = 60_000;
export const DEFAULT_LISKOV_BOOTSTRAP_RETRY_MAX_ATTEMPTS = 30;

export type LiskovSignedBootstrapMode = "auto" | "signed" | "off";

export interface LiskovSignedBootstrapRetryOptions {
  initialDelayMs?: number;
  intervalMs?: number;
  maxElapsedMs?: number;
  maxAttempts?: number;
}

export interface LiskovSignedBootstrapConfig extends RuntimeEnvLookupOptions {
  coreUrl?: string;
  secretsUrl?: string;
  allowInsecureHttp?: boolean;
  requestTtlMs?: number;
  retry?: LiskovSignedBootstrapRetryOptions;
}

export interface LiskovSignedBootstrapOptions extends LiskovSignedBootstrapConfig {
  identityProvider: RuntimeIdentityProvider;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  setTimeoutImpl?: typeof setTimeout;
}

export interface LiskovRuntimeBootstrapUnsignedRequest {
  domain: typeof LISKOV_RUNTIME_BOOTSTRAP_REQUEST_DOMAIN;
  jobId: string;
  processorId: string;
  nonce: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface LiskovRuntimeBootstrapSignedRequest extends LiskovRuntimeBootstrapUnsignedRequest {
  signature: string;
}

export interface LiskovSecretBootstrapUnsignedRequest {
  domain: typeof LISKOV_SECRET_BOOTSTRAP_REQUEST_DOMAIN;
  jobId: string;
  processorId: string;
  responseEncryptionKey: string;
  nonce: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface LiskovSecretBootstrapSignedRequest extends LiskovSecretBootstrapUnsignedRequest {
  signature: string;
}

export interface LiskovRuntimeBootstrapResponse {
  ok: true;
  domain: typeof LISKOV_RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN;
  applicationId: string;
  policyDigest: string;
  deploymentId: string;
  jobId: string;
  processorId: string;
  slipwayUrl: string;
  runtimeEnv?: {
    enabled?: boolean;
    url?: string;
  };
  secrets?: {
    required?: boolean;
    url?: string;
  };
}

export interface LiskovSecretBootstrapResponse {
  ok: true;
  domain: typeof LISKOV_SECRET_BOOTSTRAP_RESPONSE_DOMAIN;
  lockboxUrl: string;
  applicationId: string;
  grantId: string;
  policyDigest: string;
  deploymentId: string;
  jobId: string;
  processorId: string;
  requestedSecretIds: string[];
  fileBaseDir?: string;
}

export interface LiskovRuntimeBootstrapLoadResult {
  request: LiskovRuntimeBootstrapSignedRequest;
  response: LiskovRuntimeBootstrapResponse;
  runtimeEnvConfig?: SlipwayRuntimeEnvConfig;
  secretsRequired: boolean;
  secretsUrl: string;
}

export interface LiskovSecretBootstrapLoadResult {
  request: LiskovSecretBootstrapSignedRequest;
  response: LiskovSecretBootstrapResponse;
  lockboxConfig: LockboxRuntimeSecretConfig;
}

export class LiskovSignedBootstrapHttpError extends Error {
  readonly status: number;
  readonly bodyText: string;
  readonly errorCode?: string;
  readonly retryable?: boolean;

  constructor(input: {
    label: string;
    status: number;
    bodyText: string;
    errorCode?: string;
    retryable?: boolean;
  }) {
    super(`${input.label} rejected request: ${input.status} ${input.bodyText.slice(0, 500)}`);
    this.name = "LiskovSignedBootstrapHttpError";
    this.status = input.status;
    this.bodyText = input.bodyText;
    this.errorCode = input.errorCode;
    this.retryable = input.retryable;
  }
}

export function liskovSignedBootstrapUrls(options: LiskovSignedBootstrapConfig = {}): {
  coreUrl: string;
  secretsUrl: string;
} {
  return {
    coreUrl: options.coreUrl ??
      getRuntimeEnvValue("PROOF_LISKOV_CORE_URL", options) ??
      getRuntimeEnvValue("PROOF_SLIPWAY_URL", options) ??
      DEFAULT_LISKOV_CORE_URL,
    secretsUrl: options.secretsUrl ??
      getRuntimeEnvValue("PROOF_LISKOV_SECRETS_URL", options) ??
      DEFAULT_LISKOV_SECRETS_URL
  };
}

export function liskovSignedBootstrapAllowInsecureHttp(options: LiskovSignedBootstrapConfig = {}): boolean | undefined {
  return options.allowInsecureHttp ?? optionalBooleanEnv("PROOF_LISKOV_BOOTSTRAP_ALLOW_INSECURE_HTTP", options);
}

export function liskovSignedBootstrapRequestTtlMs(options: LiskovSignedBootstrapConfig = {}): number {
  return options.requestTtlMs ??
    optionalIntegerEnv("PROOF_LISKOV_BOOTSTRAP_REQUEST_TTL_MS", options) ??
    DEFAULT_LISKOV_BOOTSTRAP_REQUEST_TTL_MS;
}

export function liskovSignedBootstrapRetryOptions(
  options: LiskovSignedBootstrapConfig = {}
): Required<LiskovSignedBootstrapRetryOptions> {
  return {
    initialDelayMs: nonNegativeInteger(options.retry?.initialDelayMs) ?? DEFAULT_LISKOV_BOOTSTRAP_RETRY_INITIAL_DELAY_MS,
    intervalMs: nonNegativeInteger(options.retry?.intervalMs) ?? DEFAULT_LISKOV_BOOTSTRAP_RETRY_INTERVAL_MS,
    maxElapsedMs: nonNegativeInteger(options.retry?.maxElapsedMs) ?? DEFAULT_LISKOV_BOOTSTRAP_RETRY_MAX_ELAPSED_MS,
    maxAttempts: positiveInteger(options.retry?.maxAttempts) ?? DEFAULT_LISKOV_BOOTSTRAP_RETRY_MAX_ATTEMPTS
  };
}

export async function buildLiskovRuntimeBootstrapRequest(input: {
  identityProvider: RuntimeIdentityProvider;
  nowMs?: number;
  randomBytes?: RuntimeRandomBytes;
  requestTtlMs?: number;
  nonce?: string;
}): Promise<LiskovRuntimeBootstrapSignedRequest> {
  const identity = await input.identityProvider.resolveIdentity({ requireEncryptionKey: false });
  const nowMs = input.nowMs ?? Date.now();
  const request = canonicalLiskovRuntimeBootstrapRequest({
    domain: LISKOV_RUNTIME_BOOTSTRAP_REQUEST_DOMAIN,
    jobId: identity.jobId,
    processorId: identity.processorId,
    nonce: input.nonce ?? randomHex(16, input.randomBytes),
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + (input.requestTtlMs ?? DEFAULT_LISKOV_BOOTSTRAP_REQUEST_TTL_MS)
  });
  return {
    ...request,
    signature: await input.identityProvider.sign(liskovRuntimeBootstrapRequestMessage(request))
  };
}

export async function buildLiskovSecretBootstrapRequest(input: {
  identityProvider: RuntimeIdentityProvider;
  nowMs?: number;
  randomBytes?: RuntimeRandomBytes;
  requestTtlMs?: number;
  nonce?: string;
}): Promise<LiskovSecretBootstrapSignedRequest> {
  const identity = await input.identityProvider.resolveIdentity({ requireEncryptionKey: true });
  const nowMs = input.nowMs ?? Date.now();
  const request = canonicalLiskovSecretBootstrapRequest({
    domain: LISKOV_SECRET_BOOTSTRAP_REQUEST_DOMAIN,
    jobId: identity.jobId,
    processorId: identity.processorId,
    responseEncryptionKey: normalizeHexNoPrefix(identity.responseEncryptionKey!),
    nonce: input.nonce ?? randomHex(16, input.randomBytes),
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + (input.requestTtlMs ?? DEFAULT_LISKOV_BOOTSTRAP_REQUEST_TTL_MS)
  });
  return {
    ...request,
    signature: await input.identityProvider.sign(liskovSecretBootstrapRequestMessage(request))
  };
}

export function canonicalLiskovRuntimeBootstrapRequest(
  request: LiskovRuntimeBootstrapUnsignedRequest | LiskovRuntimeBootstrapSignedRequest
): LiskovRuntimeBootstrapUnsignedRequest {
  const { signature: _signature, ...unsigned } = request as LiskovRuntimeBootstrapSignedRequest;
  return {
    domain: LISKOV_RUNTIME_BOOTSTRAP_REQUEST_DOMAIN,
    jobId: requiredString(unsigned as unknown as Record<string, unknown>, "jobId"),
    processorId: requiredString(unsigned as unknown as Record<string, unknown>, "processorId"),
    nonce: requiredString(unsigned as unknown as Record<string, unknown>, "nonce"),
    issuedAtMs: integerTimestamp(unsigned.issuedAtMs, "issuedAtMs"),
    expiresAtMs: integerTimestamp(unsigned.expiresAtMs, "expiresAtMs")
  };
}

export function canonicalLiskovSecretBootstrapRequest(
  request: LiskovSecretBootstrapUnsignedRequest | LiskovSecretBootstrapSignedRequest
): LiskovSecretBootstrapUnsignedRequest {
  const { signature: _signature, ...unsigned } = request as LiskovSecretBootstrapSignedRequest;
  return {
    domain: LISKOV_SECRET_BOOTSTRAP_REQUEST_DOMAIN,
    jobId: requiredString(unsigned as unknown as Record<string, unknown>, "jobId"),
    processorId: requiredString(unsigned as unknown as Record<string, unknown>, "processorId"),
    responseEncryptionKey: normalizeHexNoPrefix(requiredString(unsigned as unknown as Record<string, unknown>, "responseEncryptionKey")),
    nonce: requiredString(unsigned as unknown as Record<string, unknown>, "nonce"),
    issuedAtMs: integerTimestamp(unsigned.issuedAtMs, "issuedAtMs"),
    expiresAtMs: integerTimestamp(unsigned.expiresAtMs, "expiresAtMs")
  };
}

export function liskovRuntimeBootstrapRequestMessage(request: LiskovRuntimeBootstrapUnsignedRequest): Uint8Array {
  return Buffer.from(canonicalJson(canonicalLiskovRuntimeBootstrapRequest(request)), "utf8");
}

export function liskovSecretBootstrapRequestMessage(request: LiskovSecretBootstrapUnsignedRequest): Uint8Array {
  return Buffer.from(canonicalJson(canonicalLiskovSecretBootstrapRequest(request)), "utf8");
}

export async function loadLiskovRuntimeBootstrap(
  input: LiskovSignedBootstrapOptions
): Promise<LiskovRuntimeBootstrapLoadResult> {
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("fetch is required for Liskov runtime bootstrap");
  const urls = liskovSignedBootstrapUrls(input);
  const allowInsecureHttp = liskovSignedBootstrapAllowInsecureHttp(input);
  const requestTtlMs = liskovSignedBootstrapRequestTtlMs(input);
  const { request, response } = await retrySignedBootstrapRequest(input, async () => {
    const request = await buildLiskovRuntimeBootstrapRequest({
      identityProvider: input.identityProvider,
      nowMs: input.nowMs?.() ?? Date.now(),
      randomBytes: input.randomBytes,
      requestTtlMs
    });
    const response = parseLiskovRuntimeBootstrapResponse(await postSignedBootstrapRequest({
      fetchImpl,
      url: new URL("/api/jobs/runtime-bootstrap", urls.coreUrl),
      allowInsecureHttp,
      label: "Liskov runtime bootstrap",
      request
    }));
    return { request, response };
  });
  assertRuntimeBootstrapBinding({ request, response });
  const runtimeEnvConfig = response.runtimeEnv?.enabled === false
    ? undefined
    : {
        slipwayUrl: response.runtimeEnv?.url ?? response.slipwayUrl,
        applicationId: response.applicationId,
        policyDigest: response.policyDigest,
        deploymentId: response.deploymentId,
        allowInsecureHttp,
        requestTtlMs
      };
  return {
    request,
    response,
    runtimeEnvConfig,
    secretsRequired: response.secrets?.required === true,
    secretsUrl: response.secrets?.url ?? urls.secretsUrl
  };
}

export async function loadLiskovSecretBootstrap(
  input: LiskovSignedBootstrapOptions
): Promise<LiskovSecretBootstrapLoadResult> {
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("fetch is required for Liskov secret bootstrap");
  const urls = liskovSignedBootstrapUrls(input);
  const allowInsecureHttp = liskovSignedBootstrapAllowInsecureHttp(input);
  const requestTtlMs = liskovSignedBootstrapRequestTtlMs(input);
  const { request, response } = await retrySignedBootstrapRequest(input, async () => {
    const request = await buildLiskovSecretBootstrapRequest({
      identityProvider: input.identityProvider,
      nowMs: input.nowMs?.() ?? Date.now(),
      randomBytes: input.randomBytes,
      requestTtlMs
    });
    const response = parseLiskovSecretBootstrapResponse(await postSignedBootstrapRequest({
      fetchImpl,
      url: new URL("/api/jobs/secret-bootstrap", urls.secretsUrl),
      allowInsecureHttp,
      label: "Liskov secret bootstrap",
      request
    }));
    return { request, response };
  });
  assertSecretBootstrapBinding({ request, response });
  return {
    request,
    response,
    lockboxConfig: {
      lockboxUrl: response.lockboxUrl,
      applicationId: response.applicationId,
      grantId: response.grantId,
      policyDigest: response.policyDigest,
      deploymentId: response.deploymentId,
      requestedSecretIds: response.requestedSecretIds,
      allowInsecureHttp,
      requestTtlMs,
      fileBaseDir: response.fileBaseDir
    }
  };
}

export function parseLiskovRuntimeBootstrapResponse(value: unknown): LiskovRuntimeBootstrapResponse {
  const record = asRecord(value, "Liskov runtime bootstrap response");
  if (record.ok !== true || record.domain !== LISKOV_RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN) {
    throw new Error("Liskov runtime bootstrap response has an unsupported domain");
  }
  const runtimeEnv = recordOrUndefined(record.runtimeEnv);
  const secrets = recordOrUndefined(record.secrets);
  return {
    ok: true,
    domain: LISKOV_RUNTIME_BOOTSTRAP_RESPONSE_DOMAIN,
    applicationId: requiredString(record, "applicationId"),
    policyDigest: normalizePolicyDigest(requiredString(record, "policyDigest")),
    deploymentId: requiredString(record, "deploymentId"),
    jobId: requiredString(record, "jobId"),
    processorId: requiredString(record, "processorId"),
    slipwayUrl: requiredString(record, "slipwayUrl"),
    runtimeEnv: runtimeEnv === undefined
      ? undefined
      : {
          enabled: optionalBoolean(runtimeEnv, "enabled"),
          url: optionalString(runtimeEnv, "url")
        },
    secrets: secrets === undefined
      ? undefined
      : {
          required: optionalBoolean(secrets, "required"),
          url: optionalString(secrets, "url")
        }
  };
}

export function parseLiskovSecretBootstrapResponse(value: unknown): LiskovSecretBootstrapResponse {
  const record = asRecord(value, "Liskov secret bootstrap response");
  if (record.ok !== true || record.domain !== LISKOV_SECRET_BOOTSTRAP_RESPONSE_DOMAIN) {
    throw new Error("Liskov secret bootstrap response has an unsupported domain");
  }
  return {
    ok: true,
    domain: LISKOV_SECRET_BOOTSTRAP_RESPONSE_DOMAIN,
    lockboxUrl: requiredString(record, "lockboxUrl"),
    applicationId: requiredString(record, "applicationId"),
    grantId: requiredString(record, "grantId"),
    policyDigest: normalizePolicyDigest(requiredString(record, "policyDigest")),
    deploymentId: requiredString(record, "deploymentId"),
    jobId: requiredString(record, "jobId"),
    processorId: requiredString(record, "processorId"),
    requestedSecretIds: normalizeRequestedSecretIds(requiredStringArray(record, "requestedSecretIds")),
    fileBaseDir: optionalString(record, "fileBaseDir")
  };
}

export function isLiskovSignedBootstrapUnavailableError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /Acurast (job id|processor id|Ed25519 signer|response encryption key) is required/u.test(message);
}

async function postSignedBootstrapRequest(input: {
  fetchImpl: typeof fetch;
  url: URL;
  allowInsecureHttp?: boolean;
  label: string;
  request: LiskovRuntimeBootstrapSignedRequest | LiskovSecretBootstrapSignedRequest;
}): Promise<unknown> {
  assertSecureRuntimeUrl(input.url, input.allowInsecureHttp, input.label);
  const response = await input.fetchImpl(input.url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(input.request)
  });
  const text = await response.text();
  if (!response.ok) {
    const body = parseBootstrapErrorBody(text);
    throw new LiskovSignedBootstrapHttpError({
      label: input.label,
      status: response.status,
      bodyText: text,
      errorCode: body.errorCode,
      retryable: body.retryable
    });
  }
  return parseJson(text, `${input.label} response`);
}

async function retrySignedBootstrapRequest<T>(
  input: LiskovSignedBootstrapOptions,
  attempt: () => Promise<T>
): Promise<T> {
  const retry = liskovSignedBootstrapRetryOptions(input);
  const setTimeoutImpl = input.setTimeoutImpl ?? setTimeout;
  const startedAtMs = input.nowMs?.() ?? Date.now();
  let attemptNumber = 0;
  let nextDelayMs = retry.initialDelayMs;

  for (;;) {
    attemptNumber += 1;
    try {
      return await attempt();
    } catch (error) {
      if (!liskovSignedBootstrapErrorIsRetryable(error) || attemptNumber >= retry.maxAttempts) {
        throw error;
      }
      const nowMs = input.nowMs?.() ?? Date.now();
      if (nowMs - startedAtMs + nextDelayMs > retry.maxElapsedMs) throw error;
      await sleep(nextDelayMs, setTimeoutImpl);
      nextDelayMs = retry.intervalMs;
    }
  }
}

function liskovSignedBootstrapErrorIsRetryable(error: unknown): boolean {
  if (!(error instanceof LiskovSignedBootstrapHttpError)) return false;
  if (error.retryable === true) return true;
  if (
    error.errorCode === "runtime_bootstrap_bad_signature" ||
    error.errorCode === "bad_signature" ||
    error.errorCode === "runtime_bootstrap_job_ambiguous" ||
    error.errorCode === "job_grant_ambiguous"
  ) {
    return false;
  }
  // A freshly claimed job (or grant) that core has not finished indexing yet
  // reports a transient `*_not_found`. Retry it even when the underlying
  // transport could not preserve the HTTP status (e.g. an Acurast httpPOST
  // failure surfaced without a recoverable status code).
  if (error.errorCode !== undefined && error.errorCode.endsWith("_not_found")) return true;
  return [404, 409, 425, 429, 500, 502, 503, 504].includes(error.status);
}

function parseBootstrapErrorBody(text: string): { errorCode?: string; retryable?: boolean } {
  try {
    const record = asRecord(JSON.parse(text) as unknown, "Liskov bootstrap error");
    return {
      errorCode: optionalString(record, "error"),
      retryable: optionalBoolean(record, "retryable")
    };
  } catch {
    return {};
  }
}

async function sleep(delayMs: number, setTimeoutImpl: typeof setTimeout): Promise<void> {
  if (delayMs <= 0) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeoutImpl(resolve, delayMs);
    timer.unref?.();
  });
}

function nonNegativeInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.floor(value)) : undefined;
}

function positiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(1, Math.floor(value)) : undefined;
}

function assertRuntimeBootstrapBinding(input: {
  request: LiskovRuntimeBootstrapUnsignedRequest;
  response: LiskovRuntimeBootstrapResponse;
}): void {
  if (input.response.jobId !== input.request.jobId) {
    throw new Error("Liskov runtime bootstrap response jobId did not match the signed request");
  }
  if (input.response.processorId !== input.request.processorId) {
    throw new Error("Liskov runtime bootstrap response processorId did not match the signed request");
  }
}

function assertSecretBootstrapBinding(input: {
  request: LiskovSecretBootstrapUnsignedRequest;
  response: LiskovSecretBootstrapResponse;
}): void {
  if (input.response.jobId !== input.request.jobId) {
    throw new Error("Liskov secret bootstrap response jobId did not match the signed request");
  }
  if (input.response.processorId !== input.request.processorId) {
    throw new Error("Liskov secret bootstrap response processorId did not match the signed request");
  }
}

function requiredStringArray(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && item.length > 0)) {
    throw new Error(`${field} must be a string array`);
  }
  return value;
}
