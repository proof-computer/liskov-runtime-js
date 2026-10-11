import { Buffer } from "node:buffer";

import { defaultRuntimeFetch, type RuntimeIdentityProvider } from "./acurast.js";
import {
  asRecord,
  assertSecureRuntimeUrl,
  canonicalJson,
  integerTimestamp,
  randomHex,
  requiredBoolean,
  requiredNumber,
  requiredString,
  type RuntimeRandomBytes
} from "./shared.js";

export const LISKOV_RUNTIME_CONTEXT_SCHEMA = "proof.liskov.runtime-context.v1";
export const LISKOV_RUNTIME_CONTEXT_REQUEST_DOMAIN = "proof.liskov.runtime-context-request.v1";
export const LISKOV_RUNTIME_CONTEXT_RESPONSE_DOMAIN = "proof.liskov.runtime-context-response.v1";

/** A cached snapshot about this job. Names are labels; identities are keys. */
export interface LiskovRuntimeContext {
  readonly schema: typeof LISKOV_RUNTIME_CONTEXT_SCHEMA;
  readonly serverTimeMs: number;
  readonly application: {
    /** Stable application key (app-…). */
    readonly uid: string;
    /** Slug label; do not key durable logic on it. */
    readonly name: string;
    /** Display label; do not key durable logic on it. */
    readonly displayName: string | null;
  };
  readonly deployment: { readonly liskovDeploymentId: string; readonly acurastDeploymentId: string | null };
  readonly job: { readonly id: string; readonly scheduleEndsAtMs: number | null };
  readonly processor: { readonly id: string };
  readonly policy: { readonly digest: string; readonly versionId: string | null };
  readonly artifact: { readonly cid: string | null; readonly digest: string | null };
  readonly capabilities: {
    readonly runtimeEnv: boolean;
    readonly secrets: boolean;
    readonly logging: boolean;
    readonly ingress: boolean;
  };
  readonly network: {
    readonly observedWanIp: string | null;
    readonly observedAtMs: number | null;
    readonly geolocation: {
      readonly status: "ready" | "pending" | "stale" | "disabled" | "unavailable" | "not_observed";
      readonly countryCode: string | null;
      readonly countryName: string | null;
      readonly region: string | null;
      readonly city: string | null;
      readonly asOfMs: number | null;
      readonly accuracy: "ip-derived";
    };
  };
}

/** Validate known fields and copy them, tolerating additive future fields. */
export function parseLiskovRuntimeContext(value: unknown): LiskovRuntimeContext {
  const record = asRecord(value, "Liskov runtime context");
  if (record.schema !== LISKOV_RUNTIME_CONTEXT_SCHEMA) throw new Error("Unsupported runtime context schema");
  const application = asRecord(record.application, "context.application");
  const deployment = asRecord(record.deployment, "context.deployment");
  const job = asRecord(record.job, "context.job");
  const processor = asRecord(record.processor, "context.processor");
  const policy = asRecord(record.policy, "context.policy");
  const artifact = asRecord(record.artifact, "context.artifact");
  const capabilities = asRecord(record.capabilities, "context.capabilities");
  const network = asRecord(record.network, "context.network");
  const geo = asRecord(network.geolocation, "context.network.geolocation");
  const status = geo.status;
  if (status !== "ready" && status !== "pending" && status !== "stale" && status !== "disabled" &&
      status !== "unavailable" && status !== "not_observed") throw new Error("Invalid runtime context geolocation status");
  if (geo.accuracy !== "ip-derived") throw new Error("Invalid runtime context geolocation accuracy");
  return Object.freeze({
    schema: LISKOV_RUNTIME_CONTEXT_SCHEMA,
    serverTimeMs: requiredNumber(record, "serverTimeMs"),
    application: Object.freeze({
      uid: stringField(application, "uid"), name: stringField(application, "name"),
      displayName: nullableString(application, "displayName")
    }),
    deployment: Object.freeze({
      liskovDeploymentId: stringField(deployment, "liskovDeploymentId"),
      acurastDeploymentId: nullableString(deployment, "acurastDeploymentId")
    }),
    job: Object.freeze({ id: stringField(job, "id"), scheduleEndsAtMs: nullableNumber(job, "scheduleEndsAtMs") }),
    processor: Object.freeze({ id: stringField(processor, "id") }),
    policy: Object.freeze({ digest: stringField(policy, "digest"), versionId: nullableString(policy, "versionId") }),
    artifact: Object.freeze({ cid: nullableString(artifact, "cid"), digest: nullableString(artifact, "digest") }),
    capabilities: Object.freeze({
      runtimeEnv: requiredBoolean(capabilities, "runtimeEnv"), secrets: requiredBoolean(capabilities, "secrets"),
      logging: requiredBoolean(capabilities, "logging"), ingress: requiredBoolean(capabilities, "ingress")
    }),
    network: Object.freeze({
      observedWanIp: nullableString(network, "observedWanIp"), observedAtMs: nullableNumber(network, "observedAtMs"),
      geolocation: Object.freeze({
        status, countryCode: nullableString(geo, "countryCode"), countryName: nullableString(geo, "countryName"),
        region: nullableString(geo, "region"), city: nullableString(geo, "city"),
        asOfMs: nullableNumber(geo, "asOfMs"), accuracy: "ip-derived" as const
      })
    })
  });
}

function stringField(record: Record<string, unknown>, field: string): string {
  if (typeof record[field] !== "string") throw new Error(`context.${field} must be a string`);
  return record[field];
}

function nullableString(record: Record<string, unknown>, field: string): string | null {
  return record[field] === null ? null : stringField(record, field);
}

function nullableNumber(record: Record<string, unknown>, field: string): number | null {
  return record[field] === null ? null : requiredNumber(record, field);
}

export interface LiskovRuntimeContextRequest {
  domain: typeof LISKOV_RUNTIME_CONTEXT_REQUEST_DOMAIN;
  jobId: string;
  processorId: string;
  nonce: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export function buildRuntimeContextRequest(input: Omit<LiskovRuntimeContextRequest, "domain">): LiskovRuntimeContextRequest {
  const record = input as unknown as Record<string, unknown>;
  const processorId = requiredString(record, "processorId");
  const nonce = requiredString(record, "nonce");
  if (Buffer.byteLength(processorId) > 128 || Buffer.byteLength(nonce) > 128 || nonce.includes("\0")) {
    throw new Error("Invalid runtime context processor id or nonce");
  }
  const issuedAtMs = integerTimestamp(input.issuedAtMs, "issuedAtMs");
  const expiresAtMs = integerTimestamp(input.expiresAtMs, "expiresAtMs");
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > 60_000) throw new Error("Invalid runtime context expiry");
  return { domain: LISKOV_RUNTIME_CONTEXT_REQUEST_DOMAIN, jobId: requiredString(record, "jobId"),
    processorId, nonce, issuedAtMs, expiresAtMs };
}

export function runtimeContextRequestMessage(request: LiskovRuntimeContextRequest): Uint8Array {
  return Buffer.from(canonicalJson(buildRuntimeContextRequest(request)), "utf8");
}

export class LiskovRuntimeContextRefusedError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;

  constructor(input: { code: string; status: number }) {
    super(`Liskov runtime context refresh refused (${input.status}, ${input.code})`);
    this.name = "LiskovRuntimeContextRefusedError";
    this.code = input.code;
    this.status = input.status;
    // A replayed nonce (409) must never be retried. Every new call signs a fresh nonce.
    this.retryable = input.status === 429 || input.status === 503;
  }
}

/** One explicit signed request; no retry, backoff, logging, or polling. */
export async function refreshLiskovRuntimeContext(input: {
  coreUrl: string;
  identityProvider: RuntimeIdentityProvider;
  jobId: string;
  processorId: string;
  applicationUid?: string;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  ttlMs?: number;
  allowInsecureHttp?: boolean;
}): Promise<LiskovRuntimeContext> {
  const url = new URL("/api/jobs/runtime-context", input.coreUrl);
  assertSecureRuntimeUrl(url, input.allowInsecureHttp, "Liskov runtime context");
  const fetchImpl = input.fetchImpl ?? defaultRuntimeFetch();
  if (typeof fetchImpl !== "function") throw new Error("fetch is required for Liskov runtime context");
  const issuedAtMs = input.nowMs?.() ?? Date.now();
  const request = buildRuntimeContextRequest({
    jobId: input.jobId, processorId: input.processorId, nonce: randomHex(16, input.randomBytes),
    issuedAtMs, expiresAtMs: issuedAtMs + (input.ttlMs ?? 30_000)
  });
  const signature = await input.identityProvider.sign(runtimeContextRequestMessage(request));
  const response = await fetchImpl(url, {
    method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ ...request, signature })
  });
  let value: unknown;
  try { value = await response.json(); } catch {
    // Do not reflect a malformed response's contents into errors or diagnostics.
    if (response.ok) throw new Error("Invalid Liskov runtime context response JSON");
  }
  if (!response.ok) {
    const body = value !== null && typeof value === "object" ? value as Record<string, unknown> : undefined;
    const code = typeof body?.error === "string" && /^runtime_context_[a-z_]+$/u.test(body.error)
      ? body.error : "runtime_context_request_refused";
    throw new LiskovRuntimeContextRefusedError({ status: response.status, code });
  }
  const body = asRecord(value, "Liskov runtime context response");
  if (body.ok !== true || body.domain !== LISKOV_RUNTIME_CONTEXT_RESPONSE_DOMAIN ||
      body.requestNonce !== request.nonce || body.jobId !== request.jobId || body.processorId !== request.processorId) {
    throw new Error("Liskov runtime context response binding mismatch");
  }
  const context = parseLiskovRuntimeContext(body.context);
  if (typeof body.applicationUid !== "string" || body.applicationUid !== context.application.uid ||
      (input.applicationUid !== undefined && body.applicationUid !== input.applicationUid) ||
      context.job.id !== request.jobId || context.processor.id !== request.processorId) {
    throw new Error("Liskov runtime context response binding mismatch");
  }
  return context;
}
