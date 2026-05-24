import { Buffer } from "node:buffer";

import type { RuntimeIdentityProvider } from "./acurast.js";
import {
  getRuntimeEnvValue,
  optionalBooleanEnv,
  optionalIntegerEnv,
  type RuntimeEnvLookupOptions
} from "./env.js";
import {
  asRecord,
  assertSecureRuntimeUrl,
  canonicalJson,
  integerTimestamp,
  normalizePolicyDigest,
  randomHex,
  recordOrUndefined,
  requiredString,
  requiredStringAlias,
  safeErrorMessage,
  stringRecord,
  validEnvName,
  type RuntimeRandomBytes
} from "./shared.js";

export const SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN = "proof.slipway.runtime-env-request.v1";
export const SLIPWAY_RUNTIME_ENV_RESPONSE_DOMAIN = "proof.slipway.runtime-env-response.v1";

export interface SlipwayRuntimeEnvConfig {
  slipwayUrl: string;
  applicationId: string;
  policyDigest: string;
  deploymentId: string;
  diagnosticsToken?: string;
  allowInsecureHttp?: boolean;
  requestTtlMs?: number;
  nonce?: string;
}

export interface SlipwayRuntimeEnvUnsignedRequest {
  domain: typeof SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN;
  applicationId: string;
  policyDigest: string;
  jobId: string;
  deploymentId: string;
  processorId: string;
  nonce: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface SlipwayRuntimeEnvSignedRequest extends SlipwayRuntimeEnvUnsignedRequest {
  signature: string;
}

export interface SlipwayRuntimeEnvResponse {
  ok: true;
  domain: typeof SLIPWAY_RUNTIME_ENV_RESPONSE_DOMAIN;
  requestId: string;
  applicationId: string;
  policyDigest: string;
  jobId: string;
  deploymentId: string;
  processorId: string;
  revision: string;
  issuedAtMs: number;
  expiresAtMs: number;
  refreshAfterMs: number;
  values: Record<string, string>;
}

export interface SlipwayRuntimeEnvLoadOptions {
  identityProvider: RuntimeIdentityProvider;
  config: SlipwayRuntimeEnvConfig;
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  diagnostics?: (event: SlipwayRuntimeEnvDiagnosticEvent) => void | Promise<void>;
}

export interface SlipwayRuntimeEnvDiagnosticEvent {
  phase:
    | "identity_resolved"
    | "request_signed"
    | "runtime_env_request"
    | "runtime_env_response"
    | "env_installed"
    | "refresh_failed";
  ok: boolean;
  applicationId?: string;
  revision?: string;
  valueCount?: number;
  status?: number;
  errorCode?: string;
}

export interface SlipwayRuntimeEnvLoadResult {
  request: SlipwayRuntimeEnvSignedRequest;
  response: SlipwayRuntimeEnvResponse;
  installed: string[];
}

export interface SlipwayRuntimeEnvRefreshHandle {
  stop(): void;
  refreshNow(): Promise<SlipwayRuntimeEnvLoadResult>;
}

export function readSlipwayRuntimeEnvConfig(options: RuntimeEnvLookupOptions = {}): SlipwayRuntimeEnvConfig | undefined {
  const raw = getRuntimeEnvValue("PROOF_SLIPWAY_BOOTSTRAP", options);
  if (!raw) return undefined;
  return slipwayRuntimeEnvConfigFromBootstrap(raw, options);
}

export function slipwayRuntimeEnvConfigFromBootstrap(
  rawBootstrap: string,
  options: RuntimeEnvLookupOptions = {}
): SlipwayRuntimeEnvConfig {
  const record = asRecord(JSON.parse(rawBootstrap) as unknown, "PROOF_SLIPWAY_BOOTSTRAP");
  return {
    slipwayUrl: requiredStringAlias(record, "u", "url", "slipwayUrl"),
    applicationId: requiredStringAlias(record, "a", "applicationId"),
    policyDigest: normalizePolicyDigest(requiredStringAlias(record, "p", "policyDigest")),
    deploymentId: requiredStringAlias(record, "d", "deploymentId"),
    diagnosticsToken: diagnosticsTokenFromBootstrap(record),
    allowInsecureHttp: Boolean(optionalBooleanEnv("PROOF_SLIPWAY_RUNTIME_ENV_ALLOW_INSECURE_HTTP", options) ?? record.allowInsecureHttp),
    requestTtlMs: optionalIntegerEnv("PROOF_SLIPWAY_RUNTIME_ENV_REQUEST_TTL_MS", options),
    nonce: getRuntimeEnvValue("PROOF_SLIPWAY_RUNTIME_ENV_NONCE", options)
  };
}

export async function buildSlipwayRuntimeEnvRequest(input: {
  identityProvider: RuntimeIdentityProvider;
  config: SlipwayRuntimeEnvConfig;
  nowMs?: number;
  randomBytes?: RuntimeRandomBytes;
  nonce?: string;
}): Promise<SlipwayRuntimeEnvSignedRequest> {
  const identity = await input.identityProvider.resolveIdentity({ requireEncryptionKey: false });
  const nowMs = input.nowMs ?? Date.now();
  const request = canonicalSlipwayRuntimeEnvRequest({
    domain: SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN,
    applicationId: input.config.applicationId,
    policyDigest: input.config.policyDigest,
    jobId: identity.jobId,
    deploymentId: input.config.deploymentId,
    processorId: identity.processorId,
    nonce: input.nonce ?? input.config.nonce ?? randomHex(16, input.randomBytes),
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + (input.config.requestTtlMs ?? 60_000)
  });
  return {
    ...request,
    signature: await input.identityProvider.sign(slipwayRuntimeEnvRequestMessage(request))
  };
}

export function canonicalSlipwayRuntimeEnvRequest(
  request: SlipwayRuntimeEnvUnsignedRequest | SlipwayRuntimeEnvSignedRequest
): SlipwayRuntimeEnvUnsignedRequest {
  const { signature: _signature, ...unsigned } = request as SlipwayRuntimeEnvSignedRequest;
  return {
    domain: SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN,
    applicationId: requiredString(unsigned as unknown as Record<string, unknown>, "applicationId"),
    policyDigest: normalizePolicyDigest(unsigned.policyDigest),
    jobId: requiredString(unsigned as unknown as Record<string, unknown>, "jobId"),
    deploymentId: requiredString(unsigned as unknown as Record<string, unknown>, "deploymentId"),
    processorId: requiredString(unsigned as unknown as Record<string, unknown>, "processorId"),
    nonce: requiredString(unsigned as unknown as Record<string, unknown>, "nonce"),
    issuedAtMs: integerTimestamp(unsigned.issuedAtMs, "issuedAtMs"),
    expiresAtMs: integerTimestamp(unsigned.expiresAtMs, "expiresAtMs")
  };
}

export function slipwayRuntimeEnvRequestMessage(request: SlipwayRuntimeEnvUnsignedRequest): Uint8Array {
  return Buffer.from(canonicalJson(canonicalSlipwayRuntimeEnvRequest(request)), "utf8");
}

export async function loadSlipwayRuntimeEnv(input: SlipwayRuntimeEnvLoadOptions): Promise<SlipwayRuntimeEnvLoadResult> {
  try {
    const fetchImpl = input.fetchImpl ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") throw new Error("fetch is required for Slipway runtime env bootstrap");
    const identity = await input.identityProvider.resolveIdentity({ requireEncryptionKey: false });
    await emit(input.diagnostics, { phase: "identity_resolved", ok: true, applicationId: input.config.applicationId });
    const request = await buildSlipwayRuntimeEnvRequest({
      identityProvider: input.identityProvider,
      config: input.config,
      nowMs: input.nowMs?.() ?? Date.now(),
      randomBytes: input.randomBytes
    });
    await emit(input.diagnostics, { phase: "request_signed", ok: true, applicationId: request.applicationId });
    const response = await postSlipwayRuntimeEnvRequest({ ...input, fetchImpl, request });
    assertSlipwayRuntimeEnvBinding({ request, response });
    const installed = installSlipwayRuntimeEnv({ response, env: input.env ?? process.env });
    await emit(input.diagnostics, {
      phase: "env_installed",
      ok: true,
      applicationId: response.applicationId,
      revision: response.revision,
      valueCount: installed.length
    });
    void identity;
    return { request, response, installed };
  } catch (error) {
    await emit(input.diagnostics, {
      phase: "runtime_env_request",
      ok: false,
      applicationId: input.config.applicationId,
      errorCode: safeErrorMessage(error)
    });
    throw error;
  }
}

export function installSlipwayRuntimeEnv(input: {
  response: SlipwayRuntimeEnvResponse;
  env?: Record<string, string | undefined>;
}): string[] {
  if (input.response.domain !== SLIPWAY_RUNTIME_ENV_RESPONSE_DOMAIN || input.response.ok !== true) {
    throw new Error("Slipway runtime env response did not include ok=true");
  }
  const env = input.env ?? process.env;
  const installed: string[] = [];
  for (const [name, value] of Object.entries(input.response.values)) {
    env[validEnvName(name)] = value;
    installed.push(name);
  }
  return installed.sort((left, right) => left.localeCompare(right));
}

export function startSlipwayRuntimeEnvRefresh(input: SlipwayRuntimeEnvLoadOptions & {
  setTimeoutImpl?: typeof setTimeout;
  clearTimeoutImpl?: typeof clearTimeout;
}): SlipwayRuntimeEnvRefreshHandle {
  const setTimeoutImpl = input.setTimeoutImpl ?? setTimeout;
  const clearTimeoutImpl = input.clearTimeoutImpl ?? clearTimeout;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inflight: Promise<SlipwayRuntimeEnvLoadResult> | undefined;
  const refreshNow = async () => {
    inflight ??= loadSlipwayRuntimeEnv(input).finally(() => {
      inflight = undefined;
    });
    return inflight;
  };
  const schedule = () => {
    if (stopped) return;
    if (timer) clearTimeoutImpl(timer);
    timer = setTimeoutImpl(() => {
      void refreshNow()
        .catch((error) => emit(input.diagnostics, {
          phase: "refresh_failed",
          ok: false,
          applicationId: input.config.applicationId,
          errorCode: safeErrorMessage(error)
        }))
        .finally(schedule);
    }, 30_000);
    timer.unref?.();
  };
  schedule();
  return {
    stop() {
      stopped = true;
      if (timer) clearTimeoutImpl(timer);
    },
    refreshNow
  };
}

async function postSlipwayRuntimeEnvRequest(input: SlipwayRuntimeEnvLoadOptions & {
  fetchImpl: typeof fetch;
  request: SlipwayRuntimeEnvSignedRequest;
}): Promise<SlipwayRuntimeEnvResponse> {
  const url = new URL("/api/jobs/runtime-env", input.config.slipwayUrl);
  assertSecureRuntimeUrl(url, input.config.allowInsecureHttp, "Slipway runtime env");
  await emit(input.diagnostics, { phase: "runtime_env_request", ok: true, applicationId: input.request.applicationId });
  const response = await input.fetchImpl(url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(input.request)
  });
  const text = await response.text();
  const body = JSON.parse(text) as unknown;
  if (!response.ok) {
    throw new Error(`Slipway runtime env rejected request: ${response.status} ${text.slice(0, 500)}`);
  }
  const parsed = parseSlipwayRuntimeEnvResponse(body);
  await emit(input.diagnostics, {
    phase: "runtime_env_response",
    ok: true,
    status: response.status,
    applicationId: parsed.applicationId,
    revision: parsed.revision,
    valueCount: Object.keys(parsed.values).length
  });
  return parsed;
}

export function parseSlipwayRuntimeEnvResponse(value: unknown): SlipwayRuntimeEnvResponse {
  const record = asRecord(value, "Slipway runtime env response");
  if (record.ok !== true || record.domain !== SLIPWAY_RUNTIME_ENV_RESPONSE_DOMAIN) {
    throw new Error("Slipway runtime env response has an unsupported domain");
  }
  return {
    ok: true,
    domain: SLIPWAY_RUNTIME_ENV_RESPONSE_DOMAIN,
    requestId: requiredString(record, "requestId"),
    applicationId: requiredString(record, "applicationId"),
    policyDigest: normalizePolicyDigest(requiredString(record, "policyDigest")),
    jobId: requiredString(record, "jobId"),
    deploymentId: requiredString(record, "deploymentId"),
    processorId: requiredString(record, "processorId"),
    revision: requiredString(record, "revision"),
    issuedAtMs: integerTimestamp(record.issuedAtMs, "issuedAtMs"),
    expiresAtMs: integerTimestamp(record.expiresAtMs, "expiresAtMs"),
    refreshAfterMs: integerTimestamp(record.refreshAfterMs, "refreshAfterMs"),
    values: stringRecord(asRecord(record.values, "values"), "values")
  };
}

function assertSlipwayRuntimeEnvBinding(input: {
  request: SlipwayRuntimeEnvUnsignedRequest;
  response: SlipwayRuntimeEnvResponse;
}): void {
  const expected: Array<[unknown, unknown, string]> = [
    [input.response.applicationId, input.request.applicationId, "applicationId"],
    [input.response.policyDigest, input.request.policyDigest, "policyDigest"],
    [input.response.jobId, input.request.jobId, "jobId"],
    [input.response.deploymentId, input.request.deploymentId, "deploymentId"],
    [input.response.processorId, input.request.processorId, "processorId"]
  ];
  for (const [actual, wanted, label] of expected) {
    if (actual !== wanted) throw new Error(`Slipway runtime env response ${label} did not match the signed request`);
  }
}

function diagnosticsTokenFromBootstrap(record: Record<string, unknown>): string | undefined {
  const diagnostics = recordOrUndefined(record.x) ?? recordOrUndefined(record.diagnostics);
  const token = diagnostics?.t ?? diagnostics?.token;
  return typeof token === "string" && token.length > 0 ? token : undefined;
}

async function emit(
  diagnostics: SlipwayRuntimeEnvLoadOptions["diagnostics"],
  event: SlipwayRuntimeEnvDiagnosticEvent
): Promise<void> {
  await Promise.resolve(diagnostics?.(event));
}
