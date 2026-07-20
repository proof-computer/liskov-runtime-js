import type { RuntimeIdentityProvider } from "./acurast.js";
import type { SlipwayRuntimeEnvConfig } from "./runtime-env.js";
import {
  assertSecureRuntimeUrl,
  canonicalJson,
  safeErrorMessage
} from "./shared.js";

export const SLIPWAY_RUNTIME_DIAGNOSTIC_DOMAIN = "proof.slipway.runtime-diagnostic.v1";
export const LISKOV_RUNTIME_DIAGNOSTIC_DOMAIN_V2 = "proof.liskov.runtime-diagnostic.v2";
export const LISKOV_RUNTIME_DIAGNOSTIC_DOMAIN_V3 = "proof.liskov.runtime-diagnostic.v3";
export const DEFAULT_SLIPWAY_RUNTIME_HEALTH_INTERVAL_MS = 30_000;
export const DEFAULT_SLIPWAY_RUNTIME_HEALTH_INITIAL_DELAY_MS = 30_000;
export const DEFAULT_SLIPWAY_RUNTIME_DIAGNOSTIC_SEND_TIMEOUT_MS = 1_500;
export const DEFAULT_SLIPWAY_RUNTIME_DIAGNOSTIC_REMOTE_BACKOFF_MS = 30_000;

const MAX_STAGE_LENGTH = 128;
const MAX_COMPONENT_LENGTH = 96;
const MAX_CODE_LENGTH = 96;
const MAX_MESSAGE_LENGTH = 500;
const MAX_ATTRS = 32;
const MAX_ATTR_KEY_LENGTH = 64;
const MAX_ATTR_VALUE_LENGTH = 256;

export type LiskovRuntimeDiagnosticStatus = "started" | "succeeded" | "failed" | "skipped" | "info";
export type LiskovRuntimeDiagnosticAttrs = Record<string, string | number | boolean | null>;
export type LiskovRuntimeFatalKind =
  | "bootstrap"
  | "application_start"
  | "uncaught_exception"
  | "unhandled_rejection"
  | "explicit";

export interface SlipwayRuntimeDiagnostic {
  phase?: "slipway_runtime_env" | "lockbox_secrets" | "slipway_logging" | "refresh_failed" | "skipped";
  stage: string;
  status: LiskovRuntimeDiagnosticStatus;
  sequence: number;
  timestampMs: number;
  ok: boolean;
  component?: string;
  code?: string;
  message?: string;
  attrs?: LiskovRuntimeDiagnosticAttrs;
  valueCount?: number;
  revision?: string;
  error?: string;
}

export interface LiskovRuntimeDiagnosticReport {
  stage: string;
  status: LiskovRuntimeDiagnosticStatus;
  component?: string;
  code?: string;
  message?: string;
  attrs?: LiskovRuntimeDiagnosticAttrs;
}

export interface LiskovRuntimeFatalReport {
  kind: LiskovRuntimeFatalKind;
  code: string;
  component?: string;
  error?: unknown;
  message?: string;
  attrs?: LiskovRuntimeDiagnosticAttrs;
}

export interface LiskovRuntimeDiagnostics {
  report(event: LiskovRuntimeDiagnosticReport): Promise<void>;
  fatal(event: LiskovRuntimeFatalReport): Promise<void>;
}

export interface SlipwayRuntimeDiagnosticEmitter extends LiskovRuntimeDiagnostics {
  emit(event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">): Promise<void>;
  configureBootstrap(bootstrap: SlipwayRuntimeEnvConfig | undefined): void;
  isClosed(): boolean;
}

export interface SlipwayRuntimeDiagnosticEmitterOptions {
  bootstrap?: SlipwayRuntimeEnvConfig;
  coreUrl?: string;
  allowInsecureHttp?: boolean;
  identityProvider?: RuntimeIdentityProvider;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  diagnostics?: (event: SlipwayRuntimeDiagnostic) => void | Promise<void>;
  diagnosticSendTimeoutMs?: number;
  diagnosticRemoteBackoffMs?: number;
  setTimeoutImpl?: typeof setTimeout;
  clearTimeoutImpl?: typeof clearTimeout;
  onFatal?: () => void;
}

export interface SlipwayRuntimeHealthHandle {
  stop(): void;
  sendNow(): Promise<void>;
}

export interface SlipwayRuntimeHealthOptions extends SlipwayRuntimeDiagnosticEmitterOptions {
  emitter?: SlipwayRuntimeDiagnosticEmitter;
  intervalMs?: number;
  initialDelayMs?: number;
}

export interface LiskovRuntimeDiagnosticV2Payload {
  jobId: string;
  processorId: string;
  stage: string;
  status: LiskovRuntimeDiagnosticStatus;
  sequence: number;
  timestampMs: number;
  component: string | null;
  code: string | null;
  message: string | null;
  attrs: LiskovRuntimeDiagnosticAttrs | null;
}

export interface LiskovRuntimeDiagnosticV3Payload extends LiskovRuntimeDiagnosticV2Payload {
  runtimeInstanceId: string;
}

export function createSlipwayRuntimeDiagnosticEmitter(
  options: SlipwayRuntimeDiagnosticEmitterOptions = {}
): SlipwayRuntimeDiagnosticEmitter {
  let sequence = 0;
  let remoteDisabledUntilMs = 0;
  let bootstrap = options.bootstrap;
  let closed = false;
  let fatalPromise: Promise<void> | undefined;

  const prepare = (
    event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">
  ): SlipwayRuntimeDiagnostic => {
    const timestampMs = options.nowMs?.() ?? Date.now();
    return redactDiagnostic({
      ...event,
      sequence: sequence++,
      timestampMs
    });
  };

  const deliver = async (diagnostic: SlipwayRuntimeDiagnostic, terminal: boolean): Promise<void> => {
    const local = sendLocalDiagnostic(options, diagnostic);
    const remoteSend = sendRemoteDiagnostic({
      ...options,
      bootstrap,
      diagnostic,
      terminal,
      remoteDisabledUntilMs
    });
    const remote = terminal
      ? promiseWithTimeout(
          remoteSend,
          diagnosticSendTimeoutMs(options),
          "Terminal Liskov runtime diagnostic attempt",
          options
        )
      : remoteSend;
    const [, remoteResult] = await Promise.allSettled([local, remote]);
    if (remoteResult.status === "rejected" && !terminal) {
      remoteDisabledUntilMs = (options.nowMs?.() ?? Date.now()) + diagnosticRemoteBackoffMs(options);
    }
  };

  const emitter: SlipwayRuntimeDiagnosticEmitter = {
    emit(event) {
      if (closed) return Promise.resolve();
      return deliver(prepare(event), false);
    },
    report(event) {
      if (event.stage === "runtime.fatal" || event.stage.startsWith("runtime.fatal.")) {
        return Promise.reject(new Error("runtime.fatal.* diagnostics are terminal and must use fatal()"));
      }
      if (closed) return Promise.resolve();
      return deliver(prepare({ ...event, ok: event.status !== "failed" }), false);
    },
    fatal(event) {
      if (fatalPromise) return fatalPromise;
      closed = true;
      try {
        options.onFatal?.();
      } catch {
        // Cleanup must not displace the terminal report or first-call-wins promise.
      }
      const message = event.message ?? (event.error === undefined ? undefined : diagnosticErrorMessage(event.error));
      const diagnostic = prepare({
        stage: `runtime.fatal.${event.kind}`,
        status: "failed",
        ok: false,
        component: event.component,
        code: event.code,
        message,
        error: message,
        attrs: event.attrs
      });
      fatalPromise = deliver(diagnostic, true);
      return fatalPromise;
    },
    configureBootstrap(value) {
      bootstrap = value;
    },
    isClosed() {
      return closed;
    }
  };
  return emitter;
}

export function startSlipwayRuntimeHealth(options: SlipwayRuntimeHealthOptions = {}): SlipwayRuntimeHealthHandle {
  const intervalMs = nonNegativeInteger(options.intervalMs ?? options.bootstrap?.runtimeHealth?.intervalMs) ??
    DEFAULT_SLIPWAY_RUNTIME_HEALTH_INTERVAL_MS;
  const initialDelayMs = nonNegativeInteger(options.initialDelayMs ?? options.bootstrap?.runtimeHealth?.initialDelayMs) ??
    DEFAULT_SLIPWAY_RUNTIME_HEALTH_INITIAL_DELAY_MS;
  const setTimeoutImpl = options.setTimeoutImpl ?? setTimeout;
  const clearTimeoutImpl = options.clearTimeoutImpl ?? clearTimeout;
  const emitter = options.emitter ?? createSlipwayRuntimeDiagnosticEmitter(options);
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const sendNow = async () => {
    if (stopped) return;
    await emitter.emit({
      stage: "runtime.health",
      status: "info",
      ok: true,
      component: "runtime-health"
    });
  };
  const schedule = (delayMs: number) => {
    if (stopped || intervalMs <= 0 || !canSendRemoteDiagnostic(options)) return;
    if (timer) clearTimeoutImpl(timer);
    timer = setTimeoutImpl(() => {
      void sendNow().finally(() => schedule(intervalMs));
    }, delayMs);
    timer.unref?.();
  };
  schedule(initialDelayMs);
  return {
    stop() {
      stopped = true;
      if (timer) clearTimeoutImpl(timer);
      timer = undefined;
    },
    sendNow
  };
}

export function redactDiagnostic(diagnostic: SlipwayRuntimeDiagnostic): SlipwayRuntimeDiagnostic {
  return {
    ...diagnostic,
    stage: boundedRequiredString(diagnostic.stage, MAX_STAGE_LENGTH, "stage"),
    component: boundedOptionalString(diagnostic.component, MAX_COMPONENT_LENGTH),
    code: boundedOptionalString(diagnostic.code, MAX_CODE_LENGTH),
    message: diagnostic.message ? redactDiagnosticMessage(diagnostic.message) : diagnostic.message,
    error: diagnostic.error ? redactDiagnosticMessage(diagnostic.error) : diagnostic.error,
    attrs: redactAttrs(diagnostic.attrs)
  };
}

/** Legacy v1 canonical bytes retained for the accept-both compatibility window. */
export function slipwayRuntimeDiagnosticRequestMessage(input: {
  applicationId: string;
  policyDigest: string;
  deploymentId: string;
  stage: string;
  status: string;
  sequence: number;
  timestampMs: number;
}): Uint8Array {
  return Buffer.from(
    canonicalJson({
      domain: SLIPWAY_RUNTIME_DIAGNOSTIC_DOMAIN,
      applicationId: input.applicationId,
      policyDigest: input.policyDigest.toLowerCase(),
      deploymentId: input.deploymentId,
      stage: input.stage,
      status: input.status,
      sequence: input.sequence,
      timestampMs: input.timestampMs
    }),
    "utf8"
  );
}

export function canonicalLiskovRuntimeDiagnosticV2Payload(
  input: LiskovRuntimeDiagnosticV2Payload
): LiskovRuntimeDiagnosticV2Payload {
  const status = input.status;
  if (!["started", "succeeded", "failed", "skipped", "info"].includes(status)) {
    throw new Error("status is not supported");
  }
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 0) {
    throw new Error("sequence must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(input.timestampMs) || input.timestampMs <= 0) {
    throw new Error("timestampMs must be a positive safe integer");
  }
  const message = boundedOptionalString(input.message ?? undefined, MAX_MESSAGE_LENGTH);
  return {
    jobId: boundedRequiredString(input.jobId, 256, "jobId"),
    processorId: boundedRequiredString(input.processorId, 256, "processorId"),
    stage: boundedRequiredString(input.stage, MAX_STAGE_LENGTH, "stage"),
    status,
    sequence: input.sequence,
    timestampMs: input.timestampMs,
    component: boundedOptionalString(input.component ?? undefined, MAX_COMPONENT_LENGTH) ?? null,
    code: boundedOptionalString(input.code ?? undefined, MAX_CODE_LENGTH) ?? null,
    message: message ? redactDiagnosticMessage(message) : null,
    attrs: redactAttrs(input.attrs ?? undefined) ?? null
  };
}

export function liskovRuntimeDiagnosticV2Message(input: LiskovRuntimeDiagnosticV2Payload): Uint8Array {
  return Buffer.from(canonicalJson({
    domain: LISKOV_RUNTIME_DIAGNOSTIC_DOMAIN_V2,
    ...canonicalLiskovRuntimeDiagnosticV2Payload(input)
  }), "utf8");
}

export function canonicalLiskovRuntimeDiagnosticV3Payload(
  input: LiskovRuntimeDiagnosticV3Payload
): LiskovRuntimeDiagnosticV3Payload {
  return {
    ...canonicalLiskovRuntimeDiagnosticV2Payload(input),
    runtimeInstanceId: boundedRequiredString(input.runtimeInstanceId, 256, "runtimeInstanceId")
  };
}

export function liskovRuntimeDiagnosticV3Message(input: LiskovRuntimeDiagnosticV3Payload): Uint8Array {
  return Buffer.from(canonicalJson({
    domain: LISKOV_RUNTIME_DIAGNOSTIC_DOMAIN_V3,
    ...canonicalLiskovRuntimeDiagnosticV3Payload(input)
  }), "utf8");
}

function canSendRemoteDiagnostic(options: SlipwayRuntimeDiagnosticEmitterOptions): boolean {
  if (options.coreUrl && options.identityProvider) return true;
  if (!options.bootstrap) return false;
  return Boolean(options.bootstrap.diagnosticsToken) || Boolean(options.identityProvider);
}

async function sendLocalDiagnostic(
  options: SlipwayRuntimeDiagnosticEmitterOptions,
  diagnostic: SlipwayRuntimeDiagnostic
): Promise<void> {
  if (!options.diagnostics) return;
  await promiseWithTimeout(
    Promise.resolve(options.diagnostics(diagnostic)),
    diagnosticSendTimeoutMs(options),
    "Local Liskov runtime diagnostic callback",
    options
  );
}

async function sendRemoteDiagnostic(input: SlipwayRuntimeDiagnosticEmitterOptions & {
  bootstrap?: SlipwayRuntimeEnvConfig;
  diagnostic: SlipwayRuntimeDiagnostic;
  terminal: boolean;
  remoteDisabledUntilMs: number;
}): Promise<void> {
  if (!canSendRemoteDiagnostic(input)) return;
  if (!input.terminal && input.diagnostic.timestampMs < input.remoteDisabledUntilMs) return;
  if (input.coreUrl && input.identityProvider) {
    await sendLiskovRuntimeDiagnostic({
      ...input,
      coreUrl: input.coreUrl,
      identityProvider: input.identityProvider
    });
    return;
  }
  if (input.bootstrap) await sendSlipwayRuntimeDiagnosticV1({ ...input, bootstrap: input.bootstrap });
}

async function sendLiskovRuntimeDiagnostic(input: SlipwayRuntimeDiagnosticEmitterOptions & {
  coreUrl: string;
  identityProvider: RuntimeIdentityProvider;
  diagnostic: SlipwayRuntimeDiagnostic;
}): Promise<void> {
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") return;
  const url = new URL("/api/jobs/runtime-diagnostics", input.coreUrl);
  assertSecureRuntimeUrl(url, input.allowInsecureHttp, "Liskov runtime diagnostics");
  const identity = await input.identityProvider.resolveIdentity({ requireEncryptionKey: false });
  const payload = canonicalLiskovRuntimeDiagnosticV2Payload({
    jobId: identity.jobId,
    processorId: identity.processorId,
    stage: input.diagnostic.stage,
    status: input.diagnostic.status,
    sequence: input.diagnostic.sequence,
    timestampMs: input.diagnostic.timestampMs,
    component: input.diagnostic.component ?? null,
    code: input.diagnostic.code ?? null,
    message: input.diagnostic.message ?? input.diagnostic.error ?? null,
    attrs: {
      ...input.diagnostic.attrs,
      ...(input.diagnostic.valueCount === undefined ? {} : { valueCount: input.diagnostic.valueCount }),
      ...(input.diagnostic.revision === undefined ? {} : { revision: input.diagnostic.revision })
    }
  });
  const runtimeInstanceId = input.bootstrap?.runtimeInstanceId;
  const v3Payload = runtimeInstanceId === undefined
    ? undefined
    : canonicalLiskovRuntimeDiagnosticV3Payload({ ...payload, runtimeInstanceId });
  const signature = await input.identityProvider.sign(
    v3Payload === undefined
      ? liskovRuntimeDiagnosticV2Message(payload)
      : liskovRuntimeDiagnosticV3Message(v3Payload)
  );
  await postDiagnostic({ ...input, fetchImpl, url, body: {
    domain: v3Payload === undefined
      ? LISKOV_RUNTIME_DIAGNOSTIC_DOMAIN_V2
      : LISKOV_RUNTIME_DIAGNOSTIC_DOMAIN_V3,
    ...(v3Payload ?? payload),
    signature
  }});
}

async function sendSlipwayRuntimeDiagnosticV1(input: SlipwayRuntimeDiagnosticEmitterOptions & {
  bootstrap: SlipwayRuntimeEnvConfig;
  diagnostic: SlipwayRuntimeDiagnostic;
}): Promise<void> {
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") return;
  const url = new URL("/api/jobs/runtime-diagnostics", input.bootstrap.slipwayUrl);
  assertSecureRuntimeUrl(url, input.bootstrap.allowInsecureHttp, "Slipway runtime diagnostics");
  let identity: Awaited<ReturnType<RuntimeIdentityProvider["resolveIdentity"]>> | undefined;
  try {
    identity = await input.identityProvider?.resolveIdentity({ requireEncryptionKey: false });
  } catch {
    identity = undefined;
  }
  let signature: string | undefined;
  if (input.identityProvider) {
    try {
      const message = slipwayRuntimeDiagnosticRequestMessage({
        applicationId: input.bootstrap.applicationId,
        policyDigest: input.bootstrap.policyDigest,
        deploymentId: input.bootstrap.deploymentId,
        stage: input.diagnostic.stage,
        status: input.diagnostic.status,
        sequence: input.diagnostic.sequence,
        timestampMs: input.diagnostic.timestampMs
      });
      signature = await input.identityProvider.sign(message);
    } catch {
      signature = undefined;
    }
  }
  await postDiagnostic({ ...input, fetchImpl, url, body: {
    domain: SLIPWAY_RUNTIME_DIAGNOSTIC_DOMAIN,
    applicationId: input.bootstrap.applicationId,
    policyDigest: input.bootstrap.policyDigest,
    deploymentId: input.bootstrap.deploymentId,
    token: input.bootstrap.diagnosticsToken,
    signature,
    stage: input.diagnostic.stage,
    status: input.diagnostic.status,
    sequence: input.diagnostic.sequence,
    timestampMs: input.diagnostic.timestampMs,
    jobId: identity?.jobId,
    processorAddress: identity?.processorId,
    component: input.diagnostic.component,
    code: input.diagnostic.code,
    message: input.diagnostic.message ?? input.diagnostic.error,
    attrs: {
      ...input.diagnostic.attrs,
      ...(input.diagnostic.valueCount === undefined ? {} : { valueCount: input.diagnostic.valueCount }),
      ...(input.diagnostic.revision === undefined ? {} : { revision: input.diagnostic.revision })
    }
  }});
}

async function postDiagnostic(input: SlipwayRuntimeDiagnosticEmitterOptions & {
  fetchImpl: typeof fetch;
  url: URL;
  body: Record<string, unknown>;
}): Promise<void> {
  const controller = typeof AbortController === "function" ? new AbortController() : undefined;
  const fetchPromise = input.fetchImpl(input.url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    signal: controller?.signal,
    body: JSON.stringify(input.body)
  });
  const response = await promiseWithTimeout(
    fetchPromise,
    diagnosticSendTimeoutMs(input),
    "Liskov runtime diagnostic send",
    input,
    () => controller?.abort()
  );
  if (!response.ok) {
    throw new Error(`Liskov runtime diagnostic rejected request: ${response.status} ${(await response.text()).slice(0, 500)}`);
  }
}

function diagnosticSendTimeoutMs(input: SlipwayRuntimeDiagnosticEmitterOptions): number {
  return positiveInteger(input.diagnosticSendTimeoutMs ?? input.bootstrap?.runtimeHealth?.sendTimeoutMs) ??
    DEFAULT_SLIPWAY_RUNTIME_DIAGNOSTIC_SEND_TIMEOUT_MS;
}

function diagnosticRemoteBackoffMs(input: SlipwayRuntimeDiagnosticEmitterOptions): number {
  return nonNegativeInteger(input.diagnosticRemoteBackoffMs) ??
    DEFAULT_SLIPWAY_RUNTIME_DIAGNOSTIC_REMOTE_BACKOFF_MS;
}

async function promiseWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
  options: Pick<SlipwayRuntimeDiagnosticEmitterOptions, "setTimeoutImpl" | "clearTimeoutImpl">,
  onTimeout?: () => void
): Promise<T> {
  const setTimeoutImpl = options.setTimeoutImpl ?? setTimeout;
  const clearTimeoutImpl = options.clearTimeoutImpl ?? clearTimeout;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeoutImpl(() => {
          onTimeout?.();
          reject(new Error(`${label} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeoutImpl(timer);
  }
}

function positiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function nonNegativeInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function charTruncate(value: string, max: number): string {
  return [...value].slice(0, max).join("");
}

function boundedRequiredString(value: string, max: number, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} must be a string`);
  return charTruncate(normalized, max);
}

function boundedOptionalString(value: string | undefined, max: number): string | undefined {
  const normalized = value?.trim();
  return normalized ? charTruncate(normalized, max) : undefined;
}

function sensitiveKey(key: string): boolean {
  return /(secret|seed|token|key|dek|cipher|signature|password|mnemonic|private)/iu.test(key);
}

function redactAttrs(attrs: SlipwayRuntimeDiagnostic["attrs"]): SlipwayRuntimeDiagnostic["attrs"] {
  if (!attrs) return undefined;
  const out: LiskovRuntimeDiagnosticAttrs = {};
  for (const [rawKey, rawValue] of Object.entries(attrs).slice(0, MAX_ATTRS)) {
    const key = charTruncate(rawKey.trim(), MAX_ATTR_KEY_LENGTH);
    if (!key || sensitiveKey(key)) continue;
    if (typeof rawValue === "string") {
      out[key] = redactAttrString(key, rawValue);
    } else if (typeof rawValue === "number" && Number.isFinite(rawValue)) {
      out[key] = rawValue;
    } else if (typeof rawValue === "boolean" || rawValue === null) {
      out[key] = rawValue;
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function redactAttrString(key: string, value: string): string {
  if (sensitiveKey(key) || /^(0x)?[0-9a-f]{64,}$/iu.test(value) || /^[A-Za-z0-9_-]{80,}$/u.test(value)) {
    return "[redacted]";
  }
  return charTruncate(value, MAX_ATTR_VALUE_LENGTH);
}

function redactDiagnosticMessage(value: string): string {
  const bounded = charTruncate(value.trim(), MAX_MESSAGE_LENGTH);
  return bounded
    .replace(/(0x)?[0-9a-f]{64,}/giu, "[redacted]")
    .replace(/[A-Za-z0-9_-]{80,}/gu, "[redacted]")
    .replace(/\b(secret|seed|token|private[_-]?key|dek|ciphertext|signature)\s*[:=]\s*[^,\s}]+/giu, "$1=[redacted]");
}

export function diagnosticErrorMessage(error: unknown): string {
  return safeErrorMessage(error);
}
