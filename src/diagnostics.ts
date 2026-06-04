import type { RuntimeIdentityProvider } from "./acurast.js";
import type { SlipwayRuntimeEnvConfig } from "./runtime-env.js";
import {
  assertSecureRuntimeUrl,
  safeErrorMessage
} from "./shared.js";

export const SLIPWAY_RUNTIME_DIAGNOSTIC_DOMAIN = "proof.slipway.runtime-diagnostic.v1";
export const DEFAULT_SLIPWAY_RUNTIME_HEALTH_INTERVAL_MS = 30_000;
export const DEFAULT_SLIPWAY_RUNTIME_HEALTH_INITIAL_DELAY_MS = 30_000;
export const DEFAULT_SLIPWAY_RUNTIME_DIAGNOSTIC_SEND_TIMEOUT_MS = 5_000;

export interface SlipwayRuntimeDiagnostic {
  phase?: "slipway_runtime_env" | "lockbox_secrets" | "refresh_failed" | "skipped";
  stage: string;
  status: "started" | "succeeded" | "failed" | "skipped" | "info";
  sequence: number;
  timestampMs: number;
  ok: boolean;
  component?: string;
  code?: string;
  message?: string;
  attrs?: Record<string, string | number | boolean | null>;
  valueCount?: number;
  revision?: string;
  error?: string;
}

export interface SlipwayRuntimeDiagnosticEmitter {
  emit(event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">): Promise<void>;
}

export interface SlipwayRuntimeDiagnosticEmitterOptions {
  bootstrap?: SlipwayRuntimeEnvConfig;
  identityProvider?: RuntimeIdentityProvider;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  diagnostics?: (event: SlipwayRuntimeDiagnostic) => void | Promise<void>;
  diagnosticSendTimeoutMs?: number;
  setTimeoutImpl?: typeof setTimeout;
  clearTimeoutImpl?: typeof clearTimeout;
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

export function createSlipwayRuntimeDiagnosticEmitter(
  options: SlipwayRuntimeDiagnosticEmitterOptions = {}
): SlipwayRuntimeDiagnosticEmitter {
  let sequence = 0;
  return {
    async emit(event) {
      const diagnostic = redactDiagnostic({
        ...event,
        sequence: sequence++,
        timestampMs: options.nowMs?.() ?? Date.now()
      });
      try {
        await Promise.resolve(options.diagnostics?.(diagnostic));
      } catch {
        // Local diagnostics are observability only.
      }
      if (!options.bootstrap?.diagnosticsToken) return;
      try {
        await sendSlipwayRuntimeDiagnostic({ ...options, bootstrap: options.bootstrap, diagnostic });
      } catch {
        // Remote diagnostics are best-effort and must not mask runtime bootstrap errors.
      }
    }
  };
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
    await emitter.emit({
      stage: "runtime.health",
      status: "info",
      ok: true,
      component: "runtime-health"
    });
  };
  const schedule = (delayMs: number) => {
    if (stopped || intervalMs <= 0 || !options.bootstrap?.diagnosticsToken) return;
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
    message: diagnostic.message ? redactString(diagnostic.message) : diagnostic.message,
    error: diagnostic.error ? redactString(diagnostic.error) : diagnostic.error,
    attrs: redactAttrs(diagnostic.attrs)
  };
}

async function sendSlipwayRuntimeDiagnostic(input: SlipwayRuntimeDiagnosticEmitterOptions & {
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
  const fetchPromise = fetchImpl(url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      domain: SLIPWAY_RUNTIME_DIAGNOSTIC_DOMAIN,
      applicationId: input.bootstrap.applicationId,
      policyDigest: input.bootstrap.policyDigest,
      deploymentId: input.bootstrap.deploymentId,
      token: input.bootstrap.diagnosticsToken,
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
    })
  });
  const response = await promiseWithTimeout(fetchPromise, diagnosticSendTimeoutMs(input), "Slipway runtime diagnostic send", input);
  if (!response.ok) {
    throw new Error(`Slipway runtime diagnostic rejected request: ${response.status} ${(await response.text()).slice(0, 500)}`);
  }
}

function diagnosticSendTimeoutMs(input: SlipwayRuntimeDiagnosticEmitterOptions & { bootstrap: SlipwayRuntimeEnvConfig }): number {
  return positiveInteger(input.diagnosticSendTimeoutMs ?? input.bootstrap.runtimeHealth?.sendTimeoutMs) ??
    DEFAULT_SLIPWAY_RUNTIME_DIAGNOSTIC_SEND_TIMEOUT_MS;
}

async function promiseWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
  options: Pick<SlipwayRuntimeDiagnosticEmitterOptions, "setTimeoutImpl" | "clearTimeoutImpl">
): Promise<T> {
  const setTimeoutImpl = options.setTimeoutImpl ?? setTimeout;
  const clearTimeoutImpl = options.clearTimeoutImpl ?? clearTimeout;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeoutImpl(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
        timer.unref?.();
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

function redactAttrs(attrs: SlipwayRuntimeDiagnostic["attrs"]): SlipwayRuntimeDiagnostic["attrs"] {
  if (!attrs) return undefined;
  return Object.fromEntries(Object.entries(attrs).filter(([key]) => !isSensitiveKey(key)));
}

function redactString(value: string): string {
  return value.replace(/(token|secret|password|private[_-]?key|authorization)=([^,\s]+)/giu, "$1=[redacted]");
}

function isSensitiveKey(key: string): boolean {
  return /token|secret|password|private|authorization|signature|key/iu.test(key);
}

export function diagnosticErrorMessage(error: unknown): string {
  return safeErrorMessage(error);
}
