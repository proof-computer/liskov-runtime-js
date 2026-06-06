import {
  DEFAULT_ENCRYPTION_KEY_ENV_NAMES,
  DEFAULT_JOB_ID_ENV_NAMES,
  DEFAULT_PROCESSOR_ID_ENV_NAMES,
  createAcurastRuntimeAdapter,
  type RuntimeIdentityProvider
} from "./acurast.js";
import {
  createSlipwayRuntimeDiagnosticEmitter,
  startSlipwayRuntimeHealth,
  type SlipwayRuntimeDiagnostic,
  type SlipwayRuntimeHealthHandle
} from "./diagnostics.js";
import { getFirstRuntimeEnvValue, resolveRuntimeStd, type AcurastRuntimeStd } from "./env.js";
import {
  loadLockboxRuntimeSecrets,
  readLockboxRuntimeConfig,
  type LockboxRuntimeDiagnosticEvent,
  type LockboxRuntimeLoadResult
} from "./lockbox.js";
import {
  loadSlipwayRuntimeEnv,
  readSlipwayRuntimeEnvConfig,
  startSlipwayRuntimeEnvRefresh,
  type SlipwayRuntimeEnvDiagnosticEvent,
  type SlipwayRuntimeEnvLoadResult,
  type SlipwayRuntimeEnvRefreshHandle
} from "./runtime-env.js";
import { type RuntimeRandomBytes } from "./shared.js";

export * from "./acurast.js";
export * from "./blackbox-logger.js";
export * from "./diagnostics.js";
export * from "./env.js";
export * from "./lockbox.js";
export * from "./proof-log-crypto.js";
export * from "./runtime-env.js";

export interface BootstrapSlipwayRuntimeOptions {
  env?: Record<string, string | undefined>;
  std?: AcurastRuntimeStd;
  environment?: (name: string) => unknown;
  identityProvider?: RuntimeIdentityProvider;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  diagnostics?: (event: SlipwayRuntimeDiagnostic) => void | Promise<void>;
  diagnosticSendTimeoutMs?: number;
  diagnosticRemoteBackoffMs?: number;
  runtimeHealth?: {
    intervalMs?: number;
    initialDelayMs?: number;
    sendTimeoutMs?: number;
  };
  setTimeoutImpl?: typeof setTimeout;
  clearTimeoutImpl?: typeof clearTimeout;
}

export interface BootstrapSlipwayRuntimeHandle {
  stop(): void;
  refreshNow(): Promise<SlipwayRuntimeEnvLoadResult | undefined>;
  runtimeEnv?: SlipwayRuntimeEnvLoadResult;
  lockbox?: LockboxRuntimeLoadResult;
  runtimeHealth?: SlipwayRuntimeHealthHandle;
}

export async function bootstrapSlipwayRuntime(
  options: BootstrapSlipwayRuntimeOptions = {}
): Promise<BootstrapSlipwayRuntimeHandle> {
  const env = options.env ?? process.env;
  const std = resolveRuntimeStd(options.std);
  const lookup = { env, std, environment: options.environment };
  const identityProvider = options.identityProvider ?? createAcurastRuntimeAdapter(lookup);
  const slipwayConfig = readSlipwayRuntimeEnvConfig(lookup);
  const lockboxConfig = readLockboxRuntimeConfig(lookup);
  await allowBootstrapHostnames(std, [
    urlHostOrNull(slipwayConfig?.slipwayUrl),
    urlHostOrNull(lockboxConfig?.lockboxUrl)
  ]);
  const diagnostics = createSlipwayRuntimeDiagnosticEmitter({
    bootstrap: slipwayConfig,
    identityProvider,
    fetchImpl: options.fetchImpl,
    nowMs: options.nowMs,
    diagnostics: options.diagnostics,
    diagnosticSendTimeoutMs: options.diagnosticSendTimeoutMs ?? options.runtimeHealth?.sendTimeoutMs,
    diagnosticRemoteBackoffMs: options.diagnosticRemoteBackoffMs,
    setTimeoutImpl: options.setTimeoutImpl,
    clearTimeoutImpl: options.clearTimeoutImpl
  });

  await diagnostics.emit({
    stage: "runtime.start",
    status: "info",
    ok: true,
    component: "runtime-bootstrap",
    attrs: {
      ...runtimeCapabilityAttrs(lookup, options.fetchImpl),
      ...runtimeBootstrapAttrs(lookup, slipwayConfig, lockboxConfig)
    }
  });

  let refreshHandle: SlipwayRuntimeEnvRefreshHandle | undefined;
  let runtimeHealthHandle: SlipwayRuntimeHealthHandle | undefined;
  let runtimeEnv: SlipwayRuntimeEnvLoadResult | undefined;
  let lockbox: LockboxRuntimeLoadResult | undefined;
  const bridgeRuntimeEnvDiagnostics =
    async (event: SlipwayRuntimeEnvDiagnosticEvent) => {
      await diagnostics.emit(slipwayRuntimeEnvDiagnostic(event));
    };
  const bridgeLockboxDiagnostics =
    async (event: LockboxRuntimeDiagnosticEvent) => {
      await diagnostics.emit(lockboxRuntimeDiagnostic(event));
    };

  if (slipwayConfig !== undefined) {
    refreshHandle = startSlipwayRuntimeEnvRefresh({
      identityProvider,
      config: slipwayConfig,
      env,
      fetchImpl: options.fetchImpl,
      nowMs: options.nowMs,
      randomBytes: options.randomBytes,
      diagnostics: bridgeRuntimeEnvDiagnostics,
      setTimeoutImpl: options.setTimeoutImpl,
      clearTimeoutImpl: options.clearTimeoutImpl
    });
    await diagnostics.emit({
      phase: "slipway_runtime_env",
      stage: "slipway.runtime_env.request",
      status: "started",
      ok: true
    });
    runtimeEnv = await refreshHandle.refreshNow();
  } else {
    await diagnostics.emit({
      phase: "skipped",
      stage: "slipway.runtime_env.request",
      status: "skipped",
      ok: true
    });
  }

  if (lockboxConfig !== undefined) {
    await diagnostics.emit({
      phase: "lockbox_secrets",
      stage: "lockbox.secret_request",
      status: "started",
      ok: true,
      attrs: { requestedSecretCount: lockboxConfig.requestedSecretIds.length }
    });
    try {
      lockbox = await loadLockboxRuntimeSecrets({
        identityProvider,
        config: lockboxConfig,
        env,
        fetchImpl: options.fetchImpl,
        nowMs: options.nowMs,
        randomBytes: options.randomBytes,
        diagnostics: bridgeLockboxDiagnostics
      });
      const secretCount = lockbox.installed.env.length + lockbox.installed.files.length;
      await diagnostics.emit({
        phase: "lockbox_secrets",
        stage: "lockbox.secret_request",
        status: "succeeded",
        ok: true,
        valueCount: secretCount,
        attrs: { secretCount }
      });
    } catch (error) {
      throw error;
    }
  }

  if (slipwayConfig !== undefined) {
    runtimeHealthHandle = startSlipwayRuntimeHealth({
      bootstrap: slipwayConfig,
      emitter: diagnostics,
      intervalMs: options.runtimeHealth?.intervalMs,
      initialDelayMs: options.runtimeHealth?.initialDelayMs,
      diagnosticSendTimeoutMs: options.diagnosticSendTimeoutMs ?? options.runtimeHealth?.sendTimeoutMs,
      setTimeoutImpl: options.setTimeoutImpl,
      clearTimeoutImpl: options.clearTimeoutImpl
    });
  }

  return {
    runtimeEnv,
    lockbox,
    runtimeHealth: runtimeHealthHandle,
    stop() {
      refreshHandle?.stop();
      runtimeHealthHandle?.stop();
    },
    async refreshNow() {
      return refreshHandle?.refreshNow();
    }
  };
}

function slipwayRuntimeEnvDiagnostic(
  event: SlipwayRuntimeEnvDiagnosticEvent
): Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs"> {
  const base = {
    phase: event.phase === "refresh_failed" ? "refresh_failed" as const : "slipway_runtime_env" as const,
    ok: event.ok,
    valueCount: event.valueCount,
    revision: event.revision,
    attrs: event.attrs
  };
  switch (event.phase) {
    case "identity_resolved":
      return { ...base, stage: "slipway.runtime_env.identity", status: "succeeded" };
    case "request_signed":
      return { ...base, stage: "slipway.runtime_env.signed", status: "succeeded" };
    case "runtime_env_request":
      return event.ok
        ? { ...base, stage: "slipway.runtime_env.fetch", status: "started" }
        : {
            ...base,
            stage: "slipway.runtime_env.request",
            status: "failed",
            code: "runtime_env_request_failed",
            message: event.errorCode,
            error: event.errorCode
          };
    case "runtime_env_response":
      return { ...base, stage: "slipway.runtime_env.response", status: event.ok ? "succeeded" : "failed" };
    case "env_installed":
      return { ...base, stage: "slipway.runtime_env.applied", status: "succeeded" };
    case "refresh_failed":
      return {
        ...base,
        stage: "slipway.runtime_env.refresh",
        status: "failed",
        code: "runtime_env_refresh_failed",
        message: event.errorCode,
        error: event.errorCode
      };
  }
}

function lockboxRuntimeDiagnostic(
  event: LockboxRuntimeDiagnosticEvent
): Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs"> {
  const base = {
    phase: "lockbox_secrets" as const,
    ok: event.ok,
    valueCount: event.secretCount,
    attrs: event.attrs
  };
  switch (event.phase) {
    case "identity_resolved":
      return { ...base, stage: "lockbox.secret_request.identity", status: "succeeded" };
    case "request_signed":
      return { ...base, stage: "lockbox.secret_request.signed", status: "succeeded" };
    case "lockbox_request":
      return { ...base, stage: "lockbox.secret_request.fetch", status: "started" };
    case "lockbox_response":
      return { ...base, stage: "lockbox.secret_request.response", status: event.ok ? "succeeded" : "failed" };
    case "payload_decrypted":
      return { ...base, stage: "lockbox.secret_request.decrypted", status: "succeeded" };
    case "secrets_installed":
      return { ...base, stage: "lockbox.secret_request.installed", status: "succeeded" };
    case "bootstrap_failed":
      return {
        ...base,
        stage: "lockbox.secret_request",
        status: "failed",
        code: "lockbox_secret_request_failed",
        message: event.errorCode,
        error: event.errorCode
      };
  }
}

function runtimeCapabilityAttrs(
  lookup: { env: Record<string, string | undefined>; std?: AcurastRuntimeStd; environment?: (name: string) => unknown },
  fetchImpl?: typeof fetch
): Record<string, boolean> {
  const std = lookup.std;
  return {
    hasFetch: typeof fetchImpl === "function" || typeof (globalThis as { fetch?: unknown }).fetch === "function",
    hasStdEnv: Boolean(std?.env),
    hasStdJob: Boolean(std?.job),
    hasJobId: Boolean(getFirstRuntimeEnvValue(DEFAULT_JOB_ID_ENV_NAMES, lookup) ?? stringifyRuntimeValue(std?.job?.getId?.())),
    hasEncryptionKeys: typeof std?.job?.getEncryptionKeys === "function",
    hasDeviceAddress: Boolean(getFirstRuntimeEnvValue(DEFAULT_PROCESSOR_ID_ENV_NAMES, lookup) ?? stringifyRuntimeValue(std?.device?.getAddress?.())),
    hasEd25519Signer: typeof std?.signers?.ed25519?.sign === "function",
    hasSecp256r1Encrypt: typeof std?.signers?.secp256r1?.encrypt === "function",
    hasSecp256r1Decrypt: typeof std?.signers?.secp256r1?.decrypt === "function"
  };
}

function runtimeBootstrapAttrs(
  lookup: { env: Record<string, string | undefined>; std?: AcurastRuntimeStd; environment?: (name: string) => unknown },
  slipwayConfig: ReturnType<typeof readSlipwayRuntimeEnvConfig>,
  lockboxConfig: ReturnType<typeof readLockboxRuntimeConfig>
): Record<string, string | number | boolean | null> {
  return {
    hasSlipwayBootstrap: Boolean(slipwayConfig),
    hasSlipwayDiagnosticsToken: Boolean(slipwayConfig?.diagnosticsToken),
    hasLockboxBootstrap: Boolean(lockboxConfig),
    slipwayBootstrapSource: runtimeEnvSource("PROOF_SLIPWAY_BOOTSTRAP", lookup),
    lockboxBootstrapSource: runtimeEnvSource("PROOF_LOCKBOX_BOOTSTRAP", lookup),
    slipwayHost: urlHostOrNull(slipwayConfig?.slipwayUrl),
    lockboxHost: urlHostOrNull(lockboxConfig?.lockboxUrl),
    applicationId: slipwayConfig?.applicationId ?? lockboxConfig?.applicationId ?? null,
    deploymentId: slipwayConfig?.deploymentId ?? lockboxConfig?.deploymentId ?? null
  };
}

function runtimeEnvSource(
  name: string,
  lookup: { env: Record<string, string | undefined>; std?: AcurastRuntimeStd; environment?: (name: string) => unknown }
): "process" | "std" | "environment" | "none" {
  if (lookup.env[name]) return "process";
  if (lookup.std?.env?.[name]) return "std";
  if (lookup.environment?.(name) !== undefined) return "environment";
  return "none";
}

async function allowBootstrapHostnames(
  std: AcurastRuntimeStd | undefined,
  hostnames: Array<string | null>
): Promise<void> {
  const net = std?.net;
  const addAllowedHostnames = net?.addAllowedHostnames;
  if (typeof addAllowedHostnames !== "function") return;
  const uniqueHostnames = [...new Set(hostnames.filter((hostname): hostname is string => Boolean(hostname)))];
  if (uniqueHostnames.length === 0) return;
  try {
    await Promise.resolve(addAllowedHostnames.call(net, uniqueHostnames));
  } catch {
    // Acurast network allowlisting is a bootstrap accelerator. The following
    // diagnostic/runtime-env requests still report the real network failure.
  }
}

function urlHostOrNull(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return new URL(value).hostname;
  } catch {
    return null;
  }
}

function stringifyRuntimeValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (value === undefined || value === null) return undefined;
  return JSON.stringify(value);
}
