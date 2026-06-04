import { createAcurastRuntimeAdapter, type RuntimeIdentityProvider } from "./acurast.js";
import {
  createSlipwayRuntimeDiagnosticEmitter,
  startSlipwayRuntimeHealth,
  type SlipwayRuntimeDiagnostic,
  type SlipwayRuntimeHealthHandle
} from "./diagnostics.js";
import { resolveRuntimeStd, type AcurastRuntimeStd } from "./env.js";
import {
  loadLockboxRuntimeSecrets,
  readLockboxRuntimeConfig,
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
import { safeErrorMessage, type RuntimeRandomBytes } from "./shared.js";

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
  const diagnostics = createSlipwayRuntimeDiagnosticEmitter({
    bootstrap: slipwayConfig,
    identityProvider,
    fetchImpl: options.fetchImpl,
    nowMs: options.nowMs,
    diagnostics: options.diagnostics,
    diagnosticSendTimeoutMs: options.diagnosticSendTimeoutMs ?? options.runtimeHealth?.sendTimeoutMs,
    setTimeoutImpl: options.setTimeoutImpl,
    clearTimeoutImpl: options.clearTimeoutImpl
  });

  await diagnostics.emit({
    stage: "runtime.start",
    status: "info",
    ok: true,
    component: "runtime-bootstrap",
    attrs: {
      hasSlipwayBootstrap: slipwayConfig !== undefined,
      hasLockboxBootstrap: lockboxConfig !== undefined
    }
  });

  let refreshHandle: SlipwayRuntimeEnvRefreshHandle | undefined;
  let runtimeHealthHandle: SlipwayRuntimeHealthHandle | undefined;
  let runtimeEnv: SlipwayRuntimeEnvLoadResult | undefined;
  let lockbox: LockboxRuntimeLoadResult | undefined;
  const bridgeRuntimeEnvDiagnostics =
    async (event: SlipwayRuntimeEnvDiagnosticEvent) => {
      await diagnostics.emit({
        phase: event.phase === "refresh_failed" ? "refresh_failed" : "slipway_runtime_env",
        stage: `slipway.${event.phase}`,
        status: event.ok ? "succeeded" : "failed",
        ok: event.ok,
        valueCount: event.valueCount,
        revision: event.revision,
        code: event.errorCode
      });
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
    try {
      lockbox = await loadLockboxRuntimeSecrets({
        identityProvider,
        config: lockboxConfig,
        env,
        fetchImpl: options.fetchImpl,
        nowMs: options.nowMs,
        randomBytes: options.randomBytes,
        diagnostics: async (event) => {
          await diagnostics.emit({
            phase: "lockbox_secrets",
            stage: `lockbox.${event.phase}`,
            status: event.ok ? "succeeded" : "failed",
            ok: event.ok,
            valueCount: event.secretCount,
            code: event.errorCode
          });
        }
      });
    } catch (error) {
      await diagnostics.emit({
        phase: "lockbox_secrets",
        stage: "lockbox.secret_request",
        status: "failed",
        ok: false,
        code: "lockbox_secret_request_failed",
        message: safeErrorMessage(error)
      });
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
