import {
  DEFAULT_ENCRYPTION_KEY_ENV_NAMES,
  DEFAULT_JOB_ID_ENV_NAMES,
  DEFAULT_PROCESSOR_ID_ENV_NAMES,
  createAcurastRuntimeAdapter,
  type RuntimeIdentityProvider
} from "./acurast.js";
import {
  blackboxLogHostnames,
  blackboxLogConfigFingerprint,
  createBlackboxRemoteLogger,
  maybeAcurastBlackboxRequestSigner,
  readBlackboxLogConfig,
  type BlackboxLogRecord
} from "./blackbox-logger.js";
import {
  isLiskovSignedBootstrapUnavailableError,
  liskovSignedBootstrapUrls,
  loadLiskovRuntimeBootstrap,
  loadLiskovSecretBootstrap,
  type LiskovSignedBootstrapRetryOptions,
  type LiskovSignedBootstrapMode
} from "./bootstrap.js";
import {
  createSlipwayRuntimeDiagnosticEmitter,
  startSlipwayRuntimeHealth,
  type SlipwayRuntimeDiagnostic,
  type SlipwayRuntimeHealthHandle
} from "./diagnostics.js";
import { getFirstRuntimeEnvValue, resolveRuntimeStd, type AcurastRuntimeStd } from "./env.js";
import { resolveSlipwayHome } from "./home.js";
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
import { safeErrorMessage, type RuntimeRandomBytes } from "./shared.js";

export * from "./acurast.js";
export * from "./blackbox-logger.js";
export * from "./bootstrap.js";
export * from "./diagnostics.js";
export * from "./env.js";
export * from "./home.js";
export * from "./lockbox.js";
export * from "./proof-log-crypto.js";
export * from "./runtime-env.js";

export type SlipwayRuntimeCapabilityState = "off" | "pending" | "ready" | "degraded" | "failed" | "blocked";
export type SlipwayRuntimeSecretMode = "required" | "background" | "off";
export type SlipwayRuntimeLoggingMode = "required" | "background" | "off";
export type SlipwayRuntimeLoggingSpoolMode = "auto" | "disk" | "memory";
export type SlipwayRuntimeLogSeverity = "debug" | "info" | "warn" | "error";

export interface SlipwayRuntimeSecretRetryOptions {
  initialDelayMs?: number;
  intervalMs?: number;
  maxElapsedMs?: number;
  maxAttempts?: number;
}

export interface SlipwayRuntimeCapabilityStatus {
  state: SlipwayRuntimeCapabilityState;
  required: boolean;
  sinceMs: number;
  code?: string;
  message?: string;
  revision?: string;
  fingerprint?: string;
  valueCount?: number;
}

export interface SlipwayRuntimeStatus {
  ok: boolean;
  ready: boolean;
  home: string;
  applicationId?: string;
  deploymentId?: string;
  revision?: string;
  blockers: Array<{ capability: keyof SlipwayRuntimeCapabilityMap; code: string; message: string }>;
  capabilities: SlipwayRuntimeCapabilityMap;
}

export interface SlipwayRuntimeCapabilityMap {
  runtimeEnv: SlipwayRuntimeCapabilityStatus;
  secrets: SlipwayRuntimeCapabilityStatus;
  logging: SlipwayRuntimeCapabilityStatus;
  diagnostics: SlipwayRuntimeCapabilityStatus;
  switchboard: SlipwayRuntimeCapabilityStatus;
}

export interface SlipwayRuntimeLogOptions {
  severity?: SlipwayRuntimeLogSeverity;
  labels?: Record<string, string>;
}

export interface SlipwayRuntimeFlushResult {
  ok: boolean;
  state: SlipwayRuntimeCapabilityState;
  flushed: number;
  pending: number;
  dropped: number;
  message?: string;
}

export interface SlipwayRuntimeEnvAccessor {
  get(name: string): string | undefined;
  require(name: string): string;
}

export class SlipwayRuntimeNotReadyError extends Error {
  readonly status: SlipwayRuntimeStatus;

  constructor(status: SlipwayRuntimeStatus) {
    super(`Slipway runtime is not ready: ${status.blockers.map((blocker) => blocker.code).join(", ")}`);
    this.name = "SlipwayRuntimeNotReadyError";
    this.status = status;
  }
}

export interface BootstrapSlipwayRuntimeOptions {
  appId?: string;
  component?: string;
  revision?: string;
  home?: string;
  secrets?: {
    mode?: SlipwayRuntimeSecretMode;
    retry?: SlipwayRuntimeSecretRetryOptions;
  };
  bootstrap?: {
    mode?: LiskovSignedBootstrapMode;
    coreUrl?: string;
    secretsUrl?: string;
    allowInsecureHttp?: boolean;
    requestTtlMs?: number;
    retry?: LiskovSignedBootstrapRetryOptions;
  };
  logging?: {
    mode?: SlipwayRuntimeLoggingMode;
    earlyBufferMaxRecords?: number;
    spoolMode?: SlipwayRuntimeLoggingSpoolMode;
    spoolDir?: string;
    timeoutMs?: number;
    onError?: (error: unknown, event: string) => void;
  };
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
  readonly home: string;
  readonly env: SlipwayRuntimeEnvAccessor;
  status(): SlipwayRuntimeStatus;
  whenReady(): Promise<SlipwayRuntimeStatus>;
  log(event: string, details?: Record<string, unknown>, options?: SlipwayRuntimeLogOptions): Promise<void>;
  flush(): Promise<SlipwayRuntimeFlushResult>;
  stop(): void;
  refreshNow(): Promise<SlipwayRuntimeEnvLoadResult | undefined>;
  runtimeEnv?: SlipwayRuntimeEnvLoadResult;
  lockbox?: LockboxRuntimeLoadResult;
  runtimeHealth?: SlipwayRuntimeHealthHandle;
}

async function resolveSignedRuntimeBootstrap(input: {
  mode: LiskovSignedBootstrapMode;
  env: Record<string, string | undefined>;
  std?: AcurastRuntimeStd;
  environment?: (name: string) => unknown;
  identityProvider: RuntimeIdentityProvider;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  setTimeoutImpl?: typeof setTimeout;
  bootstrap?: BootstrapSlipwayRuntimeOptions["bootstrap"];
  requestedSecretsMode?: SlipwayRuntimeSecretMode;
  hasLockboxConfig: boolean;
  setSlipwayConfig(config: NonNullable<ReturnType<typeof readSlipwayRuntimeEnvConfig>>): void;
  setLockboxConfig(config: NonNullable<ReturnType<typeof readLockboxRuntimeConfig>>): void;
}): Promise<void> {
  const signedOptions = {
    env: input.env,
    std: input.std,
    environment: input.environment,
    identityProvider: input.identityProvider,
    fetchImpl: input.fetchImpl,
    nowMs: input.nowMs,
    randomBytes: input.randomBytes,
    setTimeoutImpl: input.setTimeoutImpl,
    coreUrl: input.bootstrap?.coreUrl,
    secretsUrl: input.bootstrap?.secretsUrl,
    allowInsecureHttp: input.bootstrap?.allowInsecureHttp,
    requestTtlMs: input.bootstrap?.requestTtlMs,
    retry: input.bootstrap?.retry
  };
  const urls = liskovSignedBootstrapUrls(signedOptions);
  await allowBootstrapHostnames(input.std, [urlHostOrNull(urls.coreUrl), urlHostOrNull(urls.secretsUrl)]);
  const runtimeBootstrap = await loadSignedRuntimeBootstrapOrSkip(input.mode, signedOptions);
  if (!runtimeBootstrap) return;
  if (runtimeBootstrap.runtimeEnvConfig !== undefined) {
    input.setSlipwayConfig(runtimeBootstrap.runtimeEnvConfig);
  }
  if (input.hasLockboxConfig) return;
  if (input.requestedSecretsMode === "off") return;
  const shouldDiscoverSecrets =
    runtimeBootstrap.secretsRequired ||
    input.requestedSecretsMode === "required" ||
    input.requestedSecretsMode === "background";
  if (!shouldDiscoverSecrets) return;
  await allowBootstrapHostnames(input.std, [urlHostOrNull(runtimeBootstrap.secretsUrl)]);
  const secretBootstrap = await loadSignedSecretBootstrapOrSkip(
    input.mode,
    { ...signedOptions, secretsUrl: runtimeBootstrap.secretsUrl },
    runtimeBootstrap.secretsRequired
  );
  if (secretBootstrap !== undefined) input.setLockboxConfig(secretBootstrap.lockboxConfig);
}

async function loadSignedRuntimeBootstrapOrSkip(
  mode: LiskovSignedBootstrapMode,
  options: Parameters<typeof loadLiskovRuntimeBootstrap>[0]
): Promise<Awaited<ReturnType<typeof loadLiskovRuntimeBootstrap>> | undefined> {
  try {
    return await loadLiskovRuntimeBootstrap(options);
  } catch (error) {
    if (mode === "auto" && isLiskovSignedBootstrapUnavailableError(error)) return undefined;
    throw error;
  }
}

async function loadSignedSecretBootstrapOrSkip(
  mode: LiskovSignedBootstrapMode,
  options: Parameters<typeof loadLiskovSecretBootstrap>[0],
  required: boolean
): Promise<Awaited<ReturnType<typeof loadLiskovSecretBootstrap>> | undefined> {
  try {
    return await loadLiskovSecretBootstrap(options);
  } catch (error) {
    if (!required && mode === "auto" && isLiskovSignedBootstrapUnavailableError(error)) return undefined;
    throw error;
  }
}

export async function bootstrapSlipwayRuntime(
  options: BootstrapSlipwayRuntimeOptions = {}
): Promise<BootstrapSlipwayRuntimeHandle> {
  const env = options.env ?? process.env;
  const home = resolveSlipwayHome({ home: options.home, env });
  const std = resolveRuntimeStd(options.std);
  const lookup = { env, std, environment: options.environment };
  const identityProvider = options.identityProvider ?? createAcurastRuntimeAdapter(lookup);
  let slipwayConfig = readSlipwayRuntimeEnvConfig(lookup);
  let lockboxConfig = readLockboxRuntimeConfig(lookup);
  const startedAtMs = options.nowMs?.() ?? Date.now();
  const signedBootstrapMode = options.bootstrap?.mode ?? "auto";
  const shouldResolveSignedBootstrap =
    signedBootstrapMode !== "off" && (
      signedBootstrapMode === "signed" ||
      (slipwayConfig === undefined && lockboxConfig === undefined) ||
      (lockboxConfig === undefined && options.secrets?.mode !== undefined && options.secrets.mode !== "off")
    );
  if (shouldResolveSignedBootstrap) {
    await resolveSignedRuntimeBootstrap({
      mode: signedBootstrapMode,
      env,
      std,
      environment: options.environment,
      identityProvider,
      fetchImpl: options.fetchImpl,
      nowMs: options.nowMs,
      randomBytes: options.randomBytes,
      setTimeoutImpl: options.setTimeoutImpl,
      bootstrap: options.bootstrap,
      requestedSecretsMode: options.secrets?.mode,
      hasLockboxConfig: lockboxConfig !== undefined,
      setSlipwayConfig: (config) => {
        slipwayConfig ??= config;
      },
      setLockboxConfig: (config) => {
        lockboxConfig ??= config;
      }
    });
  }
  const secretsMode = options.secrets?.mode ?? (lockboxConfig === undefined ? "off" : "required");
  const loggingMode = options.logging?.mode ?? "background";
  await allowBootstrapHostnames(std, [
    urlHostOrNull(slipwayConfig?.slipwayUrl),
    urlHostOrNull(lockboxConfig?.lockboxUrl),
    ...blackboxLogHostnames((name) => env[name])
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
  const logging = createSlipwayRuntimeLoggingController({
    env,
    std,
    mode: loggingMode,
    required: loggingMode === "required",
    startedAtMs,
    earlyBufferMaxRecords: options.logging?.earlyBufferMaxRecords ?? 100,
    fetchImpl: options.fetchImpl,
    spoolMode: options.logging?.spoolMode,
    spoolDir: options.logging?.spoolDir,
    timeoutMs: options.logging?.timeoutMs,
    nowMs: options.nowMs,
    onError: options.logging?.onError,
    diagnostics,
    allowHostnames: (hostnames) => allowBootstrapHostnames(std, hostnames),
    baseRecord: () => compactRuntimeRecord({
      applicationId: options.appId ?? runtimeEnv?.response.applicationId ?? slipwayConfig?.applicationId ?? lockboxConfig?.applicationId,
      deploymentId: runtimeEnv?.response.deploymentId ?? slipwayConfig?.deploymentId ?? lockboxConfig?.deploymentId,
      component: options.component,
      revision: options.revision ?? runtimeEnv?.response.revision
    })
  });
  const bridgeRuntimeEnvDiagnostics =
    async (event: SlipwayRuntimeEnvDiagnosticEvent) => {
      await diagnostics.emit(slipwayRuntimeEnvDiagnostic(event));
    };
  const bridgeLockboxDiagnostics =
    async (event: LockboxRuntimeDiagnosticEvent) => {
      await diagnostics.emit(lockboxRuntimeDiagnostic(event));
    };
  const secrets = createSlipwayRuntimeSecretsController({
    env,
    mode: secretsMode,
    startedAtMs,
    config: lockboxConfig,
    retry: options.secrets?.retry,
    identityProvider,
    fetchImpl: options.fetchImpl,
    nowMs: options.nowMs,
    randomBytes: options.randomBytes,
    diagnostics,
    lockboxDiagnostics: bridgeLockboxDiagnostics,
    setTimeoutImpl: options.setTimeoutImpl,
    clearTimeoutImpl: options.clearTimeoutImpl,
    onLoaded: async () => {
      await logging.refresh();
    }
  });

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

  if (secretsMode === "required") {
    await secrets.loadRequired();
  } else if (secretsMode === "background") {
    secrets.startBackground();
  }

  await logging.refresh();

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
    home,
    get runtimeEnv() {
      return runtimeEnv;
    },
    get lockbox() {
      return secrets.result();
    },
    get runtimeHealth() {
      return runtimeHealthHandle;
    },
    env: {
      get(name) {
        return getFirstRuntimeEnvValue([name], lookup);
      },
      require(name) {
        const value = getFirstRuntimeEnvValue([name], lookup);
        if (value === undefined) throw new Error(`Slipway runtime env ${name} is required`);
        return value;
      }
    },
    status() {
      return runtimeStatus({
        home,
        startedAtMs,
        appId: options.appId,
        revision: options.revision,
        slipwayConfig,
        lockboxConfig,
        runtimeEnv,
        secretsStatus: secrets.status(),
        loggingStatus: logging.status()
      });
    },
    async whenReady() {
      const status = runtimeStatus({
        home,
        startedAtMs,
        appId: options.appId,
        revision: options.revision,
        slipwayConfig,
        lockboxConfig,
        runtimeEnv,
        secretsStatus: secrets.status(),
        loggingStatus: logging.status()
      });
      if (status.ready) return status;
      throw new SlipwayRuntimeNotReadyError(status);
    },
    async log(event, details = {}, logOptions = {}) {
      await logging.log(event, details, logOptions);
    },
    async flush() {
      return logging.flush();
    },
    stop() {
      refreshHandle?.stop();
      runtimeHealthHandle?.stop();
      secrets.stop();
    },
    async refreshNow() {
      const result = await refreshHandle?.refreshNow();
      if (result !== undefined) runtimeEnv = result;
      await secrets.refreshNow();
      await logging.refresh();
      return result;
    }
  };
}

export const bootstrapLiskovRuntime = bootstrapSlipwayRuntime;
export type BootstrapLiskovRuntimeOptions = BootstrapSlipwayRuntimeOptions;
export type BootstrapLiskovRuntimeHandle = BootstrapSlipwayRuntimeHandle;

type SlipwayRuntimeLogWriter = (event: string, details?: Record<string, unknown>) => Promise<void>;

type SlipwayRuntimeBufferedLog = BlackboxLogRecord & {
  severity: SlipwayRuntimeLogSeverity;
  labels?: Record<string, string>;
};

interface SlipwayRuntimeLoggingController {
  status(): SlipwayRuntimeCapabilityStatus;
  refresh(): Promise<number>;
  log(event: string, details?: Record<string, unknown>, options?: SlipwayRuntimeLogOptions): Promise<void>;
  flush(): Promise<SlipwayRuntimeFlushResult>;
}

const DEFAULT_SECRETS_RETRY_INITIAL_DELAY_MS = 0;
const DEFAULT_SECRETS_RETRY_INTERVAL_MS = 5_000;
const DEFAULT_SECRETS_RETRY_MAX_ELAPSED_MS = 60_000;
const DEFAULT_SECRETS_RETRY_MAX_ATTEMPTS = 12;

interface SlipwayRuntimeSecretsController {
  status(): SlipwayRuntimeCapabilityStatus;
  result(): LockboxRuntimeLoadResult | undefined;
  loadRequired(): Promise<LockboxRuntimeLoadResult | undefined>;
  startBackground(): void;
  refreshNow(): Promise<LockboxRuntimeLoadResult | undefined>;
  stop(): void;
}

interface NormalizedSecretsRetryOptions {
  initialDelayMs: number;
  intervalMs: number;
  maxElapsedMs: number;
  maxAttempts: number;
}

function createSlipwayRuntimeSecretsController(input: {
  env: Record<string, string | undefined>;
  mode: SlipwayRuntimeSecretMode;
  startedAtMs: number;
  config: ReturnType<typeof readLockboxRuntimeConfig>;
  retry?: SlipwayRuntimeSecretRetryOptions;
  identityProvider: RuntimeIdentityProvider;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  diagnostics: { emit(event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">): Promise<void> };
  lockboxDiagnostics: (event: LockboxRuntimeDiagnosticEvent) => void | Promise<void>;
  setTimeoutImpl?: typeof setTimeout;
  clearTimeoutImpl?: typeof clearTimeout;
  onLoaded?: (result: LockboxRuntimeLoadResult) => void | Promise<void>;
}): SlipwayRuntimeSecretsController {
  const retry = normalizeSecretsRetryOptions(input.retry);
  const setTimeoutImpl = input.setTimeoutImpl ?? setTimeout;
  const clearTimeoutImpl = input.clearTimeoutImpl ?? clearTimeout;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let result: LockboxRuntimeLoadResult | undefined;
  let loadPromise: Promise<LockboxRuntimeLoadResult | undefined> | undefined;
  let attempts = 0;
  let firstAttemptAtMs: number | undefined;
  let exhausted = false;
  let lastErrorMessage: string | undefined;

  function resultValue(): LockboxRuntimeLoadResult | undefined {
    return result;
  }

  async function loadRequired(): Promise<LockboxRuntimeLoadResult | undefined> {
    if (input.mode === "off") return undefined;
    if (!input.config) {
      const message = "Slipway required secrets config is not available";
      lastErrorMessage = message;
      exhausted = true;
      await emitSecretsDiagnostic({
        stage: "lockbox.secret_request",
        status: "failed",
        ok: false,
        code: "lockbox_config_missing",
        message,
        error: message
      });
      throw new Error(message);
    }
    return loadOnce({ throwOnFailure: true, scheduleRetry: false, manual: false });
  }

  function startBackground(): void {
    if (input.mode !== "background" || !input.config || stopped || result || timer) return;
    scheduleRetry(retry.initialDelayMs);
  }

  async function refreshNow(): Promise<LockboxRuntimeLoadResult | undefined> {
    if (input.mode === "off" || !input.config || stopped || result || exhausted) return result;
    clearScheduledTimer();
    return loadOnce({ throwOnFailure: input.mode === "required", scheduleRetry: input.mode === "background", manual: true });
  }

  async function loadOnce(options: {
    throwOnFailure: boolean;
    scheduleRetry: boolean;
    manual: boolean;
  }): Promise<LockboxRuntimeLoadResult | undefined> {
    if (!input.config || stopped || result) return result;
    if (loadPromise) return loadPromise;
    loadPromise = loadOnceUnshared(options).finally(() => {
      loadPromise = undefined;
    });
    return loadPromise;
  }

  async function loadOnceUnshared(options: {
    throwOnFailure: boolean;
    scheduleRetry: boolean;
    manual: boolean;
  }): Promise<LockboxRuntimeLoadResult | undefined> {
    attempts += 1;
    firstAttemptAtMs ??= nowMs();
    await emitSecretsDiagnostic({
      stage: "lockbox.secret_request",
      status: "started",
      ok: true,
      code: "lockbox_secret_request_started",
      attrs: compactDiagnosticAttrs({
        requestedSecretCount: input.config?.requestedSecretIds.length,
        attempt: attempts,
        maxAttempts: retry.maxAttempts,
        mode: input.mode,
        manual: options.manual
      })
    });
    try {
      const loaded = await loadLockboxRuntimeSecrets({
        identityProvider: input.identityProvider,
        config: input.config!,
        env: input.env,
        fetchImpl: input.fetchImpl,
        nowMs: input.nowMs,
        randomBytes: input.randomBytes,
        diagnostics: input.lockboxDiagnostics
      });
      result = loaded;
      exhausted = false;
      lastErrorMessage = undefined;
      clearScheduledTimer();
      const installedEnvCount = loaded.installed.env.length;
      const installedFileCount = loaded.installed.files.length;
      const skippedEnvCount = loaded.installed.skippedExistingEnv.length;
      const secretCount = installedEnvCount + installedFileCount;
      await emitSecretsDiagnostic({
        stage: "lockbox.secret_request",
        status: "succeeded",
        ok: true,
        code: "lockbox_secret_request_succeeded",
        valueCount: secretCount,
        attrs: compactDiagnosticAttrs({
          secretCount,
          installedEnvCount,
          installedFileCount,
          skippedEnvCount,
          attempt: attempts
        })
      });
      await input.onLoaded?.(loaded);
      return loaded;
    } catch (error) {
      lastErrorMessage = safeErrorMessage(error);
      const nextDelayMs = options.scheduleRetry ? nextRetryDelayMs() : undefined;
      exhausted = options.scheduleRetry && nextDelayMs === undefined;
      await emitSecretsDiagnostic({
        stage: nextDelayMs === undefined ? "lockbox.secret_request" : "lockbox.secret_request.retry",
        status: "failed",
        ok: false,
        code: nextDelayMs === undefined ? "lockbox_secret_request_failed" : "lockbox_secret_request_retrying",
        message: lastErrorMessage,
        error: lastErrorMessage,
        attrs: compactDiagnosticAttrs({
          attempt: attempts,
          maxAttempts: retry.maxAttempts,
          elapsedMs: nowMs() - (firstAttemptAtMs ?? nowMs()),
          nextDelayMs,
          mode: input.mode,
          manual: options.manual
        })
      });
      if (nextDelayMs !== undefined) scheduleRetry(nextDelayMs);
      if (options.throwOnFailure) throw error;
      return undefined;
    }
  }

  function status(): SlipwayRuntimeCapabilityStatus {
    if (input.mode === "off") {
      return capabilityStatus({
        state: "off",
        required: false,
        sinceMs: input.startedAtMs
      });
    }
    if (!input.config) {
      const required = input.mode === "required";
      return capabilityStatus({
        state: required ? "failed" : "off",
        required,
        sinceMs: input.startedAtMs,
        code: required ? "lockbox_config_missing" : undefined,
        message: required ? "Slipway required secrets config is not available" : undefined
      });
    }
    const secretCount = result
      ? result.installed.env.length + result.installed.files.length
      : undefined;
    if (result) {
      return capabilityStatus({
        state: "ready",
        required: input.mode === "required",
        sinceMs: input.startedAtMs,
        valueCount: secretCount
      });
    }
    if (lastErrorMessage && exhausted) {
      return capabilityStatus({
        state: input.mode === "required" ? "failed" : "failed",
        required: input.mode === "required",
        sinceMs: input.startedAtMs,
        code: "lockbox_secret_request_failed",
        message: lastErrorMessage
      });
    }
    if (lastErrorMessage) {
      return capabilityStatus({
        state: input.mode === "required" ? "failed" : "degraded",
        required: input.mode === "required",
        sinceMs: input.startedAtMs,
        code: input.mode === "required" ? "lockbox_secret_request_failed" : "lockbox_secret_request_retrying",
        message: lastErrorMessage
      });
    }
    return capabilityStatus({
      state: "pending",
      required: input.mode === "required",
      sinceMs: input.startedAtMs,
      code: "lockbox_secret_request_pending",
      message: "Slipway secrets have not been installed yet"
    });
  }

  function nextRetryDelayMs(): number | undefined {
    if (attempts >= retry.maxAttempts) return undefined;
    const elapsedMs = nowMs() - (firstAttemptAtMs ?? nowMs());
    if (elapsedMs + retry.intervalMs > retry.maxElapsedMs) return undefined;
    return retry.intervalMs;
  }

  function scheduleRetry(delayMs: number): void {
    if (stopped || result || input.mode !== "background" || !input.config || exhausted) return;
    clearScheduledTimer();
    timer = setTimeoutImpl(() => {
      timer = undefined;
      void loadOnce({ throwOnFailure: false, scheduleRetry: true, manual: false });
    }, delayMs);
    timer.unref?.();
  }

  function clearScheduledTimer(): void {
    if (!timer) return;
    clearTimeoutImpl(timer);
    timer = undefined;
  }

  function nowMs(): number {
    return input.nowMs?.() ?? Date.now();
  }

  async function emitSecretsDiagnostic(
    event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">
  ): Promise<void> {
    await input.diagnostics.emit({
      phase: "lockbox_secrets",
      component: "runtime-secrets",
      ...event
    });
  }

  return {
    status,
    result: resultValue,
    loadRequired,
    startBackground,
    refreshNow,
    stop() {
      stopped = true;
      clearScheduledTimer();
    }
  };
}

function normalizeSecretsRetryOptions(
  retry: SlipwayRuntimeSecretRetryOptions | undefined
): NormalizedSecretsRetryOptions {
  const initialDelayMs = nonNegativeInteger(retry?.initialDelayMs) ?? DEFAULT_SECRETS_RETRY_INITIAL_DELAY_MS;
  const intervalMs = nonNegativeInteger(retry?.intervalMs) ?? DEFAULT_SECRETS_RETRY_INTERVAL_MS;
  const maxElapsedMs = nonNegativeInteger(retry?.maxElapsedMs) ?? DEFAULT_SECRETS_RETRY_MAX_ELAPSED_MS;
  const maxAttempts = positiveInteger(retry?.maxAttempts) ?? DEFAULT_SECRETS_RETRY_MAX_ATTEMPTS;
  return { initialDelayMs, intervalMs, maxElapsedMs, maxAttempts };
}

function nonNegativeInteger(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return Math.max(0, Math.floor(value));
}

function positiveInteger(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return Math.max(1, Math.floor(value));
}

function createSlipwayRuntimeLoggingController(input: {
  env: Record<string, string | undefined>;
  std?: AcurastRuntimeStd;
  mode: SlipwayRuntimeLoggingMode;
  required: boolean;
  startedAtMs: number;
  earlyBufferMaxRecords: number;
  fetchImpl?: typeof fetch;
  spoolMode?: SlipwayRuntimeLoggingSpoolMode;
  spoolDir?: string;
  timeoutMs?: number;
  nowMs?: () => number;
  onError?: (error: unknown, event: string) => void;
  diagnostics: { emit(event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">): Promise<void> };
  allowHostnames(hostnames: string[]): Promise<void>;
  baseRecord?: () => Record<string, unknown>;
}): SlipwayRuntimeLoggingController {
  const getConfigValue = (name: string) => input.env[name];
  const earlyLogs: SlipwayRuntimeBufferedLog[] = [];
  let droppedEarlyLogs = 0;
  let logger: SlipwayRuntimeLogWriter | undefined;
  let attachedFingerprint: string | undefined;
  let attachErrorCode: string | undefined;
  let attachErrorMessage: string | undefined;
  let writeErrorMessage: string | undefined;
  let writeErrorCount = 0;
  let refreshPromise: Promise<number> | undefined;
  let drainPromise: Promise<number> | undefined;

  const currentFingerprint = () => blackboxLogConfigFingerprint(getConfigValue);

  async function refresh(): Promise<number> {
    if (input.mode === "off") return 0;
    refreshPromise ??= refreshOnce().finally(() => {
      refreshPromise = undefined;
    });
    return refreshPromise;
  }

  async function refreshOnce(): Promise<number> {
    const fingerprint = currentFingerprint();
    if (!fingerprint) {
      logger = undefined;
      attachedFingerprint = undefined;
      attachErrorCode = undefined;
      attachErrorMessage = undefined;
      return 0;
    }
    if (logger && attachedFingerprint === fingerprint) {
      return drainEarlyLogs();
    }
    logger = undefined;
    attachedFingerprint = undefined;
    attachErrorCode = undefined;
    attachErrorMessage = undefined;
    writeErrorMessage = undefined;
    await attachLogger(fingerprint);
    return drainEarlyLogs();
  }

  async function attachLogger(fingerprint: string): Promise<void> {
    await emitLoggingDiagnostic({
      stage: "slipway.logging.attach",
      status: "started",
      ok: true,
      code: "slipway_logging_attach_started",
      attrs: compactDiagnosticAttrs({ fingerprint })
    });
    try {
      readBlackboxLogConfig(getConfigValue);
    } catch (error) {
      recordAttachError("slipway_logging_config_invalid", error);
      return;
    }

    let signer: ReturnType<typeof maybeAcurastBlackboxRequestSigner>;
    try {
      signer = maybeAcurastBlackboxRequestSigner(input.std);
    } catch (error) {
      recordAttachError("slipway_logging_attach_failed", error);
      return;
    }
    if (!signer) {
      recordAttachError("slipway_logging_attach_failed", new Error("Slipway logging requires the Acurast Ed25519 runtime signer"));
      return;
    }

    try {
      await input.allowHostnames(blackboxLogHostnames(getConfigValue));
      logger = createBlackboxRemoteLogger({
        getConfigValue,
        signer,
        fetchImpl: input.fetchImpl,
        timeoutMs: input.timeoutMs,
        std: input.std,
        spoolMode: input.spoolMode,
        spoolDir: input.spoolDir,
        baseRecord: input.baseRecord,
        onError(error, event) {
          recordWriteError(error, event);
        }
      });
      attachedFingerprint = fingerprint;
      attachErrorCode = undefined;
      attachErrorMessage = undefined;
      await emitLoggingDiagnostic({
        stage: "slipway.logging.attach",
        status: "succeeded",
        ok: true,
        code: "slipway_logging_attached",
        attrs: compactDiagnosticAttrs({ fingerprint })
      });
    } catch (error) {
      recordAttachError("slipway_logging_attach_failed", error);
    }
  }

  function recordAttachError(code: string, error: unknown): void {
    attachErrorCode = code;
    attachErrorMessage = safeErrorMessage(error);
    void emitLoggingDiagnostic({
      stage: "slipway.logging.attach",
      status: "failed",
      ok: false,
      code,
      message: attachErrorMessage,
      error: attachErrorMessage,
      attrs: compactDiagnosticAttrs({ fingerprint: currentFingerprint() })
    });
  }

  function recordWriteError(error: unknown, event: string): void {
    writeErrorCount += 1;
    writeErrorMessage = safeErrorMessage(error);
    try {
      input.onError?.(error, event);
    } catch {
      // User logging callbacks are observability hooks and must not break the
      // runtime wrapper.
    }
    void emitLoggingDiagnostic({
      stage: "slipway.logging.write",
      status: "failed",
      ok: false,
      code: "slipway_logging_write_failed",
      message: writeErrorMessage,
      error: writeErrorMessage,
      attrs: compactDiagnosticAttrs({ event, fingerprint: attachedFingerprint ?? currentFingerprint() })
    });
  }

  async function emitLoggingDiagnostic(
    event: Omit<SlipwayRuntimeDiagnostic, "sequence" | "timestampMs">
  ): Promise<void> {
    await input.diagnostics.emit({
      phase: "slipway_logging",
      component: "runtime-logging",
      ...event
    });
  }

  function bufferLog(record: SlipwayRuntimeBufferedLog): void {
    if (earlyLogs.length >= input.earlyBufferMaxRecords) {
      droppedEarlyLogs += 1;
      void emitLoggingDiagnostic({
        stage: "slipway.logging.buffer",
        status: "failed",
        ok: false,
        code: "slipway_logging_buffer_dropped",
        message: "Slipway logging early buffer is full",
        attrs: compactDiagnosticAttrs({
          event: record.event,
          earlyBufferMaxRecords: input.earlyBufferMaxRecords
        })
      });
      return;
    }
    earlyLogs.push(record);
  }

  async function writeRecord(record: SlipwayRuntimeBufferedLog): Promise<boolean> {
    if (!logger) return false;
    const errorsBefore = writeErrorCount;
    try {
      await logger(record.event, detailsForBufferedLog(record));
    } catch (error) {
      recordWriteError(error, record.event);
      return false;
    }
    if (writeErrorCount === errorsBefore) {
      writeErrorMessage = undefined;
      return true;
    }
    return false;
  }

  async function drainEarlyLogs(): Promise<number> {
    if (!logger || earlyLogs.length === 0) return 0;
    drainPromise ??= drainEarlyLogsOnce().finally(() => {
      drainPromise = undefined;
    });
    return drainPromise;
  }

  async function drainEarlyLogsOnce(): Promise<number> {
    let flushed = 0;
    while (logger && earlyLogs.length > 0) {
      const record = earlyLogs.shift()!;
      await writeRecord(record);
      flushed += 1;
    }
    if (flushed > 0) {
      await emitLoggingDiagnostic({
        stage: "slipway.logging.buffer",
        status: "succeeded",
        ok: true,
        code: "slipway_logging_buffer_drained",
        valueCount: flushed,
        attrs: compactDiagnosticAttrs({ fingerprint: attachedFingerprint })
      });
    }
    return flushed;
  }

  function status(): SlipwayRuntimeCapabilityStatus {
    const fingerprint = currentFingerprint();
    if (input.mode === "off") {
      return capabilityStatus({
        state: "off",
        required: false,
        sinceMs: input.startedAtMs,
        fingerprint,
        valueCount: earlyLogs.length
      });
    }
    if (!fingerprint) {
      const hasBufferedRecords = earlyLogs.length > 0 || droppedEarlyLogs > 0;
      return capabilityStatus({
        state: input.required || hasBufferedRecords ? "pending" : "off",
        required: input.required,
        sinceMs: input.startedAtMs,
        fingerprint,
        valueCount: earlyLogs.length,
        code: input.required || hasBufferedRecords ? "slipway_logging_config_missing" : undefined,
        message: input.required || hasBufferedRecords
          ? "Slipway logging config is not available yet"
          : undefined
      });
    }
    if (attachErrorMessage) {
      return capabilityStatus({
        state: input.required ? "failed" : "degraded",
        required: input.required,
        sinceMs: input.startedAtMs,
        fingerprint,
        valueCount: earlyLogs.length,
        code: attachErrorCode ?? "slipway_logging_attach_failed",
        message: attachErrorMessage
      });
    }
    if (!logger || attachedFingerprint !== fingerprint) {
      return capabilityStatus({
        state: "pending",
        required: input.required,
        sinceMs: input.startedAtMs,
        fingerprint,
        valueCount: earlyLogs.length,
        code: "slipway_logging_attach_pending",
        message: "Slipway logging config changed and has not been attached yet"
      });
    }
    if (writeErrorMessage) {
      return capabilityStatus({
        state: input.required ? "failed" : "degraded",
        required: input.required,
        sinceMs: input.startedAtMs,
        fingerprint,
        valueCount: earlyLogs.length,
        code: "slipway_logging_write_failed",
        message: writeErrorMessage
      });
    }
    if (droppedEarlyLogs > 0) {
      return capabilityStatus({
        state: input.required ? "failed" : "degraded",
        required: input.required,
        sinceMs: input.startedAtMs,
        fingerprint,
        valueCount: earlyLogs.length,
        code: "slipway_logging_buffer_dropped",
        message: "Slipway logging dropped early records before attach"
      });
    }
    return capabilityStatus({
      state: "ready",
      required: input.required,
      sinceMs: input.startedAtMs,
      fingerprint,
      valueCount: earlyLogs.length
    });
  }

  return {
    status,
    refresh,
    async log(event, details = {}, options = {}) {
      if (input.mode === "off") return;
      await refresh();
      const record: SlipwayRuntimeBufferedLog = {
        timestamp: new Date(input.nowMs?.() ?? Date.now()).toISOString(),
        event,
        details,
        severity: options.severity ?? "info",
        labels: options.labels
      };
      if (logger && attachedFingerprint === currentFingerprint()) {
        await writeRecord(record);
        return;
      }
      bufferLog(record);
    },
    async flush() {
      const errorsBefore = writeErrorCount;
      const flushedFromRefresh = await refresh();
      const flushed = flushedFromRefresh + await drainEarlyLogs();
      const currentStatus = status();
      const okState = currentStatus.state === "ready" || currentStatus.state === "off";
      return {
        ok: okState && earlyLogs.length === 0 && droppedEarlyLogs === 0 && writeErrorCount === errorsBefore,
        state: currentStatus.state,
        flushed,
        pending: earlyLogs.length,
        dropped: droppedEarlyLogs,
        message: currentStatus.message
      };
    }
  };
}

function detailsForBufferedLog(record: SlipwayRuntimeBufferedLog): Record<string, unknown> {
  return {
    ...(record.details ?? {}),
    _slipwayRuntime: compactRuntimeRecord({
      loggedAt: record.timestamp,
      severity: record.severity,
      labels: record.labels
    })
  };
}

function runtimeStatus(input: {
  home: string;
  startedAtMs: number;
  appId?: string;
  revision?: string;
  slipwayConfig: ReturnType<typeof readSlipwayRuntimeEnvConfig>;
  lockboxConfig: ReturnType<typeof readLockboxRuntimeConfig>;
  runtimeEnv?: SlipwayRuntimeEnvLoadResult;
  secretsStatus: SlipwayRuntimeCapabilityStatus;
  loggingStatus: SlipwayRuntimeCapabilityStatus;
}): SlipwayRuntimeStatus {
  const runtimeEnvStatus = capabilityStatus({
    state: input.slipwayConfig === undefined ? "off" : input.runtimeEnv ? "ready" : "pending",
    required: input.slipwayConfig !== undefined,
    sinceMs: input.startedAtMs,
    revision: input.runtimeEnv?.response.revision,
    valueCount: input.runtimeEnv ? Object.keys(input.runtimeEnv.installed).length : undefined
  });
  const diagnosticsStatus = capabilityStatus({
    state: "ready",
    required: false,
    sinceMs: input.startedAtMs
  });
  const switchboardStatus = capabilityStatus({
    state: "off",
    required: false,
    sinceMs: input.startedAtMs
  });
  const capabilities = {
    runtimeEnv: runtimeEnvStatus,
    secrets: input.secretsStatus,
    logging: input.loggingStatus,
    diagnostics: diagnosticsStatus,
    switchboard: switchboardStatus
  };
  const blockers = readinessBlockers(capabilities);
  return {
    ok: blockers.length === 0,
    ready: blockers.length === 0,
    home: input.home,
    applicationId: input.appId ?? input.runtimeEnv?.response.applicationId ?? input.slipwayConfig?.applicationId ?? input.lockboxConfig?.applicationId,
    deploymentId: input.runtimeEnv?.response.deploymentId ?? input.slipwayConfig?.deploymentId ?? input.lockboxConfig?.deploymentId,
    revision: input.revision ?? input.runtimeEnv?.response.revision,
    blockers,
    capabilities
  };
}

function capabilityStatus(input: SlipwayRuntimeCapabilityStatus): SlipwayRuntimeCapabilityStatus {
  return input;
}

function readinessBlockers(
  capabilities: SlipwayRuntimeCapabilityMap
): SlipwayRuntimeStatus["blockers"] {
  return Object.entries(capabilities)
    .filter(([, status]) => status.required && status.state !== "ready")
    .map(([capability, status]) => ({
      capability: capability as keyof SlipwayRuntimeCapabilityMap,
      code: status.code ?? `${capability}_not_ready`,
      message: status.message ?? `${capability} is ${status.state}`
    }));
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

function compactRuntimeRecord(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => value !== undefined));
}

function compactDiagnosticAttrs(
  input: Record<string, string | number | boolean | null | undefined>
): Record<string, string | number | boolean | null> | undefined {
  const attrs = Object.fromEntries(
    Object.entries(input).filter(([, value]) => value !== undefined)
  ) as Record<string, string | number | boolean | null>;
  return Object.keys(attrs).length > 0 ? attrs : undefined;
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
  void std;
  void hostnames;
  // Acurast hostname allowlisting requires deployment-owner DNS TXT records for
  // both forward and reverse DNS. Do not call it until those records are
  // explicitly provisioned for the Liskov domains.
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
