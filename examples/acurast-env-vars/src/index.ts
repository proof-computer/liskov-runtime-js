import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export interface SlipwayRuntimeEnvAccessor {
  get(name: string): string | undefined;
  require?(name: string): string;
}

export interface SlipwayRuntimeHandle {
  env: SlipwayRuntimeEnvAccessor;
  status(): {
    ready?: unknown;
    applicationId?: unknown;
    deploymentId?: unknown;
    revision?: unknown;
  };
  whenReady(): Promise<unknown>;
  log(event: string, details?: Record<string, unknown>, options?: Record<string, unknown>): Promise<void> | void;
  flush?(): Promise<unknown>;
  stop(): void;
}

export type BootstrapSlipwayRuntime = (options?: Record<string, unknown>) => Promise<SlipwayRuntimeHandle>;

export interface AcurastRuntimeStdLike {
  net?: {
    addAllowedHostnames?: (hostnames: string[]) => unknown;
  };
}

export interface AcurastEnvVarsExampleOptions {
  bootstrapSlipwayRuntime?: BootstrapSlipwayRuntime;
  runtimeOptions?: Record<string, unknown>;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  stdout?: (line: string) => void;
  webhookUrl?: string;
  envName?: string;
  std?: AcurastRuntimeStdLike;
}

export interface AcurastEnvVarsExampleResult {
  ok: true;
  webhookStatus: number;
  env: {
    name: string;
    present: boolean;
    digest?: string;
  };
}

const DYNAMIC_IMPORT = new Function("specifier", "return import(specifier)") as <T>(
  specifier: string
) => Promise<T>;

export async function runAcurastEnvVarsExample(
  options: AcurastEnvVarsExampleOptions = {}
): Promise<AcurastEnvVarsExampleResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const stdout = options.stdout ?? console.log;
  const bootstrapSlipwayRuntime =
    options.bootstrapSlipwayRuntime ?? await loadBootstrapSlipwayRuntime();
  const runtime = await bootstrapSlipwayRuntime({
    component: "acurast-env-vars",
    fetchImpl,
    ...options.runtimeOptions
  });

  try {
    await runtime.whenReady();
    const envName = options.envName ?? "MY_SECRET_ENV_VAR";
    const webhookUrl = options.webhookUrl ?? runtime.env.get("WEBHOOK_URL");
    if (!webhookUrl) {
      throw new Error("WEBHOOK_URL is required for the Slipway env-vars example");
    }

    await allowHostnames(resolveStd(options), [webhookUrl]);
    const secretValue = runtime.env.get(envName);
    const envSummary = redactedEnvSummary(envName, secretValue);
    const response = await fetchImpl(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        timestamp: options.nowMs?.() ?? Date.now(),
        example: "acurast-env-vars",
        runtime: runtimeSummary(runtime),
        env: envSummary
      })
    });

    const result: AcurastEnvVarsExampleResult = {
      ok: true,
      webhookStatus: response.status,
      env: envSummary
    };
    await runtime.log("example.env-vars.posted", {
      webhookHost: new URL(webhookUrl).hostname,
      webhookStatus: response.status,
      env: envSummary
    });
    stdout(JSON.stringify(result));
    return result;
  } finally {
    await runtime.flush?.();
    runtime.stop();
  }
}

async function loadBootstrapSlipwayRuntime(): Promise<BootstrapSlipwayRuntime> {
  const module = await DYNAMIC_IMPORT<{ bootstrapSlipwayRuntime?: BootstrapSlipwayRuntime }>(
    "@proof-computer/slipway-runtime"
  );
  if (typeof module.bootstrapSlipwayRuntime !== "function") {
    throw new Error("@proof-computer/slipway-runtime did not export bootstrapSlipwayRuntime");
  }
  return module.bootstrapSlipwayRuntime;
}

function redactedEnvSummary(name: string, value: string | undefined): AcurastEnvVarsExampleResult["env"] {
  if (value === undefined) {
    return { name, present: false };
  }
  return {
    name,
    present: true,
    digest: `sha256:${createHash("sha256").update(value).digest("hex")}`
  };
}

function runtimeSummary(runtime: SlipwayRuntimeHandle): Record<string, unknown> {
  const status = runtime.status();
  return {
    ready: status.ready,
    applicationId: status.applicationId,
    deploymentId: status.deploymentId,
    revision: status.revision
  };
}

async function allowHostnames(std: AcurastRuntimeStdLike | undefined, urls: string[]): Promise<void> {
  const hostnames = [...new Set(urls.map((url) => hostnameOrUndefined(url)).filter(isString))];
  if (hostnames.length === 0 || typeof std?.net?.addAllowedHostnames !== "function") {
    return;
  }
  await Promise.resolve(std.net.addAllowedHostnames(hostnames));
}

function resolveStd(options: AcurastEnvVarsExampleOptions): AcurastRuntimeStdLike | undefined {
  return options.std ??
    (options.runtimeOptions?.std as AcurastRuntimeStdLike | undefined) ??
    (globalThis as { _STD_?: AcurastRuntimeStdLike })._STD_;
}

function hostnameOrUndefined(rawUrl: string): string | undefined {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return undefined;
  }
}

function isString(value: string | undefined): value is string {
  return typeof value === "string" && value.length > 0;
}

function isDirectRun(): boolean {
  return Boolean(process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);
}

if (isDirectRun()) {
  runAcurastEnvVarsExample().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
