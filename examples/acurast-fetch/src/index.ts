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

export interface AcurastFetchExampleOptions {
  bootstrapSlipwayRuntime?: BootstrapSlipwayRuntime;
  runtimeOptions?: Record<string, unknown>;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  stdout?: (line: string) => void;
  webhookUrl?: string;
  priceUrl?: string;
  symbol?: string;
  targetCurrency?: string;
}

export interface AcurastFetchExampleResult {
  ok: true;
  webhookStatus: number;
  symbol: string;
  targetCurrency: string;
  price: number;
}

const DEFAULT_PRICE_BASE_URL = "https://min-api.cryptocompare.com";
const DYNAMIC_IMPORT = new Function("specifier", "return import(specifier)") as <T>(
  specifier: string
) => Promise<T>;

export async function runAcurastFetchExample(
  options: AcurastFetchExampleOptions = {}
): Promise<AcurastFetchExampleResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const stdout = options.stdout ?? console.log;
  const bootstrapSlipwayRuntime =
    options.bootstrapSlipwayRuntime ?? await loadBootstrapSlipwayRuntime();
  const runtime = await bootstrapSlipwayRuntime({
    component: "acurast-fetch",
    fetchImpl,
    ...options.runtimeOptions
  });

  try {
    await runtime.whenReady();
    const symbol = options.symbol ?? runtime.env.get("PRICE_SYMBOL") ?? "BTC";
    const targetCurrency = options.targetCurrency ?? runtime.env.get("PRICE_TARGET_CURRENCY") ?? "USD";
    const priceUrl = options.priceUrl ?? runtime.env.get("PRICE_URL") ?? priceUrlFromRuntime(runtime, symbol, targetCurrency);
    const webhookUrl = options.webhookUrl ?? runtime.env.get("WEBHOOK_URL");
    if (!webhookUrl) {
      throw new Error("WEBHOOK_URL is required for the Slipway fetch example");
    }

    const priceResponse = await fetchImpl(priceUrl);
    const priceBody = await priceResponse.json() as Record<string, unknown>;
    const price = Number(priceBody[targetCurrency]);
    if (!Number.isFinite(price)) {
      throw new Error(`Price response did not include numeric ${targetCurrency}`);
    }

    const webhookResponse = await fetchImpl(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        timestamp: options.nowMs?.() ?? Date.now(),
        example: "acurast-fetch",
        runtime: runtimeSummary(runtime),
        price: {
          symbol,
          targetCurrency,
          value: price
        }
      })
    });

    const result: AcurastFetchExampleResult = {
      ok: true,
      webhookStatus: webhookResponse.status,
      symbol,
      targetCurrency,
      price
    };
    await runtime.log("example.fetch.posted", {
      priceHost: new URL(priceUrl).hostname,
      webhookHost: new URL(webhookUrl).hostname,
      webhookStatus: webhookResponse.status,
      symbol,
      targetCurrency
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

function priceUrlFromRuntime(runtime: SlipwayRuntimeHandle, symbol: string, targetCurrency: string): string {
  const baseUrl = runtime.env.get("PRICE_BASE_URL") ?? DEFAULT_PRICE_BASE_URL;
  return `${baseUrl.replace(/\/+$/u, "")}/data/price?fsym=${encodeURIComponent(symbol)}&tsyms=${encodeURIComponent(targetCurrency)}`;
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

function isDirectRun(): boolean {
  return Boolean(process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);
}

if (isDirectRun()) {
  runAcurastFetchExample().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
