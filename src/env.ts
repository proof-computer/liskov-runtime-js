export interface AcurastRuntimeStd {
  env?: Record<string, string | undefined>;
  job?: {
    getId?: () => unknown;
    getPublicKeys?: () => unknown;
    getEncryptionKeys?: () => unknown;
  };
  device?: {
    getAddress?: () => unknown;
  };
  signers?: {
    ed25519?: {
      sign?: (payloadHex: string) => string | Promise<string>;
    };
    secp256r1?: {
      encrypt?: (publicKey: string, salt: string, plaintext: string) => string | Promise<string>;
      decrypt?: (publicKey: string, salt: string, ciphertext: string) => string | Promise<string>;
    };
  };
}

export interface RuntimeEnvLookupOptions {
  env?: Record<string, string | undefined>;
  std?: AcurastRuntimeStd;
  environment?: (name: string) => unknown;
}

export function resolveRuntimeStd(std?: AcurastRuntimeStd): AcurastRuntimeStd | undefined {
  return std ?? (globalThis as { _STD_?: AcurastRuntimeStd })._STD_;
}

export function getRuntimeEnvValue(name: string, options: RuntimeEnvLookupOptions = {}): string | undefined {
  const processValue = (options.env ?? process.env)[name];
  if (typeof processValue === "string" && processValue.length > 0) return processValue;

  const stdValue = resolveRuntimeStd(options.std)?.env?.[name];
  if (typeof stdValue === "string" && stdValue.length > 0) return stdValue;

  const environment = options.environment ?? (globalThis as { environment?: (name: string) => unknown }).environment;
  if (typeof environment === "function") {
    const value = environment(name);
    if (typeof value === "string" && value.length > 0) return value;
    if (value !== undefined && value !== null && typeof value !== "object") return String(value);
  }
  return undefined;
}

export function requiredRuntimeEnvValue(name: string, options: RuntimeEnvLookupOptions = {}): string {
  const value = getRuntimeEnvValue(name, options);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

export function getFirstRuntimeEnvValue(names: readonly string[], options: RuntimeEnvLookupOptions = {}): string | undefined {
  for (const name of names) {
    const value = getRuntimeEnvValue(name, options);
    if (value !== undefined) return value;
  }
  return undefined;
}

export function optionalBooleanEnv(name: string, options: RuntimeEnvLookupOptions = {}): boolean | undefined {
  const value = getRuntimeEnvValue(name, options);
  if (value === undefined) return undefined;
  if (value === "1" || value.toLowerCase() === "true") return true;
  if (value === "0" || value.toLowerCase() === "false") return false;
  return undefined;
}

export function optionalIntegerEnv(name: string, options: RuntimeEnvLookupOptions = {}): number | undefined {
  const value = getRuntimeEnvValue(name, options);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

export function optionalNonNegativeIntegerEnv(name: string, options: RuntimeEnvLookupOptions = {}): number | undefined {
  const value = getRuntimeEnvValue(name, options);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}
