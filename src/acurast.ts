import { Buffer } from "node:buffer";

import {
  getFirstRuntimeEnvValue,
  resolveRuntimeStd,
  type AcurastRuntimeStd,
  type RuntimeEnvLookupOptions
} from "./env.js";
import {
  normalizeHex,
  normalizeHexNoPrefix,
  requireNonEmpty,
  stripHexPrefix
} from "./shared.js";

export interface RuntimeIdentity {
  jobId: string;
  processorId: string;
  responseEncryptionKey?: string;
}

export interface RuntimeIdentityProvider {
  resolveIdentity(options?: { requireEncryptionKey?: boolean }): Promise<RuntimeIdentity>;
  sign(message: Uint8Array): Promise<string>;
  decryptGrantPayload(encrypted: {
    senderPublicKey: string;
    saltHex: string;
    ciphertextHex: string;
  }): Promise<Uint8Array>;
}

export interface AcurastRuntimeAdapterOptions extends RuntimeEnvLookupOptions {
  jobIdEnvNames?: readonly string[];
  processorIdEnvNames?: readonly string[];
  encryptionKeyEnvNames?: readonly string[];
}

export const DEFAULT_JOB_ID_ENV_NAMES = [
  "ACURAST_JOB_ID",
  "PROOF_ACURAST_JOB_ID",
  "SWITCHBOARD_MANAGED_JOB_ID"
] as const;

export const DEFAULT_PROCESSOR_ID_ENV_NAMES = [
  "ACURAST_PROCESSOR_ID",
  "ACURAST_PROCESSOR_ADDRESS",
  "PROOF_ACURAST_PROCESSOR_ID",
  "SWITCHBOARD_MANAGED_PROCESSOR_ID"
] as const;

export const DEFAULT_ENCRYPTION_KEY_ENV_NAMES = [
  "ACURAST_ENCRYPTION_PUBLIC_KEY",
  "PROOF_ACURAST_ENCRYPTION_PUBLIC_KEY",
  "SWITCHBOARD_MANAGED_ENCRYPTION_PUBLIC_KEY"
] as const;

const P256_ENCRYPTION_KEY_PRIME_PUBLIC_KEY =
  "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

export function createAcurastRuntimeAdapter(options: AcurastRuntimeAdapterOptions = {}): RuntimeIdentityProvider {
  return {
    async resolveIdentity(resolveOptions) {
      return resolveAcurastRuntimeIdentityAsync(options, resolveOptions);
    },
    async sign(message) {
      return signAcurastRuntimeMessage(options, message);
    },
    async decryptGrantPayload(encrypted) {
      return decryptAcurastRuntimePayload(options, encrypted);
    }
  };
}

export async function resolveAcurastRuntimeIdentityAsync(
  options: AcurastRuntimeAdapterOptions = {},
  resolveOptions: { requireEncryptionKey?: boolean } = {}
): Promise<RuntimeIdentity> {
  const std = resolveRuntimeStd(options.std);
  if (resolveOptions.requireEncryptionKey === true) {
    await primeAcurastEncryptionKeys(std);
  }
  return resolveAcurastRuntimeIdentityFromStd(std, options, resolveOptions);
}

export function resolveAcurastRuntimeIdentity(
  options: AcurastRuntimeAdapterOptions = {},
  resolveOptions: { requireEncryptionKey?: boolean } = {}
): RuntimeIdentity {
  const std = resolveRuntimeStd(options.std);
  if (resolveOptions.requireEncryptionKey === true) {
    primeAcurastEncryptionKeysBestEffort(std);
  }
  return resolveAcurastRuntimeIdentityFromStd(std, options, resolveOptions);
}

function resolveAcurastRuntimeIdentityFromStd(
  std: AcurastRuntimeStd | undefined,
  options: AcurastRuntimeAdapterOptions,
  resolveOptions: { requireEncryptionKey?: boolean }
): RuntimeIdentity {
  const jobId =
    getFirstRuntimeEnvValue(options.jobIdEnvNames ?? DEFAULT_JOB_ID_ENV_NAMES, options) ??
    stringifyRuntimeValue(std?.job?.getId?.());
  const processorId =
    getFirstRuntimeEnvValue(options.processorIdEnvNames ?? DEFAULT_PROCESSOR_ID_ENV_NAMES, options) ??
    stringifyRuntimeValue(std?.device?.getAddress?.());

  if (!jobId) throw new Error("Acurast job id is required for Slipway runtime bootstrap");
  if (!processorId) throw new Error("Acurast processor id is required for Slipway runtime bootstrap");

  const identity: RuntimeIdentity = { jobId, processorId };
  if (resolveOptions.requireEncryptionKey === true) {
    const responseEncryptionKey =
      getFirstRuntimeEnvValue(options.encryptionKeyEnvNames ?? DEFAULT_ENCRYPTION_KEY_ENV_NAMES, options) ??
      encryptionKeyFromStd(std);
    if (!responseEncryptionKey) {
      throw new Error("Acurast response encryption key is required for Lockbox bootstrap");
    }
    identity.responseEncryptionKey = normalizeHexNoPrefix(responseEncryptionKey);
  }
  return identity;
}

export interface AcurastEncryptionKeyPrimeResult {
  attempted: boolean;
  ok: boolean;
  errorMessage?: string;
}

export async function primeAcurastEncryptionKeys(
  std: AcurastRuntimeStd | undefined = resolveRuntimeStd()
): Promise<AcurastEncryptionKeyPrimeResult> {
  const encrypt = std?.signers?.secp256r1?.encrypt;
  if (typeof encrypt !== "function") return { attempted: false, ok: false };
  try {
    await Promise.resolve(encrypt.call(std?.signers?.secp256r1, P256_ENCRYPTION_KEY_PRIME_PUBLIC_KEY, "00", "00"));
    return { attempted: true, ok: true };
  } catch (error) {
    return { attempted: true, ok: false, errorMessage: error instanceof Error ? error.message : String(error) };
  }
}

function primeAcurastEncryptionKeysBestEffort(std: AcurastRuntimeStd | undefined): void {
  const encrypt = std?.signers?.secp256r1?.encrypt;
  if (typeof encrypt !== "function") return;
  try {
    const result = encrypt.call(std?.signers?.secp256r1, P256_ENCRYPTION_KEY_PRIME_PUBLIC_KEY, "00", "00");
    if (typeof (result as Promise<string> | undefined)?.catch === "function") {
      void (result as Promise<string>).catch(() => undefined);
    }
  } catch {
    // Key priming is best-effort for the legacy synchronous helper. The async
    // adapter path reports the real failure if the key is still unavailable.
  }
}

export async function signAcurastRuntimeMessage(
  options: { std?: AcurastRuntimeStd } = {},
  message: Uint8Array
): Promise<string> {
  const std = resolveRuntimeStd(options.std);
  const sign = std?.signers?.ed25519?.sign;
  if (typeof sign !== "function") throw new Error("Acurast Ed25519 signer is required for Slipway runtime bootstrap");
  const signature = await Promise.resolve(sign.call(std?.signers?.ed25519, Buffer.from(message).toString("hex")));
  return normalizeHex(signature);
}

export async function decryptAcurastRuntimePayload(
  options: { std?: AcurastRuntimeStd } = {},
  encrypted: { senderPublicKey: string; saltHex: string; ciphertextHex: string }
): Promise<Uint8Array> {
  const std = resolveRuntimeStd(options.std);
  const decrypt = std?.signers?.secp256r1?.decrypt;
  if (typeof decrypt !== "function") throw new Error("Acurast secp256r1 decrypt is required for Lockbox bootstrap");
  const plaintextHex = await Promise.resolve(decrypt.call(
    std?.signers?.secp256r1,
    encrypted.senderPublicKey,
    encrypted.saltHex,
    encrypted.ciphertextHex
  ));
  return Buffer.from(stripHexPrefix(normalizeHex(plaintextHex)), "hex");
}

export function acurastEd25519PublicKey(std: AcurastRuntimeStd | undefined = resolveRuntimeStd()): string {
  const publicKeys = std?.job?.getPublicKeys?.();
  const parsed = typeof publicKeys === "string" ? parsePublicKeys(publicKeys) : publicKeys;
  const key = (parsed as { ed25519?: unknown } | null | undefined)?.ed25519;
  if (typeof key !== "string" || key.length === 0) {
    throw new Error("Acurast job public keys did not include ed25519");
  }
  const hex = stripHexPrefix(key).toLowerCase();
  if (!/^[0-9a-f]{64}$/u.test(hex)) throw new Error("Acurast ed25519 public key must be a 32-byte hex string");
  return hex;
}

function encryptionKeyFromStd(std: AcurastRuntimeStd | undefined): string | undefined {
  const keys = safeCall(() => std?.job?.getEncryptionKeys?.());
  if (!keys) return undefined;
  const parsed = typeof keys === "string" ? parseJsonOrUndefined(keys) : keys;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  for (const name of ["p256", "secp256r1", "secp256r1Encryption", "encP256"]) {
    const value = (parsed as Record<string, unknown>)[name];
    if (typeof value === "string" && value.length > 0) return value;
    if (value instanceof Uint8Array) return Buffer.from(value).toString("hex");
    if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
      return Buffer.from(value).toString("hex");
    }
  }
  return undefined;
}

function stringifyRuntimeValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (value === undefined || value === null) return undefined;
  return JSON.stringify(value);
}

function parsePublicKeys(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return { ed25519: requireNonEmpty(value, "ed25519 public key") };
  }
}

function parseJsonOrUndefined(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function safeCall<T>(fn: () => T): T | undefined {
  try {
    const value = fn();
    return value === null || value === undefined ? undefined : value;
  } catch {
    return undefined;
  }
}
