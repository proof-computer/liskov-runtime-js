import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { acurastEd25519PublicKey } from "./acurast.js";
import { getRuntimeEnvValue } from "./env.js";
import { encryptProofLogRecord, type ProofLogEncryptedRecord } from "./proof-log-crypto.js";
import {
  canonicalJson,
  normalizeHexNoPrefix,
  sha256Digest,
  stripHexPrefix
} from "./shared.js";

export const BLACKBOX_LOG_ENV_NAMES = [
  "BLACKBOX_LOG_CONFIG",
  "BLACKBOX_SINK_ID",
  "BLACKBOX_JOB_ID",
  "BLACKBOX_WRITE_URL",
  "BLACKBOX_LOG_DEK",
  "BLACKBOX_LOG_CONTEXT",
  "BLACKBOX_LOG_TIMEOUT_MS"
] as const;

export interface BlackboxRuntimeLogConfig {
  sinkId: string;
  jobId: string;
  writeUrl: string;
  dek: string;
  context?: string;
  timeoutMs?: number;
}

export interface BlackboxLogRecord {
  timestamp: string;
  event: string;
  context?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface BlackboxLogBatch {
  sinkId: string;
  jobId: string;
  batchId?: string;
  writerPublicKey: string;
  sequenceStart: number;
  sequenceEnd: number;
  previousHash?: string | null;
  createdAt: string;
  encrypted: ProofLogEncryptedRecord[];
  labels?: Record<string, string>;
}

export interface BlackboxRequestSigner {
  scheme: "Ed25519";
  publicKeyHex: string;
  sign(message: Uint8Array): Uint8Array | string | Promise<Uint8Array | string>;
}

export interface BlackboxRemoteLoggerOptions {
  getConfigValue?: (name: string) => string | undefined;
  signer?: BlackboxRequestSigner;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  signedAt?: () => string;
  nonce?: () => string;
  baseRecord?: () => Record<string, unknown>;
  onError?: (error: unknown, event: string) => void;
}

export function readBlackboxLogConfig(
  getConfigValue: (name: string) => string | undefined = defaultConfigValue
): BlackboxRuntimeLogConfig | undefined {
  const compact = getConfigValue("BLACKBOX_LOG_CONFIG");
  if (compact) {
    const parsed = parseBlackboxLogConfigPayload(compact);
    return normalizeBlackboxLogConfig({
      sinkId: stringField(parsed, "sinkId") ?? stringField(parsed, "sid"),
      jobId: stringField(parsed, "jobId") ?? stringField(parsed, "jid"),
      writeUrl: stringField(parsed, "writeUrl") ?? stringField(parsed, "url"),
      dek: stringField(parsed, "dek") ?? stringField(parsed, "k"),
      context: contextField(parsed.context ?? parsed.ctx),
      timeoutMs: numberField(parsed, "timeoutMs")
    });
  }

  const explicit = {
    sinkId: getConfigValue("BLACKBOX_SINK_ID"),
    jobId: getConfigValue("BLACKBOX_JOB_ID"),
    writeUrl: getConfigValue("BLACKBOX_WRITE_URL"),
    dek: getConfigValue("BLACKBOX_LOG_DEK"),
    context: getConfigValue("BLACKBOX_LOG_CONTEXT"),
    timeoutMs: numberFromString(getConfigValue("BLACKBOX_LOG_TIMEOUT_MS"))
  };
  if (!explicit.sinkId && !explicit.jobId && !explicit.writeUrl && !explicit.dek) return undefined;
  return normalizeBlackboxLogConfig(explicit);
}

export function blackboxLogHostnames(getConfigValue?: (name: string) => string | undefined): string[] {
  try {
    const config = readBlackboxLogConfig(getConfigValue);
    return config ? [new URL(config.writeUrl).hostname] : [];
  } catch {
    return [];
  }
}

export function blackboxLogConfigFingerprint(
  getConfigValue: (name: string) => string | undefined = defaultConfigValue
): string | undefined {
  const hasConfig =
    Boolean(getConfigValue("BLACKBOX_LOG_CONFIG")) ||
    Boolean(getConfigValue("BLACKBOX_SINK_ID")) ||
    Boolean(getConfigValue("BLACKBOX_JOB_ID")) ||
    Boolean(getConfigValue("BLACKBOX_WRITE_URL")) ||
    Boolean(getConfigValue("BLACKBOX_LOG_DEK"));
  if (!hasConfig) return undefined;
  const values = BLACKBOX_LOG_ENV_NAMES
    .map((name) => [name, getConfigValue(name) ?? null] as const)
    .filter(([, value]) => value !== null);
  return `0x${sha256Digest(canonicalJson(values)).slice("sha256:".length)}`;
}

export function createBlackboxRemoteLogger(
  options: BlackboxRemoteLoggerOptions = {}
): (event: string, details?: Record<string, unknown>) => Promise<void> {
  const getConfigValue = options.getConfigValue ?? defaultConfigValue;
  let config: BlackboxRuntimeLogConfig | undefined;
  try {
    config = readBlackboxLogConfig(getConfigValue);
  } catch (error) {
    return async (event) => options.onError?.(error, event);
  }
  if (!config) return async () => undefined;

  const signer = options.signer ?? maybeAcurastBlackboxRequestSigner();
  if (!signer) {
    return async (event) => {
      options.onError?.(new Error("Blackbox logging requires the Acurast Ed25519 runtime signer"), event);
    };
  }

  let writerPublicKey: string;
  try {
    writerPublicKey = normalizePublicKeyHex(signer.publicKeyHex);
  } catch (error) {
    return async (event) => options.onError?.(error, event);
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? config.timeoutMs ?? 5_000;
  const pending: BlackboxLogBatch[] = [];
  let nextSequence = 1;
  let previousHash: string | null = null;
  let flushing: Promise<void> | undefined;

  const flushPending = async (triggerEvent: string) => {
    flushing ??= flushBlackboxBatches({
      batches: pending,
      config,
      fetchImpl,
      signer,
      timeoutMs,
      signedAt: options.signedAt,
      nonce: options.nonce,
      onAccepted: (batch) => {
        previousHash = logBatchHash(batch);
        nextSequence = batch.sequenceEnd + 1;
        pending.shift();
      },
      onError: (error) => options.onError?.(error, triggerEvent)
    }).finally(() => {
      flushing = undefined;
    });
    await flushing;
  };

  return async (event: string, details: Record<string, unknown> = {}) => {
    const previousBatch = pending[pending.length - 1];
    const sequenceStart = previousBatch ? previousBatch.sequenceEnd + 1 : nextSequence;
    const record: BlackboxLogRecord = {
      ...options.baseRecord?.(),
      timestamp: new Date().toISOString(),
      event,
      context: config.context,
      details
    };
    const batchWithoutId: BlackboxLogBatch = {
      sinkId: config.sinkId,
      jobId: config.jobId,
      writerPublicKey,
      sequenceStart,
      sequenceEnd: sequenceStart,
      previousHash: previousBatch ? logBatchHash(previousBatch) : previousHash,
      createdAt: new Date().toISOString(),
      encrypted: [encryptProofLogRecord(config.dek, record)]
    };
    pending.push({
      ...batchWithoutId,
      batchId: logBatchId(batchWithoutId)
    });
    await flushPending(event);
  };
}

export async function createBlackboxSignedJsonRequest(input: {
  signer: BlackboxRequestSigner;
  method: string;
  path: string;
  body: unknown;
  signedAt?: string;
  nonce?: string;
}): Promise<{ headers: Record<string, string>; body: string; signingMessage: string }> {
  const body = canonicalJson(input.body);
  const bodyBytes = Buffer.from(body, "utf8");
  const signedAt = input.signedAt ?? new Date().toISOString();
  const nonce = input.nonce ?? randomBytes(16).toString("base64url");
  const signingMessage = [
    input.method.toUpperCase(),
    input.path,
    `0x${sha256Digest(bodyBytes).slice("sha256:".length)}`,
    signedAt,
    nonce
  ].join("\n");
  const signature = await input.signer.sign(Buffer.from(signingMessage, "utf8"));
  const signatureBytes = typeof signature === "string"
    ? Buffer.from(stripHexPrefix(signature), "hex")
    : Buffer.from(signature);

  return {
    headers: {
      accept: "application/json",
      authorization: `${input.signer.scheme} ${normalizePublicKeyHex(input.signer.publicKeyHex)}:${signatureBytes.toString("base64")}`,
      "content-type": "application/json",
      "x-signed-at": signedAt,
      "x-nonce": nonce
    },
    body,
    signingMessage
  };
}

export function maybeAcurastBlackboxRequestSigner(
  std = (globalThis as { _STD_?: unknown })._STD_
): BlackboxRequestSigner | undefined {
  const runtime = std as {
    signers?: { ed25519?: { sign?: (payloadHex: string) => string | Promise<string> } };
  } | undefined;
  if (typeof runtime?.signers?.ed25519?.sign !== "function") return undefined;
  return {
    scheme: "Ed25519",
    get publicKeyHex() {
      return acurastEd25519PublicKey(std as never);
    },
    async sign(message: Uint8Array) {
      const signature = await Promise.resolve(
        runtime.signers!.ed25519!.sign!.call(runtime.signers!.ed25519, Buffer.from(message).toString("hex"))
      );
      return stripHexPrefix(signature);
    }
  };
}

async function flushBlackboxBatches(input: {
  batches: BlackboxLogBatch[];
  config: BlackboxRuntimeLogConfig;
  fetchImpl: typeof fetch;
  signer: BlackboxRequestSigner;
  timeoutMs: number;
  signedAt?: () => string;
  nonce?: () => string;
  onAccepted: (batch: BlackboxLogBatch) => void;
  onError?: (error: unknown) => void;
}): Promise<void> {
  while (input.batches.length > 0) {
    const batch = input.batches[0]!;
    try {
      await postBlackboxBatch({
        batch,
        writeUrl: input.config.writeUrl,
        fetchImpl: input.fetchImpl,
        signer: input.signer,
        timeoutMs: input.timeoutMs,
        signedAt: input.signedAt,
        nonce: input.nonce
      });
      input.onAccepted(batch);
    } catch (error) {
      input.onError?.(error);
      return;
    }
  }
}

async function postBlackboxBatch(input: {
  batch: BlackboxLogBatch;
  writeUrl: string;
  fetchImpl: typeof fetch;
  signer: BlackboxRequestSigner;
  timeoutMs: number;
  signedAt?: () => string;
  nonce?: () => string;
}): Promise<void> {
  const url = new URL(input.writeUrl);
  const path = `${url.pathname}${url.search}`;
  const signed = await createBlackboxSignedJsonRequest({
    signer: input.signer,
    method: "POST",
    path,
    body: input.batch,
    signedAt: input.signedAt?.(),
    nonce: input.nonce?.()
  });
  const response = await input.fetchImpl(url, {
    method: "POST",
    headers: signed.headers,
    body: signed.body,
    signal: AbortSignal.timeout(Math.max(1, input.timeoutMs))
  });
  if (!response.ok) throw new Error(`Blackbox log write failed: ${response.status} ${(await response.text()).slice(0, 500)}`);
}

function parseBlackboxLogConfigPayload(value: string): Record<string, unknown> {
  const trimmed = value.trim();
  const raw = trimmed.startsWith("{") ? trimmed : decodeEncodedJson(trimmed);
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("BLACKBOX_LOG_CONFIG must be a JSON object");
  return parsed as Record<string, unknown>;
}

function decodeEncodedJson(value: string): string {
  for (const encoding of ["base64url", "base64"] as const) {
    try {
      const decoded = Buffer.from(value, encoding).toString("utf8");
      if (decoded.trim().startsWith("{")) return decoded;
    } catch {
      // Try the next accepted compact encoding.
    }
  }
  throw new Error("BLACKBOX_LOG_CONFIG must be JSON, base64url JSON, or base64 JSON");
}

function normalizeBlackboxLogConfig(input: {
  sinkId?: string;
  jobId?: string;
  writeUrl?: string;
  dek?: string;
  context?: string;
  timeoutMs?: number;
}): BlackboxRuntimeLogConfig {
  if (!input.sinkId) throw new Error("Blackbox log config requires sinkId");
  if (!input.jobId) throw new Error("Blackbox log config requires jobId");
  if (!input.writeUrl) throw new Error("Blackbox log config requires writeUrl");
  if (!input.dek) throw new Error("Blackbox log config requires dek");
  const url = new URL(input.writeUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Blackbox writeUrl must use http or https");
  return {
    sinkId: input.sinkId,
    jobId: input.jobId,
    writeUrl: url.toString(),
    dek: input.dek,
    context: input.context,
    timeoutMs: input.timeoutMs
  };
}

function contextField(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (value && typeof value === "object" && !Array.isArray(value)) return canonicalJson(value);
  return undefined;
}

function stringField(record: Record<string, unknown>, name: string): string | undefined {
  const value = record[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberField(record: Record<string, unknown>, name: string): number | undefined {
  const value = record[name];
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? value
    : numberFromString(typeof value === "string" ? value : undefined);
}

function numberFromString(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function defaultConfigValue(name: string): string | undefined {
  return getRuntimeEnvValue(name);
}

function logBatchHash(batch: BlackboxLogBatch): string {
  const { batchId: _batchId, ...hashMaterial } = batch;
  return `0x${sha256Digest(canonicalJson(hashMaterial)).slice("sha256:".length)}`;
}

function logBatchId(batch: BlackboxLogBatch): string {
  return logBatchHash(batch);
}

function normalizePublicKeyHex(value: string): string {
  const hex = normalizeHexNoPrefix(value);
  if (!/^[0-9a-f]{64}$/u.test(hex)) throw new Error("Blackbox signer public key must be a 32-byte hex string");
  return hex;
}

