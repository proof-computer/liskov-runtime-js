import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { DEFAULT_JOB_ID_ENV_NAMES, acurastEd25519PublicKey } from "./acurast.js";
import { getRuntimeEnvValue, resolveRuntimeStd, type AcurastRuntimeStd } from "./env.js";
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
  "BLACKBOX_LOG_TIMEOUT_MS",
  // Factory-token self-registration variant (P1.3).
  "BLACKBOX_FACTORY_TOKEN",
  "BLACKBOX_FACTORY_ID",
  "BLACKBOX_BASE_URL",
  "BLACKBOX_SPOOL_DIR",
  "BLACKBOX_NETWORK",
  "BLACKBOX_APPLICATION_ID",
  "BLACKBOX_DEPLOYMENT_ID"
] as const;

const SPOOL_STATE_FILE = "state.json";
const SPOOL_RECORD_FORMAT = "blackbox-spool-record-v1";
const SPOOL_BATCH_FORMAT = "blackbox-spool-batch-v1";
const SPOOL_STATE_FORMAT = "blackbox-spool-state-v1";
const DEFAULT_SPOOL_ROOT = "/tmp/blackbox-spool";
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_BATCH_MAX_RECORDS = 50;
const DEFAULT_BATCH_MAX_BYTES = 256 * 1024;
const DEFAULT_MAX_SPOOL_BYTES = 10 * 1024 * 1024;

/**
 * Runtime Blackbox log config. Two accepted shapes:
 *
 * - Pre-bound sink: `sinkId` + `jobId` + `writeUrl` + `dek`.
 * - Factory-token self-registration (P1.3): `factoryToken` + `baseUrl` + `dek`.
 *   The writer self-creates its job-bound sink on the first flush, resolving the
 *   job id at runtime, so the config can ship as a plain pre-boot secret and
 *   first-boot/`prepare()` failures are captured from the very first write.
 */
export interface BlackboxRuntimeLogConfig {
  sinkId?: string;
  jobId?: string;
  writeUrl?: string;
  dek: string;
  /** Sink-factory token (`bbx_sf_<factoryId>_<secret>`). */
  factoryToken?: string;
  /** Factory id; parsed from the token when omitted. */
  factoryId?: string;
  /** Base URL of the Blackbox service; derives self-register + write URLs. */
  baseUrl?: string;
  /** Local spool directory for the always-on spool (P1.4). */
  spoolDir?: string;
  network?: string;
  applicationId?: string;
  deploymentId?: string;
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
  /** Acurast `_STD_` override for runtime job-id resolution (tests). */
  std?: AcurastRuntimeStd;
  /** Spool backend: "auto" (default) probes disk and falls back to memory. */
  spoolMode?: "auto" | "disk" | "memory";
  /** Spool directory override; defaults to the config value or a derived path. */
  spoolDir?: string;
}

export function readBlackboxLogConfig(
  getConfigValue: (name: string) => string | undefined = defaultConfigValue
): BlackboxRuntimeLogConfig | undefined {
  const compact = getConfigValue("BLACKBOX_LOG_CONFIG");
  if (compact) {
    const parsed = parseBlackboxLogConfigPayload(compact);
    return normalizeBlackboxLogConfig({
      sinkId: stringField(parsed, "sinkId") ?? stringField(parsed, "sid"),
      jobId: stringField(parsed, "jobId") ?? stringField(parsed, "jid") ?? stringField(parsed, "job"),
      writeUrl: stringField(parsed, "writeUrl") ?? stringField(parsed, "url"),
      dek: stringField(parsed, "dek") ?? stringField(parsed, "k") ?? stringField(parsed, "logDek"),
      factoryToken: stringField(parsed, "factoryToken") ?? stringField(parsed, "ft"),
      factoryId: stringField(parsed, "factoryId") ?? stringField(parsed, "fid"),
      baseUrl: stringField(parsed, "baseUrl") ?? stringField(parsed, "base"),
      spoolDir: stringField(parsed, "spoolDir") ?? stringField(parsed, "spool"),
      network: stringField(parsed, "network") ?? stringField(parsed, "net"),
      applicationId: stringField(parsed, "applicationId") ?? stringField(parsed, "app"),
      deploymentId: stringField(parsed, "deploymentId") ?? stringField(parsed, "dep"),
      context: contextField(parsed.context ?? parsed.ctx),
      timeoutMs: numberField(parsed, "timeoutMs") ?? numberField(parsed, "flushTimeoutMs")
    });
  }

  const explicit = {
    sinkId: getConfigValue("BLACKBOX_SINK_ID"),
    jobId: getConfigValue("BLACKBOX_JOB_ID"),
    writeUrl: getConfigValue("BLACKBOX_WRITE_URL"),
    dek: getConfigValue("BLACKBOX_LOG_DEK"),
    factoryToken: getConfigValue("BLACKBOX_FACTORY_TOKEN"),
    factoryId: getConfigValue("BLACKBOX_FACTORY_ID"),
    baseUrl: getConfigValue("BLACKBOX_BASE_URL"),
    spoolDir: getConfigValue("BLACKBOX_SPOOL_DIR"),
    network: getConfigValue("BLACKBOX_NETWORK"),
    applicationId: getConfigValue("BLACKBOX_APPLICATION_ID"),
    deploymentId: getConfigValue("BLACKBOX_DEPLOYMENT_ID"),
    context: getConfigValue("BLACKBOX_LOG_CONTEXT"),
    timeoutMs: numberFromString(getConfigValue("BLACKBOX_LOG_TIMEOUT_MS"))
  };
  if (
    !explicit.sinkId &&
    !explicit.jobId &&
    !explicit.writeUrl &&
    !explicit.dek &&
    !explicit.factoryToken &&
    !explicit.factoryId &&
    !explicit.baseUrl
  ) {
    return undefined;
  }
  return normalizeBlackboxLogConfig(explicit);
}

export function blackboxLogHostnames(getConfigValue?: (name: string) => string | undefined): string[] {
  try {
    const config = readBlackboxLogConfig(getConfigValue);
    if (!config) return [];
    const hostnames = new Set<string>();
    if (config.writeUrl) hostnames.add(new URL(config.writeUrl).hostname);
    if (config.baseUrl) hostnames.add(new URL(config.baseUrl).hostname);
    return [...hostnames];
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
    Boolean(getConfigValue("BLACKBOX_LOG_DEK")) ||
    Boolean(getConfigValue("BLACKBOX_FACTORY_TOKEN")) ||
    Boolean(getConfigValue("BLACKBOX_FACTORY_ID")) ||
    Boolean(getConfigValue("BLACKBOX_BASE_URL"));
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

  const engine = new BlackboxSpoolEngine(config, {
    signer,
    writerPublicKey,
    fetchImpl: options.fetchImpl ?? fetch,
    timeoutMs: options.timeoutMs ?? config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    spoolMode: options.spoolMode ?? "auto",
    spoolDir: options.spoolDir ?? config.spoolDir,
    getConfigValue,
    std: resolveRuntimeStd(options.std),
    signedAt: options.signedAt,
    nonce: options.nonce,
    baseRecord: options.baseRecord,
    onError: options.onError
  });
  return (event, details = {}) => engine.log(event, details);
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

interface BlackboxSpoolEngineOptions {
  signer: BlackboxRequestSigner;
  writerPublicKey: string;
  fetchImpl: typeof fetch;
  timeoutMs: number;
  spoolMode: "auto" | "disk" | "memory";
  spoolDir?: string;
  getConfigValue: (name: string) => string | undefined;
  std?: AcurastRuntimeStd;
  signedAt?: () => string;
  nonce?: () => string;
  baseRecord?: () => Record<string, unknown>;
  onError?: (error: unknown, event: string) => void;
}

interface BlackboxSpoolRecord {
  format: typeof SPOOL_RECORD_FORMAT;
  recordId: string;
  createdAt: string;
  encrypted: ProofLogEncryptedRecord;
}

interface BlackboxSpoolBatch {
  format: typeof SPOOL_BATCH_FORMAT;
  batch: BlackboxLogBatch;
  recordFiles: string[];
}

interface BlackboxSpoolChainState {
  format: typeof SPOOL_STATE_FORMAT;
  nextSequence: number;
  previousHash: string | null;
  /** Sink id resolved via factory self-registration, cached for reboots (P1.3). */
  sinkId?: string;
  /** Job the persisted chain belongs to; a different job resets the chain. */
  jobId?: string;
}

/**
 * Always-on spooling writer (P1.4): records are encrypted and spooled from the
 * first instruction - independent of whether the sink/config/network is usable
 * yet - then batched and flushed once the sink exists. A boot that dies before
 * its sink is reachable leaves its spooled records (disk mode) to flush on the
 * next attempt rather than disappear.
 */
class BlackboxSpoolEngine {
  private storage?: SpoolStorage;
  private openPromise?: Promise<void>;
  private flushing?: Promise<void>;
  private state: BlackboxSpoolChainState = { format: SPOOL_STATE_FORMAT, nextSequence: 1, previousHash: null };
  private resolved?: { sinkId: string; jobId: string; writeUrl: string };

  constructor(
    private readonly config: BlackboxRuntimeLogConfig,
    private readonly options: BlackboxSpoolEngineOptions
  ) {}

  async log(event: string, details: Record<string, unknown>): Promise<void> {
    try {
      await this.ensureOpen();
      const record: BlackboxLogRecord = {
        ...this.options.baseRecord?.(),
        timestamp: new Date().toISOString(),
        event,
        context: this.config.context,
        details
      };
      const spoolRecord: BlackboxSpoolRecord = {
        format: SPOOL_RECORD_FORMAT,
        recordId: `${String(Date.now()).padStart(13, "0")}-${randomBytes(8).toString("hex")}`,
        createdAt: new Date().toISOString(),
        encrypted: encryptProofLogRecord(this.config.dek, record)
      };
      const bytes = Buffer.byteLength(JSON.stringify(spoolRecord), "utf8");
      if (bytes > DEFAULT_BATCH_MAX_BYTES) {
        throw new Error("Blackbox spool rejected record: record_too_large");
      }
      if ((await this.storage!.sizeBytes()) + bytes > DEFAULT_MAX_SPOOL_BYTES) {
        throw new Error("Blackbox spool rejected record: spool_full");
      }
      await this.storage!.writeRecord(spoolRecord.recordId, spoolRecord);
    } catch (error) {
      this.options.onError?.(error, event);
      return;
    }
    await this.flush(event);
  }

  private async flush(triggerEvent: string): Promise<void> {
    this.flushing ??= this.flushLoop(triggerEvent).finally(() => {
      this.flushing = undefined;
    });
    await this.flushing;
  }

  private async flushLoop(triggerEvent: string): Promise<void> {
    let context: { sinkId: string; jobId: string; writeUrl: string };
    try {
      context = await this.resolveSinkContext();
    } catch (error) {
      // No sink yet (factory self-register failed / network unreachable). Keep the
      // records spooled and retry on the next flush so nothing is dropped (P1.4).
      this.options.onError?.(error, triggerEvent);
      return;
    }
    for (;;) {
      let batchFile: string | undefined;
      try {
        batchFile = (await this.oldestPendingBatchFile()) ?? (await this.buildPendingBatch(context));
        if (!batchFile) return;
        await this.sendPendingBatch(batchFile, context.writeUrl);
      } catch (error) {
        this.options.onError?.(error, triggerEvent);
        return;
      }
    }
  }

  private async ensureOpen(): Promise<void> {
    this.openPromise ??= this.open();
    await this.openPromise;
  }

  private async open(): Promise<void> {
    this.storage = await resolveSpoolStorage(this.options.spoolMode, this.spoolDirOrDefault());
    await this.storage.init();
    this.state = await this.readChainState();
    const currentJobId = this.maybeCurrentJobId();
    const sinkChanged =
      this.state.sinkId !== undefined && this.config.sinkId !== undefined && this.state.sinkId !== this.config.sinkId;
    const jobChanged =
      this.state.jobId !== undefined && currentJobId !== undefined && this.state.jobId !== currentJobId;
    if (sinkChanged || jobChanged) {
      // The persisted chain belongs to another job/sink generation. Its pending
      // batches can never be accepted under this writer; drop them and restart
      // the chain, but keep loose records so the previous boot's unflushed lines
      // are delivered into this job's sink.
      for (const file of await this.storage.batchFiles()) {
        await this.storage.removeBatch(file);
      }
      this.state = { format: SPOOL_STATE_FORMAT, nextSequence: 1, previousHash: null };
      await this.storage.writeState(this.state);
    }
    await this.cleanupClaimedRecordsForPendingBatches();
  }

  private async resolveSinkContext(): Promise<{ sinkId: string; jobId: string; writeUrl: string }> {
    if (this.resolved) return this.resolved;
    if (this.config.sinkId && this.config.writeUrl) {
      this.resolved = {
        sinkId: this.config.sinkId,
        jobId: this.requireCurrentJobId(),
        writeUrl: this.config.writeUrl
      };
      return this.resolved;
    }
    if (this.state.sinkId) {
      this.resolved = {
        sinkId: this.state.sinkId,
        jobId: this.state.jobId ?? this.requireCurrentJobId(),
        writeUrl: this.writeUrlFor(this.state.sinkId)
      };
      return this.resolved;
    }
    const jobId = this.requireCurrentJobId();
    const sinkId = await this.selfRegisterSink(jobId);
    this.resolved = { sinkId, jobId, writeUrl: this.writeUrlFor(sinkId) };
    this.state = { ...this.state, sinkId, jobId };
    await this.storage!.writeState(this.state);
    return this.resolved;
  }

  private async selfRegisterSink(jobId: string): Promise<string> {
    const factoryToken = this.config.factoryToken;
    if (!factoryToken) {
      throw new Error(
        "Blackbox log config requires sinkId + jobId + writeUrl (pre-bound sink) or factoryToken + baseUrl (factory self-registration)"
      );
    }
    const factoryId = this.config.factoryId ?? parseFactoryIdFromToken(factoryToken);
    if (!factoryId) {
      throw new Error("Blackbox factory logger requires a factoryId (or a parseable factory token)");
    }
    const url = `${this.requireBaseUrl()}/v1/sink-factories/${encodeURIComponent(factoryId)}/job-sinks`;
    const body = withoutUndefined({
      jobId,
      network: this.config.network,
      applicationId: this.config.applicationId,
      deploymentId: this.config.deploymentId
    });
    const target = new URL(url);
    const signed = await createBlackboxSignedJsonRequest({
      signer: this.options.signer,
      method: "POST",
      path: `${target.pathname}${target.search}`,
      body,
      signedAt: this.options.signedAt?.(),
      nonce: this.options.nonce?.()
    });
    const response = await this.options.fetchImpl(target, {
      method: "POST",
      headers: {
        ...signed.headers,
        "x-blackbox-sink-factory-token": factoryToken
      },
      body: signed.body,
      signal: AbortSignal.timeout(Math.max(1, this.options.timeoutMs))
    });
    if (!response.ok) {
      throw new Error(`Blackbox sink self-register failed: ${response.status} ${(await response.text()).slice(0, 500)}`);
    }
    const payload = (await response.json()) as { sink?: { sinkId?: unknown }; sinkId?: unknown };
    const sinkId = stringOrUndefined(payload.sink?.sinkId) ?? stringOrUndefined(payload.sinkId);
    if (!sinkId) {
      throw new Error("Blackbox sink self-register response did not include a sinkId");
    }
    return sinkId;
  }

  private async buildPendingBatch(context: { sinkId: string; jobId: string }): Promise<string | undefined> {
    const files = await this.storage!.recordFiles();
    if (files.length === 0) return undefined;

    const selected: Array<{ file: string; record: BlackboxSpoolRecord }> = [];
    for (const file of files) {
      const record = await this.storage!.readRecord(file);
      if (!record || record.format !== SPOOL_RECORD_FORMAT) continue;
      const candidate = [...selected, { file, record }];
      const candidateBatch = this.batchForRecords(context, candidate);
      if (candidate.length > 1 && Buffer.byteLength(canonicalJson(candidateBatch), "utf8") > DEFAULT_BATCH_MAX_BYTES) {
        break;
      }
      selected.push({ file, record });
      if (selected.length >= DEFAULT_BATCH_MAX_RECORDS) break;
    }
    if (selected.length === 0) return undefined;

    const batchWithoutId = this.batchForRecords(context, selected);
    const batch: BlackboxLogBatch = { ...batchWithoutId, batchId: logBatchId(batchWithoutId) };
    const batchFile =
      `${String(batch.sequenceStart).padStart(16, "0")}-${String(batch.sequenceEnd).padStart(16, "0")}-${batch.batchId!.slice(2, 18)}.json`;
    await this.storage!.writeBatch(batchFile, {
      format: SPOOL_BATCH_FORMAT,
      batch,
      recordFiles: selected.map((item) => item.file)
    });
    for (const item of selected) {
      await this.storage!.removeRecord(item.file);
    }
    return batchFile;
  }

  private batchForRecords(
    context: { sinkId: string; jobId: string },
    records: Array<{ record: BlackboxSpoolRecord }>
  ): BlackboxLogBatch {
    const sequenceStart = this.state.nextSequence;
    return {
      sinkId: context.sinkId,
      jobId: context.jobId,
      writerPublicKey: this.options.writerPublicKey,
      sequenceStart,
      sequenceEnd: sequenceStart + records.length - 1,
      previousHash: this.state.previousHash,
      createdAt: new Date().toISOString(),
      encrypted: records.map((item) => item.record.encrypted)
    };
  }

  private async sendPendingBatch(file: string, writeUrl: string): Promise<void> {
    const spoolBatch = await this.storage!.readBatch(file);
    if (!spoolBatch || spoolBatch.format !== SPOOL_BATCH_FORMAT) {
      await this.storage!.removeBatch(file);
      return;
    }
    const url = new URL(writeUrl);
    const signed = await createBlackboxSignedJsonRequest({
      signer: this.options.signer,
      method: "POST",
      path: `${url.pathname}${url.search}`,
      body: spoolBatch.batch,
      signedAt: this.options.signedAt?.(),
      nonce: this.options.nonce?.()
    });
    const response = await this.options.fetchImpl(url, {
      method: "POST",
      headers: signed.headers,
      body: signed.body,
      signal: AbortSignal.timeout(Math.max(1, this.options.timeoutMs))
    });
    if (!response.ok) {
      throw new Error(`Blackbox log write failed: ${response.status} ${(await response.text()).slice(0, 500)}`);
    }
    this.state = {
      format: SPOOL_STATE_FORMAT,
      nextSequence: Math.max(this.state.nextSequence, spoolBatch.batch.sequenceEnd + 1),
      previousHash: logBatchHash(spoolBatch.batch),
      sinkId: this.state.sinkId,
      jobId: this.state.jobId
    };
    await this.storage!.writeState(this.state);
    await this.storage!.removeBatch(file);
  }

  private async oldestPendingBatchFile(): Promise<string | undefined> {
    return (await this.storage!.batchFiles())[0];
  }

  private async readChainState(): Promise<BlackboxSpoolChainState> {
    try {
      const state = await this.storage!.readState();
      if (state && state.format === SPOOL_STATE_FORMAT && Number.isInteger(state.nextSequence) && state.nextSequence > 0) {
        return {
          format: SPOOL_STATE_FORMAT,
          nextSequence: state.nextSequence,
          previousHash: state.previousHash ?? null,
          sinkId: typeof state.sinkId === "string" ? state.sinkId : undefined,
          jobId: typeof state.jobId === "string" ? state.jobId : undefined
        };
      }
    } catch {
      // Unreadable state restarts the chain below.
    }
    return { format: SPOOL_STATE_FORMAT, nextSequence: 1, previousHash: null };
  }

  private async cleanupClaimedRecordsForPendingBatches(): Promise<void> {
    for (const batchFile of await this.storage!.batchFiles()) {
      const spoolBatch = await this.storage!.readBatch(batchFile);
      for (const recordFile of spoolBatch?.recordFiles ?? []) {
        await this.storage!.removeRecord(recordFile);
      }
    }
  }

  private requireCurrentJobId(): string {
    const jobId = this.maybeCurrentJobId();
    if (!jobId) {
      throw new Error("Blackbox factory logger requires the Acurast job id (env or _STD_.job.getId)");
    }
    return jobId;
  }

  private maybeCurrentJobId(): string | undefined {
    if (this.config.jobId) return this.config.jobId;
    for (const name of DEFAULT_JOB_ID_ENV_NAMES) {
      const value = this.options.getConfigValue(name);
      if (value) return value;
    }
    return stringifyRuntimeValue(this.options.std?.job?.getId?.());
  }

  private writeUrlFor(sinkId: string): string {
    if (this.config.writeUrl && this.config.sinkId === sinkId) return this.config.writeUrl;
    return `${this.requireBaseUrl()}/v1/sinks/${encodeURIComponent(sinkId)}/events`;
  }

  private requireBaseUrl(): string {
    if (!this.config.baseUrl) {
      throw new Error("Blackbox factory logger requires a baseUrl to derive its sink URLs");
    }
    return this.config.baseUrl.replace(/\/+$/, "");
  }

  private spoolDirOrDefault(): string {
    if (this.options.spoolDir) return this.options.spoolDir;
    const seed = this.config.factoryId ?? parseFactoryIdFromToken(this.config.factoryToken ?? "") ?? this.config.sinkId ?? "sink";
    const jobId = this.maybeCurrentJobId();
    return defaultBlackboxSpoolDir(jobId ? `${seed}-${jobId}` : seed);
  }
}

interface SpoolStorage {
  readonly mode: "disk" | "memory";
  init(): Promise<void>;
  readState(): Promise<BlackboxSpoolChainState | undefined>;
  writeState(state: BlackboxSpoolChainState): Promise<void>;
  recordFiles(): Promise<string[]>;
  readRecord(file: string): Promise<BlackboxSpoolRecord | undefined>;
  writeRecord(recordId: string, record: BlackboxSpoolRecord): Promise<void>;
  removeRecord(file: string): Promise<void>;
  batchFiles(): Promise<string[]>;
  readBatch(file: string): Promise<BlackboxSpoolBatch | undefined>;
  writeBatch(file: string, batch: BlackboxSpoolBatch): Promise<void>;
  removeBatch(file: string): Promise<void>;
  sizeBytes(): Promise<number>;
}

async function resolveSpoolStorage(mode: "auto" | "disk" | "memory", spoolDir: string): Promise<SpoolStorage> {
  if (mode === "memory") return new MemorySpoolStorage();
  let disk: DiskSpoolStorage;
  try {
    // node:fs is loaded lazily so a runtime without a filesystem module can never
    // fail at bundle load; it just falls back to the in-memory spool.
    disk = new DiskSpoolStorage(spoolDir, await loadDiskSpoolModules());
  } catch (error) {
    if (mode === "disk") throw error;
    return new MemorySpoolStorage();
  }
  if (mode === "disk") return disk;
  try {
    await disk.probe();
    return disk;
  } catch {
    // Always-on local spool (P1.4): fall back to memory so records written before
    // a writable disk/sink/config exists are buffered rather than silently dropped.
    return new MemorySpoolStorage();
  }
}

type DiskSpoolModules = {
  fs: typeof import("node:fs/promises");
  path: typeof import("node:path");
};

async function loadDiskSpoolModules(): Promise<DiskSpoolModules> {
  const [fs, path] = await Promise.all([import("node:fs/promises"), import("node:path")]);
  return { fs, path: (path as { default?: typeof import("node:path") }).default ?? path };
}

class DiskSpoolStorage implements SpoolStorage {
  readonly mode = "disk" as const;
  private readonly recordsDir: string;
  private readonly batchesDir: string;
  private readonly stateFile: string;

  constructor(private readonly spoolDir: string, private readonly modules: DiskSpoolModules) {
    this.recordsDir = modules.path.join(spoolDir, "records");
    this.batchesDir = modules.path.join(spoolDir, "batches");
    this.stateFile = modules.path.join(spoolDir, SPOOL_STATE_FILE);
  }

  async probe(): Promise<void> {
    const { fs, path } = this.modules;
    await fs.mkdir(this.spoolDir, { recursive: true });
    const marker = path.join(this.spoolDir, `.blackbox-spool-probe-${randomBytes(6).toString("hex")}`);
    try {
      await fs.writeFile(marker, "ok", "utf8");
    } finally {
      await fs.rm(marker, { force: true });
    }
  }

  async init(): Promise<void> {
    await this.modules.fs.mkdir(this.recordsDir, { recursive: true });
    await this.modules.fs.mkdir(this.batchesDir, { recursive: true });
  }

  async readState(): Promise<BlackboxSpoolChainState | undefined> {
    return this.readJson<BlackboxSpoolChainState>(this.stateFile);
  }

  async writeState(state: BlackboxSpoolChainState): Promise<void> {
    await this.writeJsonAtomic(this.stateFile, state);
  }

  recordFiles(): Promise<string[]> {
    return this.sortedJsonFiles(this.recordsDir);
  }

  readRecord(file: string): Promise<BlackboxSpoolRecord | undefined> {
    return this.readJson<BlackboxSpoolRecord>(this.modules.path.join(this.recordsDir, file));
  }

  async writeRecord(recordId: string, record: BlackboxSpoolRecord): Promise<void> {
    await this.writeJsonAtomic(this.modules.path.join(this.recordsDir, `${recordId}.json`), record);
  }

  async removeRecord(file: string): Promise<void> {
    await this.modules.fs.rm(this.modules.path.join(this.recordsDir, file), { force: true });
  }

  batchFiles(): Promise<string[]> {
    return this.sortedJsonFiles(this.batchesDir);
  }

  readBatch(file: string): Promise<BlackboxSpoolBatch | undefined> {
    return this.readJson<BlackboxSpoolBatch>(this.modules.path.join(this.batchesDir, file));
  }

  async writeBatch(file: string, batch: BlackboxSpoolBatch): Promise<void> {
    await this.writeJsonAtomic(this.modules.path.join(this.batchesDir, file), batch);
  }

  async removeBatch(file: string): Promise<void> {
    await this.modules.fs.rm(this.modules.path.join(this.batchesDir, file), { force: true });
  }

  async sizeBytes(): Promise<number> {
    return (await this.directorySize(this.recordsDir)) + (await this.directorySize(this.batchesDir));
  }

  private async sortedJsonFiles(dir: string): Promise<string[]> {
    try {
      return (await this.modules.fs.readdir(dir)).filter((name) => name.endsWith(".json")).sort();
    } catch (error) {
      if (isNotFound(error)) return [];
      throw error;
    }
  }

  private async readJson<T>(file: string): Promise<T | undefined> {
    try {
      return JSON.parse(await this.modules.fs.readFile(file, "utf8")) as T;
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
  }

  private async writeJsonAtomic(file: string, value: unknown): Promise<void> {
    const { fs, path } = this.modules;
    await fs.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.${randomBytes(6).toString("hex")}.tmp`;
    await fs.writeFile(tmp, `${JSON.stringify(value)}\n`, "utf8");
    await fs.rename(tmp, file);
  }

  private async directorySize(dir: string): Promise<number> {
    const { fs, path } = this.modules;
    let total = 0;
    let entries: string[];
    try {
      entries = await fs.readdir(dir);
    } catch (error) {
      if (isNotFound(error)) return 0;
      throw error;
    }
    for (const entry of entries) {
      const info = await fs.stat(path.join(dir, entry));
      total += info.isDirectory() ? await this.directorySize(path.join(dir, entry)) : info.size;
    }
    return total;
  }
}

class MemorySpoolStorage implements SpoolStorage {
  readonly mode = "memory" as const;
  private readonly records = new Map<string, string>();
  private readonly batches = new Map<string, string>();
  private state: string | undefined;

  async init(): Promise<void> {}

  async readState(): Promise<BlackboxSpoolChainState | undefined> {
    return this.state === undefined ? undefined : (JSON.parse(this.state) as BlackboxSpoolChainState);
  }

  async writeState(state: BlackboxSpoolChainState): Promise<void> {
    this.state = JSON.stringify(state);
  }

  async recordFiles(): Promise<string[]> {
    return [...this.records.keys()].sort();
  }

  async readRecord(file: string): Promise<BlackboxSpoolRecord | undefined> {
    const value = this.records.get(file);
    return value === undefined ? undefined : (JSON.parse(value) as BlackboxSpoolRecord);
  }

  async writeRecord(recordId: string, record: BlackboxSpoolRecord): Promise<void> {
    this.records.set(`${recordId}.json`, JSON.stringify(record));
  }

  async removeRecord(file: string): Promise<void> {
    this.records.delete(file);
  }

  async batchFiles(): Promise<string[]> {
    return [...this.batches.keys()].sort();
  }

  async readBatch(file: string): Promise<BlackboxSpoolBatch | undefined> {
    const value = this.batches.get(file);
    return value === undefined ? undefined : (JSON.parse(value) as BlackboxSpoolBatch);
  }

  async writeBatch(file: string, batch: BlackboxSpoolBatch): Promise<void> {
    this.batches.set(file, JSON.stringify(batch));
  }

  async removeBatch(file: string): Promise<void> {
    this.batches.delete(file);
  }

  async sizeBytes(): Promise<number> {
    let total = 0;
    for (const value of this.records.values()) total += Buffer.byteLength(value, "utf8");
    for (const value of this.batches.values()) total += Buffer.byteLength(value, "utf8");
    return total;
  }
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
  factoryToken?: string;
  factoryId?: string;
  baseUrl?: string;
  spoolDir?: string;
  network?: string;
  applicationId?: string;
  deploymentId?: string;
  context?: string;
  timeoutMs?: number;
}): BlackboxRuntimeLogConfig {
  if (!input.dek) throw new Error("Blackbox log config requires dek");

  // Factory-token self-registration variant (P1.3).
  if (input.factoryToken && !input.sinkId) {
    const factoryId = input.factoryId ?? parseFactoryIdFromToken(input.factoryToken);
    if (!factoryId) {
      throw new Error("Blackbox factory log config requires a factoryId (or a parseable factory token)");
    }
    if (!input.baseUrl) throw new Error("Blackbox factory log config requires baseUrl");
    const baseUrl = new URL(input.baseUrl);
    if (baseUrl.protocol !== "https:" && baseUrl.protocol !== "http:") {
      throw new Error("Blackbox baseUrl must use http or https");
    }
    return withoutUndefined({
      jobId: input.jobId,
      dek: input.dek,
      factoryToken: input.factoryToken,
      factoryId,
      baseUrl: input.baseUrl,
      spoolDir: input.spoolDir,
      network: input.network,
      applicationId: input.applicationId,
      deploymentId: input.deploymentId,
      context: input.context,
      timeoutMs: input.timeoutMs
    }) as BlackboxRuntimeLogConfig;
  }

  // Pre-bound sink variant. Unrecognized shapes fail loudly with both accepted
  // shapes named, instead of degrading into a silent no-op writer.
  if (!input.sinkId || !input.jobId || !input.writeUrl) {
    throw new Error(
      "Blackbox log config requires sinkId + jobId + writeUrl (pre-bound sink) or factoryToken + baseUrl (factory self-registration)"
    );
  }
  const url = new URL(input.writeUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Blackbox writeUrl must use http or https");
  return withoutUndefined({
    sinkId: input.sinkId,
    jobId: input.jobId,
    writeUrl: url.toString(),
    dek: input.dek,
    baseUrl: input.baseUrl,
    spoolDir: input.spoolDir,
    context: input.context,
    timeoutMs: input.timeoutMs
  }) as BlackboxRuntimeLogConfig;
}

/** Token format is `bbx_sf_<factoryId>_<secret>`; factoryId never contains `_`. */
function parseFactoryIdFromToken(token: string): string | undefined {
  const match = /^bbx_sf_([A-Za-z0-9][A-Za-z0-9.:-]{0,127})_/.exec(token);
  return match?.[1];
}

function defaultBlackboxSpoolDir(seed: string): string {
  const segment = seed.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 96) || "sink";
  return `${DEFAULT_SPOOL_ROOT}/${segment}`;
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

function isNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: unknown }).code === "ENOENT";
}

function stringifyRuntimeValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (value === undefined || value === null) return undefined;
  return JSON.stringify(value);
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function withoutUndefined<T extends Record<string, unknown>>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;
}
