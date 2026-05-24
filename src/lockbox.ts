import { Buffer } from "node:buffer";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type { RuntimeIdentityProvider } from "./acurast.js";
import {
  getRuntimeEnvValue,
  optionalBooleanEnv,
  optionalIntegerEnv,
  requiredRuntimeEnvValue,
  type RuntimeEnvLookupOptions
} from "./env.js";
import {
  asRecord,
  assertSecureRuntimeUrl,
  canonicalJson,
  digestMatches,
  integerTimestamp,
  normalizeHexNoPrefix,
  normalizePolicyDigest,
  normalizeRequestedSecretIds,
  parseJson,
  parseStringArrayOrCsv,
  randomHex,
  requiredBoolean,
  requiredNumber,
  requiredString,
  requiredStringAlias,
  safeErrorMessage,
  sha256Digest,
  stringRecord,
  validEnvName,
  type RuntimeRandomBytes
} from "./shared.js";

export const LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN = "proof.lockbox.job-secret-request.v1";
export const LOCKBOX_RUNTIME_JOB_SECRET_RESPONSE_DOMAIN = "proof.lockbox.job-secret-response.v1";
export const LOCKBOX_RUNTIME_JOB_SECRET_ENCRYPTED_PAYLOAD_DOMAIN = "proof.lockbox.job-secret-response.encrypted-payload.v1";

export interface LockboxRuntimeJobSecretUnsignedRequest {
  domain: typeof LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN;
  applicationId: string;
  grantId: string;
  policyDigest: string;
  jobId: string;
  deploymentId: string;
  processorId: string;
  requestedSecretIds: string[];
  nonce: string;
  issuedAtMs: number;
  expiresAtMs: number;
  responseEncryptionKey: string;
}

export interface LockboxRuntimeJobSecretSignedRequest extends LockboxRuntimeJobSecretUnsignedRequest {
  signature: string;
}

export interface LockboxRuntimeJobSecretEncryptedPayload {
  domain: typeof LOCKBOX_RUNTIME_JOB_SECRET_ENCRYPTED_PAYLOAD_DOMAIN;
  version: "acurast-p256-hkdf-aes-256-gcm-v1";
  curveName: "secp256r1";
  senderPublicKey: string;
  saltHex: string;
  ciphertextHex: string;
  plaintextDigest: string;
  encryptedPayloadDigest: string;
}

export interface LockboxRuntimePlaintextSecret {
  secretId: string;
  versionId: string;
  target: "env" | "file";
  name: string;
  required: boolean;
  bundleId: string;
  value: string;
}

export interface LockboxRuntimeJobSecretPlaintextPayload {
  domain: typeof LOCKBOX_RUNTIME_JOB_SECRET_RESPONSE_DOMAIN;
  requestId: string;
  grantId: string;
  applicationId: string;
  repository: string;
  policyDigest: string;
  jobId: string;
  deploymentId: string;
  processorId: string;
  issuedAtMs: number;
  secrets: LockboxRuntimePlaintextSecret[];
}

export interface LockboxRuntimeSecretVersionMetadata {
  secretId: string;
  versionId: string;
  target: "env" | "file";
  name: string;
  required: boolean;
  bundleId: string;
  encryptedPayloadDigest?: string;
}

export interface LockboxRuntimeJobSecretResponse {
  ok: true;
  requestId: string;
  grantId: string;
  applicationId: string;
  repository: string;
  policyDigest: string;
  jobId: string;
  deploymentId: string;
  processorId: string;
  requestedSecretIds: string[];
  responseKeyDigest: string;
  secretVersions: LockboxRuntimeSecretVersionMetadata[];
  encryptedPayload: LockboxRuntimeJobSecretEncryptedPayload;
}

export interface LockboxRuntimeSecretConfig {
  lockboxUrl: string;
  applicationId: string;
  grantId: string;
  policyDigest: string;
  deploymentId: string;
  requestedSecretIds: readonly string[];
  allowInsecureHttp?: boolean;
  requestTtlMs?: number;
  nonce?: string;
  fileBaseDir?: string;
  overwriteEnv?: boolean;
}

export interface LockboxRuntimeDiagnosticEvent {
  phase:
    | "identity_resolved"
    | "request_signed"
    | "lockbox_request"
    | "lockbox_response"
    | "payload_decrypted"
    | "secrets_installed"
    | "bootstrap_failed";
  ok: boolean;
  applicationId?: string;
  grantId?: string;
  requestId?: string;
  secretCount?: number;
  installedEnvCount?: number;
  installedFileCount?: number;
  skippedEnvCount?: number;
  status?: number;
  errorCode?: string;
}

export interface LockboxRuntimeLoadOptions {
  identityProvider: RuntimeIdentityProvider;
  config: LockboxRuntimeSecretConfig;
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  randomBytes?: RuntimeRandomBytes;
  files?: RuntimeFileWriter;
  diagnostics?: (event: LockboxRuntimeDiagnosticEvent) => void | Promise<void>;
}

export interface RuntimeFileWriter {
  mkdir(path: string, options: { recursive: true }): Promise<unknown>;
  writeFile(path: string, data: string, options: { encoding: "utf8"; mode: number }): Promise<unknown>;
  chmod(path: string, mode: number): Promise<unknown>;
}

export interface LockboxRuntimeInstalledSecret {
  secretId: string;
  versionId: string;
  target: "env" | "file";
  name: string;
  bundleId: string;
}

export interface LockboxRuntimeInstallResult {
  env: LockboxRuntimeInstalledSecret[];
  files: LockboxRuntimeInstalledSecret[];
  skippedExistingEnv: LockboxRuntimeInstalledSecret[];
}

export interface LockboxRuntimeLoadResult {
  request: LockboxRuntimeJobSecretSignedRequest;
  response: LockboxRuntimeJobSecretResponse;
  installed: LockboxRuntimeInstallResult;
}

export function readLockboxRuntimeConfig(options: RuntimeEnvLookupOptions = {}): LockboxRuntimeSecretConfig | undefined {
  const compact = getRuntimeEnvValue("PROOF_LOCKBOX_BOOTSTRAP", options);
  if (compact !== undefined) return lockboxRuntimeConfigFromBootstrap(compact, options);
  const lockboxUrl = getRuntimeEnvValue("PROOF_LOCKBOX_URL", options);
  if (!lockboxUrl) return undefined;
  const secretIds = getRuntimeEnvValue("PROOF_LOCKBOX_SECRET_IDS", options) ??
    getRuntimeEnvValue("PROOF_LOCKBOX_REQUESTED_SECRET_IDS", options);
  return {
    lockboxUrl,
    applicationId: requiredRuntimeEnvValue("PROOF_LOCKBOX_APPLICATION_ID", options),
    grantId: requiredRuntimeEnvValue("PROOF_LOCKBOX_GRANT_ID", options),
    policyDigest: normalizePolicyDigest(requiredRuntimeEnvValue("PROOF_LOCKBOX_POLICY_DIGEST", options)),
    deploymentId: requiredRuntimeEnvValue("PROOF_LOCKBOX_DEPLOYMENT_ID", options),
    requestedSecretIds: parseStringArrayOrCsv(secretIds, "PROOF_LOCKBOX_SECRET_IDS"),
    allowInsecureHttp: optionalBooleanEnv("PROOF_LOCKBOX_ALLOW_INSECURE_HTTP", options),
    fileBaseDir: getRuntimeEnvValue("PROOF_LOCKBOX_FILE_BASE_DIR", options),
    requestTtlMs: optionalIntegerEnv("PROOF_LOCKBOX_REQUEST_TTL_MS", options),
    overwriteEnv: optionalBooleanEnv("PROOF_LOCKBOX_OVERWRITE_ENV", options)
  };
}

export function lockboxRuntimeConfigFromBootstrap(
  rawBootstrap: string,
  options: RuntimeEnvLookupOptions = {}
): LockboxRuntimeSecretConfig {
  const record = asRecord(parseJson(rawBootstrap, "PROOF_LOCKBOX_BOOTSTRAP"), "PROOF_LOCKBOX_BOOTSTRAP");
  const secretIds = record.s ?? record.secretIds ?? record.requestedSecretIds;
  return {
    lockboxUrl: requiredStringAlias(record, "u", "url", "lockboxUrl"),
    applicationId: requiredStringAlias(record, "a", "applicationId"),
    grantId: requiredStringAlias(record, "g", "grantId"),
    policyDigest: normalizePolicyDigest(requiredStringAlias(record, "p", "policyDigest")),
    deploymentId: requiredStringAlias(record, "d", "deploymentId"),
    requestedSecretIds: parseStringArrayOrCsv(secretIds, "PROOF_LOCKBOX_BOOTSTRAP.s"),
    allowInsecureHttp: Boolean(optionalBooleanEnv("PROOF_LOCKBOX_ALLOW_INSECURE_HTTP", options) ?? record.allowInsecureHttp),
    fileBaseDir: typeof record.f === "string" ? record.f : typeof record.fileBaseDir === "string" ? record.fileBaseDir : undefined,
    requestTtlMs: optionalIntegerEnv("PROOF_LOCKBOX_REQUEST_TTL_MS", options),
    overwriteEnv: optionalBooleanEnv("PROOF_LOCKBOX_OVERWRITE_ENV", options)
  };
}

export async function buildLockboxRuntimeJobSecretRequest(input: {
  identityProvider: RuntimeIdentityProvider;
  config: LockboxRuntimeSecretConfig;
  nowMs?: number;
  randomBytes?: RuntimeRandomBytes;
  nonce?: string;
}): Promise<LockboxRuntimeJobSecretSignedRequest> {
  const identity = await input.identityProvider.resolveIdentity({ requireEncryptionKey: true });
  const nowMs = input.nowMs ?? Date.now();
  const request = canonicalLockboxRuntimeJobSecretRequest({
    domain: LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN,
    applicationId: input.config.applicationId,
    grantId: input.config.grantId,
    policyDigest: input.config.policyDigest,
    jobId: identity.jobId,
    deploymentId: input.config.deploymentId,
    processorId: identity.processorId,
    requestedSecretIds: normalizeRequestedSecretIds(input.config.requestedSecretIds),
    nonce: input.nonce ?? input.config.nonce ?? randomHex(16, input.randomBytes),
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + (input.config.requestTtlMs ?? 60_000),
    responseEncryptionKey: normalizeHexNoPrefix(identity.responseEncryptionKey!)
  });
  return {
    ...request,
    signature: await input.identityProvider.sign(lockboxRuntimeJobSecretRequestMessage(request))
  };
}

export function canonicalLockboxRuntimeJobSecretRequest(
  request: LockboxRuntimeJobSecretUnsignedRequest | LockboxRuntimeJobSecretSignedRequest
): LockboxRuntimeJobSecretUnsignedRequest {
  const { signature: _signature, ...unsigned } = request as LockboxRuntimeJobSecretSignedRequest;
  return {
    domain: LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN,
    applicationId: requiredString(unsigned as unknown as Record<string, unknown>, "applicationId"),
    grantId: requiredString(unsigned as unknown as Record<string, unknown>, "grantId"),
    policyDigest: normalizePolicyDigest(unsigned.policyDigest),
    jobId: requiredString(unsigned as unknown as Record<string, unknown>, "jobId"),
    deploymentId: requiredString(unsigned as unknown as Record<string, unknown>, "deploymentId"),
    processorId: requiredString(unsigned as unknown as Record<string, unknown>, "processorId"),
    requestedSecretIds: normalizeRequestedSecretIds(unsigned.requestedSecretIds),
    nonce: requiredString(unsigned as unknown as Record<string, unknown>, "nonce"),
    issuedAtMs: integerTimestamp(unsigned.issuedAtMs, "issuedAtMs"),
    expiresAtMs: integerTimestamp(unsigned.expiresAtMs, "expiresAtMs"),
    responseEncryptionKey: normalizeHexNoPrefix(unsigned.responseEncryptionKey)
  };
}

export function lockboxRuntimeJobSecretRequestMessage(request: LockboxRuntimeJobSecretUnsignedRequest): Uint8Array {
  return Buffer.from(canonicalJson(canonicalLockboxRuntimeJobSecretRequest(request)), "utf8");
}

export async function loadLockboxRuntimeSecrets(input: LockboxRuntimeLoadOptions): Promise<LockboxRuntimeLoadResult> {
  try {
    const fetchImpl = input.fetchImpl ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") throw new Error("fetch is required for Lockbox runtime secrets");
    await emit(input.diagnostics, {
      phase: "identity_resolved",
      ok: true,
      applicationId: input.config.applicationId,
      grantId: input.config.grantId
    });
    const request = await buildLockboxRuntimeJobSecretRequest({
      identityProvider: input.identityProvider,
      config: input.config,
      nowMs: input.nowMs?.() ?? Date.now(),
      randomBytes: input.randomBytes
    });
    await emit(input.diagnostics, {
      phase: "request_signed",
      ok: true,
      applicationId: request.applicationId,
      grantId: request.grantId,
      secretCount: request.requestedSecretIds.length
    });
    const response = await postLockboxRuntimeJobSecretRequest({ ...input, fetchImpl, request });
    const payload = await decryptAndVerifyLockboxRuntimePayload({
      identityProvider: input.identityProvider,
      request,
      response
    });
    await emit(input.diagnostics, {
      phase: "payload_decrypted",
      ok: true,
      applicationId: payload.applicationId,
      grantId: payload.grantId,
      requestId: payload.requestId,
      secretCount: payload.secrets.length
    });
    const installed = await installLockboxRuntimeSecrets({
      payload,
      env: input.env ?? process.env,
      fileBaseDir: input.config.fileBaseDir,
      overwriteEnv: input.config.overwriteEnv ?? false,
      files: input.files
    });
    await emit(input.diagnostics, {
      phase: "secrets_installed",
      ok: true,
      applicationId: payload.applicationId,
      grantId: payload.grantId,
      requestId: payload.requestId,
      secretCount: payload.secrets.length,
      installedEnvCount: installed.env.length,
      installedFileCount: installed.files.length,
      skippedEnvCount: installed.skippedExistingEnv.length
    });
    return { request, response, installed };
  } catch (error) {
    await emit(input.diagnostics, {
      phase: "bootstrap_failed",
      ok: false,
      applicationId: input.config.applicationId,
      grantId: input.config.grantId,
      errorCode: safeErrorMessage(error)
    });
    throw error;
  }
}

export async function decryptAndVerifyLockboxRuntimePayload(input: {
  identityProvider: RuntimeIdentityProvider;
  request: LockboxRuntimeJobSecretUnsignedRequest;
  response: LockboxRuntimeJobSecretResponse;
}): Promise<LockboxRuntimeJobSecretPlaintextPayload> {
  const encryptedPayload = parseLockboxEncryptedPayload(input.response.encryptedPayload);
  const encryptedPayloadBase = { ...encryptedPayload };
  delete (encryptedPayloadBase as { encryptedPayloadDigest?: string }).encryptedPayloadDigest;
  if (!digestMatches(canonicalJson(encryptedPayloadBase), encryptedPayload.encryptedPayloadDigest)) {
    throw new Error("Lockbox encrypted payload digest mismatch");
  }
  const plaintextBytes = await input.identityProvider.decryptGrantPayload(encryptedPayload);
  const plaintextText = Buffer.from(plaintextBytes).toString("utf8");
  if (!digestMatches(plaintextText, encryptedPayload.plaintextDigest)) {
    throw new Error("Lockbox plaintext digest mismatch");
  }
  const payload = parseLockboxPlaintextPayload(parseJson(plaintextText, "Lockbox plaintext payload"));
  assertLockboxPayloadBinding({ request: input.request, response: input.response, payload });
  return payload;
}

export async function installLockboxRuntimeSecrets(input: {
  payload: LockboxRuntimeJobSecretPlaintextPayload;
  env?: Record<string, string | undefined>;
  fileBaseDir?: string;
  overwriteEnv?: boolean;
  files?: RuntimeFileWriter;
}): Promise<LockboxRuntimeInstallResult> {
  const env = input.env ?? process.env;
  const files = input.files ?? { mkdir, writeFile, chmod };
  const installed: LockboxRuntimeInstallResult = { env: [], files: [], skippedExistingEnv: [] };
  for (const secret of input.payload.secrets) {
    const record = installedSecret(secret);
    if (secret.target === "env") {
      const name = validEnvName(secret.name);
      if (env[name] !== undefined && input.overwriteEnv !== true) {
        installed.skippedExistingEnv.push(record);
        continue;
      }
      env[name] = secret.value;
      installed.env.push(record);
      continue;
    }
    if (!input.fileBaseDir) throw new Error("file-target Lockbox secrets require fileBaseDir");
    const targetPath = safeSecretFilePath(input.fileBaseDir, secret.name);
    await files.mkdir(path.dirname(targetPath), { recursive: true });
    await files.writeFile(targetPath, secret.value, { encoding: "utf8", mode: 0o600 });
    await files.chmod(targetPath, 0o600);
    installed.files.push(record);
  }
  return installed;
}

async function postLockboxRuntimeJobSecretRequest(input: LockboxRuntimeLoadOptions & {
  fetchImpl: typeof fetch;
  request: LockboxRuntimeJobSecretSignedRequest;
}): Promise<LockboxRuntimeJobSecretResponse> {
  const url = new URL("/api/jobs/secret-requests", input.config.lockboxUrl);
  assertSecureRuntimeUrl(url, input.config.allowInsecureHttp, "Lockbox runtime secrets");
  await emit(input.diagnostics, {
    phase: "lockbox_request",
    ok: true,
    applicationId: input.request.applicationId,
    grantId: input.request.grantId,
    secretCount: input.request.requestedSecretIds.length
  });
  const response = await input.fetchImpl(url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(input.request)
  });
  const text = await response.text();
  const body = parseJson(text, "Lockbox response");
  if (!response.ok) throw new Error(`Lockbox rejected secret request: ${response.status} ${text.slice(0, 500)}`);
  const parsed = parseLockboxRuntimeJobSecretResponse(body);
  assertLockboxResponseBinding({ request: input.request, response: parsed });
  await emit(input.diagnostics, {
    phase: "lockbox_response",
    ok: true,
    status: response.status,
    applicationId: parsed.applicationId,
    grantId: parsed.grantId,
    requestId: parsed.requestId,
    secretCount: parsed.secretVersions.length
  });
  return parsed;
}

export function parseLockboxRuntimeJobSecretResponse(value: unknown): LockboxRuntimeJobSecretResponse {
  const record = asRecord(value, "Lockbox job secret response");
  if (record.ok !== true) throw new Error("Lockbox response did not include ok=true");
  return {
    ok: true,
    requestId: requiredString(record, "requestId"),
    grantId: requiredString(record, "grantId"),
    applicationId: requiredString(record, "applicationId"),
    repository: requiredString(record, "repository"),
    policyDigest: normalizePolicyDigest(requiredString(record, "policyDigest")),
    jobId: requiredString(record, "jobId"),
    deploymentId: requiredString(record, "deploymentId"),
    processorId: requiredString(record, "processorId"),
    requestedSecretIds: normalizeRequestedSecretIds(requiredStringArray(record, "requestedSecretIds")),
    responseKeyDigest: requiredString(record, "responseKeyDigest"),
    secretVersions: parseSecretVersionMetadata(record.secretVersions),
    encryptedPayload: parseLockboxEncryptedPayload(record.encryptedPayload)
  };
}

export function parseLockboxPlaintextPayload(value: unknown): LockboxRuntimeJobSecretPlaintextPayload {
  const record = asRecord(value, "Lockbox plaintext payload");
  if (record.domain !== LOCKBOX_RUNTIME_JOB_SECRET_RESPONSE_DOMAIN) {
    throw new Error("Lockbox plaintext payload has an unsupported domain");
  }
  return {
    domain: LOCKBOX_RUNTIME_JOB_SECRET_RESPONSE_DOMAIN,
    requestId: requiredString(record, "requestId"),
    grantId: requiredString(record, "grantId"),
    applicationId: requiredString(record, "applicationId"),
    repository: requiredString(record, "repository"),
    policyDigest: normalizePolicyDigest(requiredString(record, "policyDigest")),
    jobId: requiredString(record, "jobId"),
    deploymentId: requiredString(record, "deploymentId"),
    processorId: requiredString(record, "processorId"),
    issuedAtMs: integerTimestamp(requiredNumber(record, "issuedAtMs"), "issuedAtMs"),
    secrets: parsePlaintextSecrets(record.secrets)
  };
}

export function parseLockboxEncryptedPayload(value: unknown): LockboxRuntimeJobSecretEncryptedPayload {
  const record = asRecord(value, "Lockbox encrypted payload");
  if (record.domain !== LOCKBOX_RUNTIME_JOB_SECRET_ENCRYPTED_PAYLOAD_DOMAIN) {
    throw new Error("Lockbox encrypted payload has an unsupported domain");
  }
  const version = requiredString(record, "version");
  const curveName = requiredString(record, "curveName");
  if (version !== "acurast-p256-hkdf-aes-256-gcm-v1") throw new Error("Lockbox encrypted payload has an unsupported version");
  if (curveName !== "secp256r1") throw new Error("Lockbox encrypted payload has an unsupported curve");
  return {
    domain: LOCKBOX_RUNTIME_JOB_SECRET_ENCRYPTED_PAYLOAD_DOMAIN,
    version,
    curveName,
    senderPublicKey: requiredString(record, "senderPublicKey"),
    saltHex: requiredString(record, "saltHex"),
    ciphertextHex: requiredString(record, "ciphertextHex"),
    plaintextDigest: requiredString(record, "plaintextDigest"),
    encryptedPayloadDigest: requiredString(record, "encryptedPayloadDigest")
  };
}

function assertLockboxResponseBinding(input: {
  request: LockboxRuntimeJobSecretUnsignedRequest;
  response: LockboxRuntimeJobSecretResponse;
}): void {
  const request = canonicalLockboxRuntimeJobSecretRequest(input.request);
  const response = input.response;
  const expected: Array<[unknown, unknown, string]> = [
    [response.grantId, request.grantId, "grantId"],
    [response.applicationId, request.applicationId, "applicationId"],
    [response.policyDigest, request.policyDigest, "policyDigest"],
    [response.jobId, request.jobId, "jobId"],
    [response.deploymentId, request.deploymentId, "deploymentId"],
    [response.processorId, request.processorId, "processorId"],
    [response.requestedSecretIds.join(","), request.requestedSecretIds.join(","), "requestedSecretIds"]
  ];
  for (const [actual, wanted, label] of expected) {
    if (actual !== wanted) throw new Error(`Lockbox response ${label} did not match the signed request`);
  }
}

function assertLockboxPayloadBinding(input: {
  request: LockboxRuntimeJobSecretUnsignedRequest;
  response: LockboxRuntimeJobSecretResponse;
  payload: LockboxRuntimeJobSecretPlaintextPayload;
}): void {
  assertLockboxResponseBinding({ request: input.request, response: input.response });
  const request = canonicalLockboxRuntimeJobSecretRequest(input.request);
  const expected: Array<[unknown, unknown, string]> = [
    [input.payload.requestId, input.response.requestId, "requestId"],
    [input.payload.grantId, request.grantId, "grantId"],
    [input.payload.applicationId, request.applicationId, "applicationId"],
    [input.payload.policyDigest, request.policyDigest, "policyDigest"],
    [input.payload.jobId, request.jobId, "jobId"],
    [input.payload.deploymentId, request.deploymentId, "deploymentId"],
    [input.payload.processorId, request.processorId, "processorId"]
  ];
  for (const [actual, wanted, label] of expected) {
    if (actual !== wanted) throw new Error(`Lockbox plaintext payload ${label} did not match the signed request`);
  }
  const requested = new Set(request.requestedSecretIds);
  for (const secret of input.payload.secrets) {
    if (!requested.has(secret.secretId)) {
      throw new Error("Lockbox plaintext payload included a secret that was not requested");
    }
  }
}

function parsePlaintextSecrets(value: unknown): LockboxRuntimePlaintextSecret[] {
  if (!Array.isArray(value)) throw new Error("Lockbox plaintext payload secrets must be an array");
  return value.map((item) => {
    const record = asRecord(item, "Lockbox plaintext secret");
    const target = requiredString(record, "target");
    if (target !== "env" && target !== "file") throw new Error("Lockbox plaintext secret target must be env or file");
    return {
      secretId: requiredString(record, "secretId"),
      versionId: requiredString(record, "versionId"),
      target,
      name: requiredString(record, "name"),
      required: requiredBoolean(record, "required"),
      bundleId: requiredString(record, "bundleId"),
      value: requiredString(record, "value")
    };
  });
}

function parseSecretVersionMetadata(value: unknown): LockboxRuntimeSecretVersionMetadata[] {
  if (!Array.isArray(value)) throw new Error("Lockbox response secretVersions must be an array");
  return value.map((item) => {
    const record = asRecord(item, "Lockbox secret version metadata");
    const target = requiredString(record, "target");
    if (target !== "env" && target !== "file") throw new Error("Lockbox secret version target must be env or file");
    return {
      secretId: requiredString(record, "secretId"),
      versionId: requiredString(record, "versionId"),
      target,
      name: requiredString(record, "name"),
      required: requiredBoolean(record, "required"),
      bundleId: requiredString(record, "bundleId"),
      encryptedPayloadDigest: typeof record.encryptedPayloadDigest === "string" ? record.encryptedPayloadDigest : undefined
    };
  });
}

function requiredStringArray(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`${field} must be a string array`);
  }
  return value;
}

function safeSecretFilePath(baseDir: string, name: string): string {
  const cleanName = validSecretFileName(name);
  const base = path.resolve(baseDir);
  const target = path.resolve(base, cleanName);
  const relative = path.relative(base, target);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("file secret path escapes the configured base directory");
  }
  return target;
}

function validSecretFileName(name: string): string {
  if (name.length === 0 || name.includes("\0")) throw new Error("file secret name is invalid");
  return name;
}

function installedSecret(secret: LockboxRuntimePlaintextSecret): LockboxRuntimeInstalledSecret {
  return {
    secretId: secret.secretId,
    versionId: secret.versionId,
    target: secret.target,
    name: secret.name,
    bundleId: secret.bundleId
  };
}

async function emit(
  diagnostics: LockboxRuntimeLoadOptions["diagnostics"],
  event: LockboxRuntimeDiagnosticEvent
): Promise<void> {
  await Promise.resolve(diagnostics?.(event));
}

export function lockboxEncryptedPayloadDigest(
  encryptedPayload: Omit<LockboxRuntimeJobSecretEncryptedPayload, "encryptedPayloadDigest">
): string {
  return sha256Digest(canonicalJson(encryptedPayload));
}
