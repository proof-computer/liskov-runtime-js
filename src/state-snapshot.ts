import { Buffer } from "node:buffer";
import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign as signEd25519,
  timingSafeEqual,
  verify as verifyEd25519
} from "node:crypto";

const CHUNK_KEY_INFO = "liskov-state-chunk-key-v1";
const CHUNK_ID_KEY_INFO = "liskov-state-chunk-id-v1";
const CHUNK_AAD_DOMAIN = "liskov-state-chunk-v1";
const CHUNK_FORMAT_VERSION = 0x01;
const CHUNK_NONCE_LENGTH = 12;
const CHUNK_TAG_LENGTH = 16;
const CHUNK_MIN_OBJECT_LENGTH = 1 + CHUNK_NONCE_LENGTH + CHUNK_TAG_LENGTH;

// The HKDF label says GCM-SIV; the cipher is AES-256-GCM. That is the grant scheme.
const GRANT_VERSION = "acurast-p256-hkdf-aes-256-gcm-v1";
const GRANT_CURVE_NAME = "secp256r1";
const GRANT_LABEL = Buffer.from("ECDH secp256r1 AES-256-GCM-SIV", "ascii");
const GRANT_SALT_LENGTH = 16;
const GRANT_IV_LENGTH = 12;
const WRAPPED_PLAINTEXT_VERSION = 1;

export const MANIFEST_SIGNATURE_DOMAIN = "liskov-state-manifest-v1";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const RECIPIENT_KINDS = ["lockbox", "job", "customer", "broker_share"] as const;
const MANIFEST_KEYS = [
  "v", "org", "application", "lineage", "sequence", "writer",
  "capturedAtMs", "dekVersion", "plaintextBytes", "chunks", "recipients"
] as const;
const MANIFEST_KEYS_WITH_PREVIOUS = [
  "v", "org", "application", "lineage", "sequence", "previousManifestDigest", "writer",
  "capturedAtMs", "dekVersion", "plaintextBytes", "chunks", "recipients"
] as const;
const WRITER_KEYS = ["jobId", "processorId", "generation", "signerPublicKey"] as const;
const CHUNK_ENTRY_KEYS = ["id", "plaintextBytes", "objectBytes"] as const;
const WRAPPED_KEYS = ["recipientKind", "recipientKeyId", "dekVersion", "grant"] as const;
const GRANT_KEYS = ["version", "curveName", "senderPublicKey", "saltHex", "ciphertextHex"] as const;
const WRAPPED_PLAINTEXT_KEYS = ["v", "org", "application", "lineage", "dekVersion", "dek"] as const;

export type RecipientKind = (typeof RECIPIENT_KINDS)[number];

export type StateSnapshotErrorCode =
  | "ChunkTruncated"
  | "UnsupportedChunkVersion"
  | "Decrypt"
  | "ChunkIdMismatch"
  | "Encoding"
  | "InvalidKey"
  | "RecipientKeyMismatch"
  | "WrappedKeyBinding"
  | "Malformed"
  | "SizeMismatch"
  | "SignerMismatch"
  | "BadSignature"
  | "CrossLineage"
  | "SequenceNotAdvanced"
  | "SequenceGap"
  | "Fork";

export class StateSnapshotError extends Error {
  readonly code: StateSnapshotErrorCode;
  readonly len?: number;
  readonly version?: number;
  readonly field?: string;
  readonly declared?: number;
  readonly chunks?: number;
  readonly previous?: number;
  readonly next?: number;

  constructor(code: StateSnapshotErrorCode, message: string, details: {
    len?: number;
    version?: number;
    field?: string;
    declared?: number;
    chunks?: number;
    previous?: number;
    next?: number;
  } = {}) {
    super(message);
    this.name = "StateSnapshotError";
    this.code = code;
    this.len = details.len;
    this.version = details.version;
    this.field = details.field;
    this.declared = details.declared;
    this.chunks = details.chunks;
    this.previous = details.previous;
    this.next = details.next;
  }
}

export interface SealedChunk {
  chunkId: Buffer;
  object: Buffer;
}

export interface DataKeyBinding {
  org: string;
  application: string;
  lineage: string;
  dekVersion: number;
}

export interface GrantPayload {
  version: string;
  curveName: string;
  senderPublicKey: Uint8Array;
  salt: Uint8Array;
  ciphertext: Uint8Array;
}

export interface WrappedDataKey {
  recipientKind: RecipientKind;
  recipientKeyId: string;
  dekVersion: number;
  grant: GrantPayload;
}

export interface ManifestChunk {
  id: Uint8Array;
  plaintextBytes: number;
  objectBytes: number;
}

export interface ManifestWriter {
  jobId: string;
  processorId: string;
  generation: number;
  signerPublicKey: Uint8Array;
}

export interface Manifest {
  v: number;
  org: string;
  application: string;
  lineage: string;
  sequence: number;
  previousManifestDigest?: Uint8Array;
  writer: ManifestWriter;
  capturedAtMs: number;
  dekVersion: number;
  plaintextBytes: number;
  chunks: ManifestChunk[];
  recipients: WrappedDataKey[];
}

function malformed(field: string): never {
  throw new StateSnapshotError("Malformed", `manifest is not well formed: ${field}`, { field });
}

function encoding(field: string): never {
  throw new StateSnapshotError("Encoding", `invalid encoding: ${field}`, { field });
}

function invalidKey(): never {
  throw new StateSnapshotError("InvalidKey", "invalid key material");
}

function decryptFailed(): never {
  throw new StateSnapshotError("Decrypt", "decrypt failed");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSafeNonNegative(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isRecipientKind(value: unknown): value is RecipientKind {
  return typeof value === "string" && (RECIPIENT_KINDS as readonly string[]).includes(value);
}

function sameKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  if (actual.length !== keys.length) return false;
  for (let index = 0; index < keys.length; index += 1) {
    if (actual[index] !== keys[index]) return false;
  }
  return true;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function requireBytes(value: Uint8Array, length: number, code: "InvalidKey" | "Encoding"): Buffer {
  const bytes = Buffer.from(value);
  if (bytes.length !== length) {
    if (code === "InvalidKey") invalidKey();
    encoding("length");
  }
  return bytes;
}

function trimAsciiSpaceAndTab(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && (value.charCodeAt(start) === 0x20 || value.charCodeAt(start) === 0x09)) start += 1;
  while (end > start && (value.charCodeAt(end - 1) === 0x20 || value.charCodeAt(end - 1) === 0x09)) end -= 1;
  return value.slice(start, end);
}

/**
 * True only when `enabled` is exactly `true` and `applicationId` is a non-empty
 * allowlist entry. Entries are split on commas; only ASCII space and tab are trimmed.
 * Does not read the environment.
 */
export function statePlaneEnabled(
  enabled: string | undefined,
  applications: string | undefined,
  applicationId: string | undefined
): boolean {
  if (enabled !== "true" || typeof applications !== "string"
    || typeof applicationId !== "string" || applicationId.length === 0) {
    return false;
  }
  for (const entry of applications.split(",")) {
    const id = trimAsciiSpaceAndTab(entry);
    if (id.length > 0 && id === applicationId) return true;
  }
  return false;
}

function lineageSalt(lineageId: string): Buffer {
  if (typeof lineageId !== "string") encoding("lineage");
  return Buffer.from(lineageId, "utf8");
}

function hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer): Buffer {
  try {
    return Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
  } catch (error) {
    if (error instanceof StateSnapshotError) throw error;
    invalidKey();
  }
}

export function deriveChunkKey(dek: Uint8Array, lineageId: string): Buffer {
  return hkdfSha256(requireBytes(dek, 32, "InvalidKey"), lineageSalt(lineageId), Buffer.from(CHUNK_KEY_INFO, "ascii"));
}

export function deriveChunkIdKey(dek: Uint8Array, lineageId: string): Buffer {
  return hkdfSha256(requireBytes(dek, 32, "InvalidKey"), lineageSalt(lineageId), Buffer.from(CHUNK_ID_KEY_INFO, "ascii"));
}

// Keyed so a store that sees chunk ids cannot confirm a guessed plaintext.
export function chunkId(dek: Uint8Array, lineageId: string, plaintext: Uint8Array): Buffer {
  return createHmac("sha256", deriveChunkIdKey(dek, lineageId)).update(Buffer.from(plaintext)).digest();
}

export function sealChunk(
  dek: Uint8Array,
  lineageId: string,
  nonce: Uint8Array,
  plaintext: Uint8Array
): SealedChunk {
  const dekBytes = requireBytes(dek, 32, "InvalidKey");
  const nonceBytes = requireBytes(nonce, CHUNK_NONCE_LENGTH, "Encoding");
  const plain = Buffer.from(plaintext);
  const salt = lineageSalt(lineageId);
  const id = createHmac("sha256", hkdfSha256(dekBytes, salt, Buffer.from(CHUNK_ID_KEY_INFO, "ascii"))).update(plain).digest();
  const key = hkdfSha256(dekBytes, salt, Buffer.from(CHUNK_KEY_INFO, "ascii"));
  const aad = Buffer.concat([Buffer.from(CHUNK_AAD_DOMAIN, "ascii"), salt, id]);
  const cipher = createCipheriv("aes-256-gcm", key, nonceBytes);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return {
    chunkId: id,
    object: Buffer.concat([Buffer.from([CHUNK_FORMAT_VERSION]), nonceBytes, body])
  };
}

export function openChunk(
  dek: Uint8Array,
  lineageId: string,
  expectedChunkId: Uint8Array,
  object: Uint8Array
): Buffer {
  const bytes = Buffer.from(object);
  if (bytes.length < CHUNK_MIN_OBJECT_LENGTH) {
    throw new StateSnapshotError("ChunkTruncated", `state chunk object is truncated (${bytes.length} bytes)`, {
      len: bytes.length
    });
  }
  if (bytes[0] !== CHUNK_FORMAT_VERSION) {
    throw new StateSnapshotError("UnsupportedChunkVersion", `unsupported state chunk format version ${bytes[0]}`, {
      version: bytes[0]
    });
  }
  const dekBytes = requireBytes(dek, 32, "InvalidKey");
  const salt = lineageSalt(lineageId);
  const expected = Buffer.from(expectedChunkId);
  const nonce = bytes.subarray(1, 1 + CHUNK_NONCE_LENGTH);
  const bodyTag = bytes.subarray(1 + CHUNK_NONCE_LENGTH);
  const tag = bodyTag.subarray(bodyTag.length - CHUNK_TAG_LENGTH);
  const ciphertext = bodyTag.subarray(0, bodyTag.length - CHUNK_TAG_LENGTH);
  const key = hkdfSha256(dekBytes, salt, Buffer.from(CHUNK_KEY_INFO, "ascii"));
  const aad = Buffer.concat([Buffer.from(CHUNK_AAD_DOMAIN, "ascii"), salt, expected]);
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    decryptFailed();
  }
  const actual = createHmac("sha256", hkdfSha256(dekBytes, salt, Buffer.from(CHUNK_ID_KEY_INFO, "ascii")))
    .update(plaintext)
    .digest();
  if (!bytesEqual(actual, expected)) {
    throw new StateSnapshotError("ChunkIdMismatch", "state chunk plaintext does not match its chunk id");
  }
  return plaintext;
}

function p256(privateKey: Buffer): ReturnType<typeof createECDH> {
  if (privateKey.length !== 32) invalidKey();
  const ecdh = createECDH("prime256v1");
  try {
    ecdh.setPrivateKey(privateKey);
  } catch {
    invalidKey();
  }
  return ecdh;
}

// Node has no SEC1 compress helper. Once the point is accepted, Y's parity is the prefix.
function compressP256(pub: Buffer): Buffer {
  if (pub.length !== 33 && pub.length !== 65) invalidKey();
  const probe = createECDH("prime256v1");
  probe.generateKeys();
  try {
    probe.computeSecret(pub);
  } catch {
    invalidKey();
  }
  if (pub.length === 33 && (pub[0] === 0x02 || pub[0] === 0x03)) return Buffer.from(pub);
  if (pub.length === 65 && pub[0] === 0x04) {
    const prefix = (pub[64] & 1) === 0 ? 0x02 : 0x03;
    return Buffer.concat([Buffer.from([prefix]), pub.subarray(1, 33)]);
  }
  invalidKey();
}

export function recipientKeyId(recipientPub: Uint8Array): string {
  return createHash("sha256").update(compressP256(Buffer.from(recipientPub))).digest("hex");
}

function sortedConcat(left: Buffer, right: Buffer): Buffer {
  const leftFirst = left.length !== right.length ? left.length < right.length : Buffer.compare(left, right) <= 0;
  return leftFirst ? Buffer.concat([left, right]) : Buffer.concat([right, left]);
}

function grantEncrypt(
  senderPriv: Buffer,
  senderPub: Buffer,
  recipientPub: Buffer,
  salt: Buffer,
  iv: Buffer,
  plaintext: Buffer
): Buffer {
  let shared: Buffer;
  try {
    shared = p256(senderPriv).computeSecret(recipientPub);
  } catch (error) {
    if (error instanceof StateSnapshotError) throw error;
    invalidKey();
  }
  const key = hkdfSha256(shared, salt, Buffer.concat([GRANT_LABEL, sortedConcat(senderPub, recipientPub)]));
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, body, cipher.getAuthTag()]);
}

function grantDecrypt(
  recipientPriv: Buffer,
  recipientPub: Buffer,
  senderPub: Buffer,
  salt: Buffer,
  payload: Buffer
): Buffer {
  if (payload.length < GRANT_IV_LENGTH + CHUNK_TAG_LENGTH) decryptFailed();
  const iv = payload.subarray(0, GRANT_IV_LENGTH);
  const tag = payload.subarray(payload.length - CHUNK_TAG_LENGTH);
  const body = payload.subarray(GRANT_IV_LENGTH, payload.length - CHUNK_TAG_LENGTH);
  try {
    const shared = p256(recipientPriv).computeSecret(senderPub);
    const key = hkdfSha256(shared, salt, Buffer.concat([GRANT_LABEL, sortedConcat(recipientPub, senderPub)]));
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    decryptFailed();
  }
}

function encodeWrappedPlaintext(binding: DataKeyBinding, dek: Buffer): Buffer {
  return Buffer.from(JSON.stringify({
    v: WRAPPED_PLAINTEXT_VERSION,
    org: binding.org,
    application: binding.application,
    lineage: binding.lineage,
    dekVersion: binding.dekVersion,
    dek: dek.toString("hex")
  }), "utf8");
}

function requireBinding(binding: DataKeyBinding): void {
  if (typeof binding.org !== "string" || typeof binding.application !== "string"
    || typeof binding.lineage !== "string" || !isSafeNonNegative(binding.dekVersion)) {
    encoding("binding");
  }
}

export function wrapDataKey(
  dek: Uint8Array,
  binding: DataKeyBinding,
  recipientKind: RecipientKind,
  recipientPub: Uint8Array,
  senderPriv: Uint8Array,
  salt: Uint8Array,
  iv: Uint8Array
): WrappedDataKey {
  requireBinding(binding);
  if (!isRecipientKind(recipientKind)) encoding("recipientKind");
  const dekBytes = requireBytes(dek, 32, "InvalidKey");
  const saltBytes = requireBytes(salt, GRANT_SALT_LENGTH, "Encoding");
  const ivBytes = requireBytes(iv, GRANT_IV_LENGTH, "Encoding");
  const senderKey = p256(requireBytes(senderPriv, 32, "InvalidKey"));
  const senderPub = Buffer.from(senderKey.getPublicKey(null, "compressed"));
  const recipient = Buffer.from(recipientPub);
  const keyId = recipientKeyId(recipient);
  // The grant takes no AAD, so the binding travels inside the plaintext.
  const plaintext = encodeWrappedPlaintext(binding, dekBytes);
  try {
    const ciphertext = grantEncrypt(requireBytes(senderPriv, 32, "InvalidKey"), senderPub, recipient, saltBytes, ivBytes, plaintext);
    return {
      recipientKind,
      recipientKeyId: keyId,
      dekVersion: binding.dekVersion,
      grant: {
        version: GRANT_VERSION,
        curveName: GRANT_CURVE_NAME,
        senderPublicKey: Buffer.from(senderPub),
        salt: Buffer.from(saltBytes),
        ciphertext
      }
    };
  } finally {
    plaintext.fill(0);
  }
}

interface ParsedWrappedPlaintext {
  org: string;
  application: string;
  lineage: string;
  dekVersion: number;
  dek: Buffer;
}

function parseCanonicalWrappedPlaintext(plaintext: Buffer): ParsedWrappedPlaintext {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext.toString("utf8")) as unknown;
  } catch {
    encoding("wrapped plaintext");
  }
  if (!isRecord(parsed) || !sameKeys(parsed, WRAPPED_PLAINTEXT_KEYS)) encoding("wrapped plaintext");
  if (parsed.v !== WRAPPED_PLAINTEXT_VERSION) encoding("wrapped plaintext version");
  if (typeof parsed.org !== "string" || typeof parsed.application !== "string" || typeof parsed.lineage !== "string") {
    encoding("wrapped plaintext");
  }
  if (!isSafeNonNegative(parsed.dekVersion)) encoding("dekVersion");
  if (typeof parsed.dek !== "string" || !/^[0-9a-f]{64}$/.test(parsed.dek)) encoding("dek");
  const dek = Buffer.from(parsed.dek, "hex");
  const canonical = encodeWrappedPlaintext({
    org: parsed.org,
    application: parsed.application,
    lineage: parsed.lineage,
    dekVersion: parsed.dekVersion
  }, dek);
  if (!canonical.equals(plaintext)) encoding("wrapped plaintext");
  return {
    org: parsed.org,
    application: parsed.application,
    lineage: parsed.lineage,
    dekVersion: parsed.dekVersion,
    dek
  };
}

export function unwrapDataKey(
  wrapped: WrappedDataKey,
  recipientPriv: Uint8Array,
  recipientPub: Uint8Array,
  expected: DataKeyBinding
): Buffer {
  if (wrapped.grant.version !== GRANT_VERSION || wrapped.grant.curveName !== GRANT_CURVE_NAME) {
    encoding("grant scheme");
  }
  requireBinding(expected);
  const recipientPrivate = requireBytes(recipientPriv, 32, "InvalidKey");
  const ownKeyId = createHash("sha256")
    .update(Buffer.from(p256(recipientPrivate).getPublicKey(null, "compressed")))
    .digest("hex");
  const givenPub = Buffer.from(recipientPub);
  if (recipientKeyId(givenPub) !== ownKeyId) invalidKey();
  if (wrapped.recipientKeyId !== ownKeyId) {
    throw new StateSnapshotError("RecipientKeyMismatch", "wrapped data key is for a different recipient key");
  }
  if (wrapped.dekVersion !== expected.dekVersion) {
    throw new StateSnapshotError("WrappedKeyBinding", "wrapped data key is bound to a different dekVersion", {
      field: "dekVersion"
    });
  }
  const plaintext = grantDecrypt(
    recipientPrivate,
    givenPub,
    Buffer.from(wrapped.grant.senderPublicKey),
    Buffer.from(wrapped.grant.salt),
    Buffer.from(wrapped.grant.ciphertext)
  );
  try {
    const inner = parseCanonicalWrappedPlaintext(plaintext);
    const fields = [
      ["org", inner.org, expected.org],
      ["application", inner.application, expected.application],
      ["lineage", inner.lineage, expected.lineage]
    ] as const;
    for (const [field, got, want] of fields) {
      if (got !== want) {
        throw new StateSnapshotError("WrappedKeyBinding", `wrapped data key is bound to a different ${field}`, { field });
      }
    }
    if (inner.dekVersion !== expected.dekVersion) {
      throw new StateSnapshotError("WrappedKeyBinding", "wrapped data key is bound to a different dekVersion", {
        field: "dekVersion"
      });
    }
    return Buffer.from(inner.dek);
  } finally {
    plaintext.fill(0);
  }
}

function readLowerHex(value: unknown, fail: () => never, byteLength?: number): Buffer {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) fail();
  const bytes = Buffer.from(value, "hex");
  if (byteLength !== undefined && bytes.length !== byteLength) fail();
  return bytes;
}

function readCount(value: unknown, field: string): number {
  if (!isSafeNonNegative(value)) malformed(field);
  return value;
}

function readUtf8(value: unknown, field: string): string {
  if (typeof value !== "string") malformed(field);
  return value;
}

function readChunk(value: unknown): ManifestChunk {
  if (!isRecord(value) || !sameKeys(value, CHUNK_ENTRY_KEYS)) malformed("chunks");
  return {
    id: readLowerHex(value.id, () => malformed("chunks[].id"), 32),
    plaintextBytes: readCount(value.plaintextBytes, "chunks[].plaintextBytes"),
    objectBytes: readCount(value.objectBytes, "chunks[].objectBytes")
  };
}

function readWrapped(value: unknown, fail: (field: string) => never): WrappedDataKey {
  if (!isRecord(value) || !sameKeys(value, WRAPPED_KEYS)) fail("wrapped");
  if (!isRecipientKind(value.recipientKind)) fail("recipientKind");
  const recipientKeyIdHex = value.recipientKeyId;
  if (typeof recipientKeyIdHex !== "string" || !/^[0-9a-f]{64}$/.test(recipientKeyIdHex)) fail("recipientKeyId");
  if (!isSafeNonNegative(value.dekVersion)) fail("dekVersion");
  if (!isRecord(value.grant) || !sameKeys(value.grant, GRANT_KEYS)) fail("grant");
  const grant = value.grant;
  if (typeof grant.version !== "string") fail("grant.version");
  if (typeof grant.curveName !== "string") fail("grant.curveName");
  return {
    recipientKind: value.recipientKind,
    recipientKeyId: recipientKeyIdHex,
    dekVersion: value.dekVersion,
    grant: {
      version: grant.version,
      curveName: grant.curveName,
      senderPublicKey: readLowerHex(grant.senderPublicKey, () => fail("grant.senderPublicKey")),
      salt: readLowerHex(grant.saltHex, () => fail("grant.saltHex")),
      ciphertext: readLowerHex(grant.ciphertextHex, () => fail("grant.ciphertextHex"))
    }
  };
}

export function parseWrappedDataKey(value: unknown): WrappedDataKey {
  return readWrapped(value, (field) => encoding(field));
}

export function parseManifest(value: unknown): Manifest {
  if (!isRecord(value)) malformed("manifest");
  const hasPrevious = sameKeys(value, MANIFEST_KEYS_WITH_PREVIOUS);
  if (!hasPrevious && !sameKeys(value, MANIFEST_KEYS)) malformed("manifest");
  if (value.v !== 1) malformed("v");
  const manifest: Manifest = {
    v: 1,
    org: readUtf8(value.org, "org"),
    application: readUtf8(value.application, "application"),
    lineage: readUtf8(value.lineage, "lineage"),
    sequence: readCount(value.sequence, "sequence"),
    writer: readWriter(value.writer),
    capturedAtMs: readCount(value.capturedAtMs, "capturedAtMs"),
    dekVersion: readCount(value.dekVersion, "dekVersion"),
    plaintextBytes: readCount(value.plaintextBytes, "plaintextBytes"),
    chunks: readChunks(value.chunks),
    recipients: readRecipients(value.recipients)
  };
  if (hasPrevious) {
    if (value.previousManifestDigest === null || value.previousManifestDigest === undefined) {
      malformed("previousManifestDigest");
    }
    manifest.previousManifestDigest = readLowerHex(
      value.previousManifestDigest,
      () => malformed("previousManifestDigest"),
      32
    );
  }
  return manifest;
}

function readWriter(value: unknown): ManifestWriter {
  if (!isRecord(value) || !sameKeys(value, WRITER_KEYS)) malformed("writer");
  return {
    jobId: readUtf8(value.jobId, "writer.jobId"),
    processorId: readUtf8(value.processorId, "writer.processorId"),
    generation: readCount(value.generation, "writer.generation"),
    signerPublicKey: readLowerHex(value.signerPublicKey, () => malformed("writer.signerPublicKey"), 32)
  };
}

function readChunks(value: unknown): ManifestChunk[] {
  if (!Array.isArray(value)) malformed("chunks");
  return value.map((chunk) => readChunk(chunk));
}

function readRecipients(value: unknown): WrappedDataKey[] {
  if (!Array.isArray(value)) malformed("recipients");
  return value.map((recipient) => readWrapped(recipient, (field) => malformed(`recipients[].${field}`)));
}

function checkWellFormed(manifest: Manifest): void {
  if (manifest.v !== 1) malformed("v");
  if (typeof manifest.org !== "string" || manifest.org.length === 0) malformed("org");
  if (typeof manifest.application !== "string" || manifest.application.length === 0) malformed("application");
  if (typeof manifest.lineage !== "string" || manifest.lineage.length === 0) malformed("lineage");
  if (manifest.writer === undefined || manifest.writer === null || typeof manifest.writer !== "object") malformed("writer");
  if (typeof manifest.writer.jobId !== "string" || manifest.writer.jobId.length === 0) malformed("writer.jobId");
  if (typeof manifest.writer.processorId !== "string" || manifest.writer.processorId.length === 0) {
    malformed("writer.processorId");
  }
  if (!isSafeNonNegative(manifest.sequence) || manifest.sequence < 1) malformed("sequence");
  const previous = manifest.previousManifestDigest;
  if ((manifest.sequence === 1) !== (previous === undefined)) malformed("previousManifestDigest");
  if (previous !== undefined && previous.length !== 32) malformed("previousManifestDigest");
  for (const [field, value] of [
    ["sequence", manifest.sequence],
    ["writer.generation", manifest.writer.generation],
    ["capturedAtMs", manifest.capturedAtMs],
    ["dekVersion", manifest.dekVersion],
    ["plaintextBytes", manifest.plaintextBytes]
  ] as const) {
    if (!isSafeNonNegative(value)) malformed(field);
  }
  if (!(manifest.writer.signerPublicKey instanceof Uint8Array) || manifest.writer.signerPublicKey.length !== 32) {
    malformed("writer.signerPublicKey");
  }
  if (!Array.isArray(manifest.chunks)) malformed("chunks");
  let chunkSum = 0;
  for (const chunk of manifest.chunks) {
    if (chunk === null || typeof chunk !== "object" || !(chunk.id instanceof Uint8Array) || chunk.id.length !== 32) {
      malformed("chunks[].id");
    }
    if (!isSafeNonNegative(chunk.plaintextBytes)) malformed("chunks[].plaintextBytes");
    if (!isSafeNonNegative(chunk.objectBytes)) malformed("chunks[].objectBytes");
    chunkSum += chunk.plaintextBytes;
    if (!Number.isSafeInteger(chunkSum)) malformed("chunks[].plaintextBytes");
  }
  if (!Array.isArray(manifest.recipients)) malformed("recipients");
  for (const recipient of manifest.recipients) {
    if (!isRecipientKind(recipient.recipientKind)) malformed("recipients[].recipientKind");
    if (!isSafeNonNegative(recipient.dekVersion) || recipient.dekVersion !== manifest.dekVersion) {
      malformed("recipients[].dekVersion");
    }
    if (typeof recipient.recipientKeyId !== "string" || !/^[0-9a-f]{64}$/.test(recipient.recipientKeyId)) {
      malformed("recipients[].recipientKeyId");
    }
    const grant = recipient.grant;
    if (grant === undefined || grant === null || typeof grant !== "object") malformed("recipients[].grant");
    if (typeof grant.version !== "string") malformed("recipients[].grant.version");
    if (typeof grant.curveName !== "string") malformed("recipients[].grant.curveName");
    if (!(grant.senderPublicKey instanceof Uint8Array)) malformed("recipients[].grant.senderPublicKey");
    if (!(grant.salt instanceof Uint8Array)) malformed("recipients[].grant.saltHex");
    if (!(grant.ciphertext instanceof Uint8Array)) malformed("recipients[].grant.ciphertextHex");
  }
  if (chunkSum !== manifest.plaintextBytes) {
    throw new StateSnapshotError(
      "SizeMismatch",
      `manifest plaintextBytes ${manifest.plaintextBytes} disagrees with its chunks' sum ${chunkSum}`,
      { declared: manifest.plaintextBytes, chunks: chunkSum }
    );
  }
}

function u32(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) malformed("length");
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function u64(value: number): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

function encodeBytes(value: Uint8Array): Buffer {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32(bytes.length), bytes]);
}

function encodeStr(value: string): Buffer {
  return encodeBytes(Buffer.from(value, "utf8"));
}

export function canonicalBytes(manifest: Manifest): Buffer {
  checkWellFormed(manifest);
  const parts: Buffer[] = [
    u64(manifest.v),
    encodeStr(manifest.org),
    encodeStr(manifest.application),
    encodeStr(manifest.lineage),
    u64(manifest.sequence)
  ];
  if (manifest.previousManifestDigest === undefined) {
    parts.push(Buffer.from([0x00]));
  } else {
    parts.push(Buffer.concat([Buffer.from([0x01]), Buffer.from(manifest.previousManifestDigest)]));
  }
  parts.push(
    encodeStr(manifest.writer.jobId),
    encodeStr(manifest.writer.processorId),
    u64(manifest.writer.generation),
    Buffer.from(manifest.writer.signerPublicKey),
    u64(manifest.capturedAtMs),
    u64(manifest.dekVersion),
    u64(manifest.plaintextBytes),
    u32(manifest.chunks.length)
  );
  for (const chunk of manifest.chunks) {
    parts.push(Buffer.from(chunk.id), u64(chunk.plaintextBytes), u64(chunk.objectBytes));
  }
  parts.push(u32(manifest.recipients.length));
  for (const recipient of manifest.recipients) {
    parts.push(
      encodeStr(recipient.recipientKind),
      Buffer.from(recipient.recipientKeyId, "hex"),
      u64(recipient.dekVersion),
      encodeStr(recipient.grant.version),
      encodeStr(recipient.grant.curveName),
      encodeBytes(recipient.grant.senderPublicKey),
      encodeBytes(recipient.grant.salt),
      encodeBytes(recipient.grant.ciphertext)
    );
  }
  return Buffer.concat(parts);
}

export function manifestDigest(manifest: Manifest): Buffer {
  return createHash("sha256").update(canonicalBytes(manifest)).digest();
}

function ed25519PrivateKey(seed: Buffer): ReturnType<typeof createPrivateKey> {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8"
  });
}

function ed25519PublicRaw(seed: Buffer): Buffer {
  try {
    const exported = createPublicKey(ed25519PrivateKey(seed)).export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(exported)) invalidKey();
    return Buffer.from(exported.subarray(exported.length - 32));
  } catch (error) {
    if (error instanceof StateSnapshotError) throw error;
    invalidKey();
  }
}

function ed25519KeyFromRaw(raw: Buffer): ReturnType<typeof createPublicKey> {
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk"
  });
}

function signedMessage(digest: Buffer): Buffer {
  return Buffer.concat([Buffer.from(MANIFEST_SIGNATURE_DOMAIN, "ascii"), digest]);
}

export function signManifest(manifest: Manifest, seed: Uint8Array): Buffer {
  const seedBytes = requireBytes(seed, 32, "InvalidKey");
  const declared = manifest.writer?.signerPublicKey;
  if (!(declared instanceof Uint8Array) || !bytesEqual(ed25519PublicRaw(seedBytes), declared)) {
    throw new StateSnapshotError("SignerMismatch", "manifest signer is not the trusted key");
  }
  return signEd25519(null, signedMessage(manifestDigest(manifest)), ed25519PrivateKey(seedBytes));
}

export function verifyManifestSignature(
  manifest: Manifest,
  signature: Uint8Array,
  trustedSigner: Uint8Array
): Buffer {
  const digest = manifestDigest(manifest);
  const trusted = Buffer.from(trustedSigner);
  const declared = manifest.writer?.signerPublicKey;
  if (!(declared instanceof Uint8Array) || !bytesEqual(declared, trusted)) {
    throw new StateSnapshotError("SignerMismatch", "manifest signer is not the trusted key");
  }
  const sig = Buffer.from(signature);
  let verified = false;
  if (sig.length === 64) {
    try {
      verified = verifyEd25519(null, signedMessage(digest), ed25519KeyFromRaw(trusted), sig);
    } catch {
      verified = false;
    }
  }
  if (!verified) throw new StateSnapshotError("BadSignature", "manifest signature does not verify");
  return digest;
}

export function verifySuccessor(previous: Manifest, next: Manifest): void {
  const previousDigest = manifestDigest(previous);
  checkWellFormed(next);
  for (const field of ["org", "application", "lineage"] as const) {
    if (previous[field] !== next[field]) {
      throw new StateSnapshotError("CrossLineage", `successor manifest is for a different ${field}`, { field });
    }
  }
  if (next.sequence <= previous.sequence) {
    throw new StateSnapshotError(
      "SequenceNotAdvanced",
      `successor sequence ${next.sequence} does not advance past ${previous.sequence}`,
      { previous: previous.sequence, next: next.sequence }
    );
  }
  if (next.sequence !== previous.sequence + 1) {
    throw new StateSnapshotError(
      "SequenceGap",
      `successor sequence ${next.sequence} skips past ${previous.sequence}`,
      { previous: previous.sequence, next: next.sequence }
    );
  }
  const named = next.previousManifestDigest;
  if (named === undefined || !bytesEqual(named, previousDigest)) {
    throw new StateSnapshotError("Fork", "successor names a different predecessor digest");
  }
}
