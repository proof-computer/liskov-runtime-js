import { createDecipheriv, createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type { BootstrapSlipwayRuntimeHandle } from "./index.js";

export const ENCRYPTED_CODE_DOMAIN = "proof.liskov.encrypted-code.v1";
export const ENCRYPTED_CODE_KEY_ENV = "LISKOV_CODE_KEY";
export const MAX_ENCRYPTED_CODE_BYTES = 16 * 1024 * 1024;

type LoadPhase = "descriptor" | "readiness" | "key_release" | "ciphertext"
  | "verification" | "directory" | "module_write" | "module_load"
  | "entrypoint" | "verified_event" | "application_start";

/** Public metadata inside the immutable, OIDC-attested bootstrap ZIP. */
export interface EncryptedCodeDescriptor {
  domain: typeof ENCRYPTED_CODE_DOMAIN;
  algorithm: "aes-256-gcm";
  keySecretId: string;
  iv: string;
  authTag: string;
  plaintextDigest: string;
  ciphertextDigest: string;
}

export function parseEncryptedCodeDescriptor(value: unknown): EncryptedCodeDescriptor {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("encrypted_code_descriptor_invalid");
  }
  const record = value as Record<string, unknown>;
  const fields = ["domain", "algorithm", "keySecretId", "iv", "authTag", "plaintextDigest", "ciphertextDigest"];
  if (Object.keys(record).length !== fields.length || fields.some((field) => typeof record[field] !== "string")) {
    throw new Error("encrypted_code_descriptor_invalid");
  }
  if (record.domain !== ENCRYPTED_CODE_DOMAIN || record.algorithm !== "aes-256-gcm"
    || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u.test(record.keySecretId as string)
    || !/^sha256:[0-9a-f]{64}$/u.test(record.plaintextDigest as string)
    || !/^sha256:[0-9a-f]{64}$/u.test(record.ciphertextDigest as string)
    || record.plaintextDigest === record.ciphertextDigest) {
    throw new Error("encrypted_code_descriptor_invalid");
  }
  decodeCanonicalBase64(record.iv as string, 12);
  decodeCanonicalBase64(record.authTag as string, 16);
  return record as unknown as EncryptedCodeDescriptor;
}

/** Domain-separate the payload and authenticate its key selector and plaintext identity. */
export function encryptedCodeAad(descriptor: Pick<EncryptedCodeDescriptor, "keySecretId" | "plaintextDigest">): Buffer {
  return Buffer.from(`${ENCRYPTED_CODE_DOMAIN}\n${descriptor.keySecretId}\n${descriptor.plaintextDigest}`, "utf8");
}

export function decryptEncryptedCode(ciphertext: Uint8Array, key: string, metadata: unknown): Buffer {
  const descriptor = parseEncryptedCodeDescriptor(metadata);
  if (ciphertext.length === 0 || ciphertext.length > MAX_ENCRYPTED_CODE_BYTES
    || digest(ciphertext) !== descriptor.ciphertextDigest) {
    throw new Error("encrypted_code_ciphertext_mismatch");
  }
  const keyBytes = decodeCanonicalBase64(key, 32);
  try {
    const decipher = createDecipheriv("aes-256-gcm", keyBytes, decodeCanonicalBase64(descriptor.iv, 12));
    decipher.setAAD(encryptedCodeAad(descriptor));
    decipher.setAuthTag(decodeCanonicalBase64(descriptor.authTag, 16));
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (digest(plaintext) !== descriptor.plaintextDigest) {
      plaintext.fill(0);
      throw new Error("encrypted_code_plaintext_mismatch");
    }
    return plaintext;
  } catch {
    // Crypto exceptions and source text must never reach diagnostics.
    throw new Error("encrypted_code_decryption_failed");
  } finally {
    keyBytes.fill(0);
  }
}

/**
 * Load a self-contained CommonJS module exporting start(runtime), after the
 * existing signed bootstrap and Lockbox release. No URL, eval or caller-chosen
 * output path is accepted. The public bootstrap ZIP binds metadata and bytes.
 */
export async function startEncryptedApplication(input: {
  runtime: BootstrapSlipwayRuntimeHandle;
  descriptor: unknown;
  ciphertextPath: string;
}): Promise<void> {
  const { runtime } = input;
  let directory: string | undefined;
  let filename: string | undefined;
  let loadModule: ReturnType<typeof createRequire> | undefined;
  let plaintext: Buffer | undefined;
  let phase: LoadPhase = "descriptor";
  try {
    const descriptor = parseEncryptedCodeDescriptor(input.descriptor);
    phase = "readiness";
    await runtime.whenReady();
    phase = "key_release";
    const release = runtime.lockbox;
    const status = runtime.status();
    const delivered = release?.installed.env.filter((secret) =>
      secret.secretId === descriptor.keySecretId && secret.name === ENCRYPTED_CODE_KEY_ENV);
    if (release === undefined || status.applicationUid === undefined
      || release.response.applicationUid !== status.applicationUid
      || release.response.deploymentId !== status.deploymentId
      || delivered?.length !== 1
      || !release.response.secretVersions.some((secret) => secret.secretId === delivered[0].secretId
        && secret.versionId === delivered[0].versionId && secret.target === "env"
        && secret.name === ENCRYPTED_CODE_KEY_ENV)) {
      throw new Error("encrypted_code_key_release_required");
    }
    phase = "ciphertext";
    const ciphertext = await readFile(input.ciphertextPath);
    phase = "verification";
    plaintext = decryptEncryptedCode(ciphertext, runtime.env.require(ENCRYPTED_CODE_KEY_ENV), descriptor);
    // A fresh 0700 directory and exclusive 0600 write prevent cache reuse and
    // path/symlink substitution across boots. Only authenticated bytes reach it.
    phase = "directory";
    await mkdir(runtime.home, { recursive: true, mode: 0o700 });
    directory = await mkdtemp(path.join(runtime.home, "encrypted-code-"));
    filename = path.resolve(directory, "application.cjs");
    phase = "module_write";
    await writeFile(filename, plaintext, { mode: 0o600, flag: "wx" });
    plaintext.fill(0);
    plaintext = undefined;
    // The payload contract is CommonJS. Use its loader directly: embedded
    // Node contexts need not install a host callback for dynamic import().
    phase = "module_load";
    loadModule = createRequire(pathToFileURL(filename));
    const module = loadModule(filename);
    phase = "entrypoint";
    const start = module.start ?? module.default?.start;
    if (typeof start !== "function") throw new Error("encrypted_code_start_missing");
    phase = "verified_event";
    await runtime.diagnostics.report({
      stage: "application.encrypted_code.loaded", status: "succeeded",
      code: "encrypted_code_verified", attrs: { plaintextDigest: descriptor.plaintextDigest,
        ciphertextDigest: descriptor.ciphertextDigest }
    });
    phase = "application_start";
    await start(runtime);
  } catch {
    // A bounded phase is useful evidence without inspecting an exception that
    // may contain private source, keys, paths or application-controlled text.
    // The separate detail event keeps the existing fatal code/metric stable.
    await runtime.diagnostics.report({
      stage: `application.encrypted_code.refused.${phase}`, status: "failed",
      code: "encrypted_code_failure_detail", attrs: { phase }
    });
    await runtime.diagnostics.fatal({ kind: "application_start", code: "encrypted_code_start_failed",
      message: `Encrypted application could not be verified and started (${phase})`, attrs: { phase } });
    throw new Error("encrypted_code_start_failed");
  } finally {
    plaintext?.fill(0);
    if (filename !== undefined && loadModule !== undefined) delete loadModule.cache[filename];
    if (directory !== undefined) await rm(directory, { recursive: true, force: true });
  }
}

function digest(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function decodeCanonicalBase64(value: string, size: number): Buffer {
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== size || bytes.toString("base64") !== value) {
    throw new Error("encrypted_code_base64_invalid");
  }
  return bytes;
}
