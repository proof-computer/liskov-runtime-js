import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface ProofLogEncryptedRecord {
  v: 1;
  alg: "A256GCM";
  iv: string;
  ciphertext: string;
  tag: string;
}

export function generateProofLogEncryptionKey(): string {
  return base64UrlEncode(randomBytes(32));
}

export function encryptProofLogRecord(key: string, value: unknown): ProofLogEncryptedRecord {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", decodeProofLogKey(key), iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: "A256GCM",
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag)
  };
}

export function decryptProofLogRecord<T = unknown>(key: string, encrypted: ProofLogEncryptedRecord): T {
  if (encrypted.v !== 1 || encrypted.alg !== "A256GCM") {
    throw new Error(`Unsupported encrypted log record format: v=${encrypted.v} alg=${encrypted.alg}`);
  }
  const decipher = createDecipheriv("aes-256-gcm", decodeProofLogKey(key), base64UrlDecode(encrypted.iv));
  decipher.setAuthTag(base64UrlDecode(encrypted.tag));
  const plaintext = Buffer.concat([
    decipher.update(base64UrlDecode(encrypted.ciphertext)),
    decipher.final()
  ]).toString("utf8");
  return JSON.parse(plaintext) as T;
}

function decodeProofLogKey(key: string): Buffer {
  const decoded = base64UrlDecode(key);
  if (decoded.length !== 32) throw new Error("Proof log encryption key must decode to 32 bytes");
  return decoded;
}

function base64UrlEncode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("Expected base64url value");
  return Buffer.from(value, "base64url");
}

