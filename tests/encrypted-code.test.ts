import assert from "node:assert/strict";
import { createCipheriv, createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import type { BootstrapSlipwayRuntimeHandle } from "../src/index.js";
import { decryptEncryptedCode, encryptedCodeAad, parseEncryptedCodeDescriptor,
  startEncryptedApplication } from "../src/encrypted-code.js";

const vector = JSON.parse(await readFile(new URL("./fixtures/encrypted-code-v1.json", import.meta.url), "utf8"));
const ciphertext = Buffer.from(vector.ciphertext, "base64");

describe("encrypted code v1", () => {
  it("decrypts the independent Python AESGCM vector and pins the AAD bytes", () => {
    assert.equal(decryptEncryptedCode(ciphertext, vector.key, vector.descriptor).toString(), vector.plaintext);
    assert.equal(encryptedCodeAad(vector.descriptor).toString(),
      `proof.liskov.encrypted-code.v1\napplication-code-key\n${vector.descriptor.plaintextDigest}`);
  });

  it("refuses corrupt ciphertext, wrong keys, tags and authenticated selectors", () => {
    const corrupt = Buffer.from(ciphertext); corrupt[0] ^= 1;
    assert.throws(() => decryptEncryptedCode(corrupt, vector.key, vector.descriptor), /ciphertext_mismatch/);
    assert.throws(() => decryptEncryptedCode(ciphertext, Buffer.alloc(32).toString("base64"), vector.descriptor), /decryption_failed/);
    for (const altered of [
      { authTag: Buffer.alloc(16).toString("base64") }, { keySecretId: "another-application" },
      { plaintextDigest: `sha256:${"f".repeat(64)}` }
    ]) {
      assert.throws(() => decryptEncryptedCode(ciphertext, vector.key, { ...vector.descriptor, ...altered }), /decryption_failed/);
    }
  });

  it("checks plaintext identity even when an encryptor supplies a valid tag for false metadata", () => {
    const descriptor = { ...vector.descriptor, plaintextDigest: `sha256:${"f".repeat(64)}` };
    const cipher = createCipheriv("aes-256-gcm", Buffer.from(vector.key, "base64"), Buffer.from(descriptor.iv, "base64"));
    cipher.setAAD(encryptedCodeAad(descriptor));
    const bytes = Buffer.concat([cipher.update(vector.plaintext), cipher.final()]);
    descriptor.authTag = cipher.getAuthTag().toString("base64");
    descriptor.ciphertextDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    assert.throws(() => decryptEncryptedCode(bytes, vector.key, descriptor), /decryption_failed/);
  });

  it("refuses unknown fields, secret material, noncanonical base64 and malformed identities", () => {
    for (const changes of [{ key: vector.key }, { domain: "future" }, { algorithm: "none" },
      { keySecretId: "../key" }, { iv: "AA==" }, { authTag: vector.descriptor.authTag + "\n" },
      { plaintextDigest: "sha256:" + "A".repeat(64) }, { iv: null }]) {
      assert.throws(() => parseEncryptedCodeDescriptor({ ...vector.descriptor, ...changes }));
    }
    assert.throws(() => decryptEncryptedCode(ciphertext, vector.key.trimEnd() + "\n", vector.descriptor));
    assert.throws(() => parseEncryptedCodeDescriptor(null));
  });

  it("loads verified CommonJS once, passes the bootstrapped handle, and removes plaintext", async () => {
    const fixture = await runtimeFixture();
    try {
      await startEncryptedApplication({ runtime: fixture.runtime, descriptor: vector.descriptor, ciphertextPath: fixture.payload });
      assert.deepEqual(fixture.events, ["application.encrypted_code.loaded", "encrypted-canary"]);
      assert.deepEqual(await readdir(fixture.home), ["payload.enc"]);
    } finally { await fixture.cleanup(); }
  });

  it("cannot use an environment key without the matching installed Lockbox grant", async () => {
    for (const mutate of [
      (runtime: BootstrapSlipwayRuntimeHandle) => { runtime.lockbox = undefined; },
      (runtime: BootstrapSlipwayRuntimeHandle) => { runtime.lockbox!.installed.env = []; },
      (runtime: BootstrapSlipwayRuntimeHandle) => { runtime.lockbox!.response.applicationUid = "another-app"; },
      (runtime: BootstrapSlipwayRuntimeHandle) => { runtime.lockbox!.response.deploymentId = "another-job"; },
      (runtime: BootstrapSlipwayRuntimeHandle) => { runtime.lockbox!.response.secretVersions[0].versionId = "other-version"; }
    ]) {
      const fixture = await runtimeFixture();
      try {
        mutate(fixture.runtime);
        await assert.rejects(startEncryptedApplication({ runtime: fixture.runtime, descriptor: vector.descriptor,
          ciphertextPath: fixture.payload }), /encrypted_code_start_failed/);
        assert.deepEqual(fixture.events, ["encrypted_code_start_failed"]);
        assert.deepEqual(await readdir(fixture.home), ["payload.enc"]);
      } finally { await fixture.cleanup(); }
    }
  });

  it("never imports corrupt bytes or discloses crypto exceptions through diagnostics", async () => {
    const fixture = await runtimeFixture();
    try {
      await writeFile(fixture.payload, "untrusted-source");
      await assert.rejects(startEncryptedApplication({ runtime: fixture.runtime, descriptor: vector.descriptor,
        ciphertextPath: fixture.payload }), /encrypted_code_start_failed/);
      assert.deepEqual(fixture.events, ["encrypted_code_start_failed"]);
      assert.deepEqual(await readdir(fixture.home), ["payload.enc"]);
    } finally { await fixture.cleanup(); }
  });
});

async function runtimeFixture() {
  const home = await mkdtemp(path.join(tmpdir(), "encrypted-code-test-"));
  const payload = path.join(home, "payload.enc");
  await writeFile(payload, ciphertext);
  const events: string[] = [];
  const secret = { secretId: "application-code-key", versionId: "version-1", target: "env",
    name: "LISKOV_CODE_KEY", bundleId: "application-code-key" };
  // The loader consumes the already-authenticated SDK handle, not a wire reply.
  // Lockbox's wire/crypto/binding and bootstrap tests cover construction of it.
  const runtime = {
    home, whenReady: async () => {}, status: () => ({ applicationUid: "app-test", deploymentId: "job-test" }),
    env: { require: () => vector.key },
    lockbox: { installed: { env: [{ ...secret }] }, response: { applicationUid: "app-test", deploymentId: "job-test",
      secretVersions: [{ ...secret }] } },
    diagnostics: { report: async (event: { stage: string }) => { events.push(event.stage); },
      fatal: async (event: { code: string }) => { events.push(event.code); } },
    log: async (event: string, details: unknown) => { assert.deepEqual(details, { marker: "8ho7" }); events.push(event); }
  } as unknown as BootstrapSlipwayRuntimeHandle;
  return { home, payload, runtime, events, cleanup: () => rm(home, { recursive: true, force: true }) };
}
