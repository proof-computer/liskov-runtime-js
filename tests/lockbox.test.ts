import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import {
  LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN,
  buildLockboxRuntimeJobSecretRequest,
  installLockboxRuntimeSecrets,
  loadLockboxRuntimeSecrets,
  lockboxEncryptedPayloadDigest,
  lockboxRuntimeConfigFromBootstrap,
  lockboxRuntimeJobSecretRequestMessage,
  parseLockboxPlaintextPayload,
  readLockboxRuntimeConfig,
  type LockboxRuntimeJobSecretPlaintextPayload,
  type LockboxRuntimeJobSecretSignedRequest,
  type RuntimeFileWriter,
  type RuntimeIdentityProvider
} from "../src/index.js";

describe("Lockbox runtime secrets", () => {
  it("parses compact and expanded bootstrap config", () => {
    assert.deepEqual(lockboxRuntimeConfigFromBootstrap(JSON.stringify({
      v: 1,
      u: "https://lockbox.test",
      a: "generic-worker",
      g: "grant-1",
      p: "1".repeat(64),
      d: "42",
      s: ["api-token", "file-config"],
      f: "./secrets"
    })), {
      lockboxUrl: "https://lockbox.test",
      applicationId: "generic-worker",
      grantId: "grant-1",
      policyDigest: "1".repeat(64),
      deploymentId: "42",
      requestedSecretIds: ["api-token", "file-config"],
      allowInsecureHttp: false,
      fileBaseDir: "./secrets",
      requestTtlMs: undefined,
      overwriteEnv: undefined
    });

    assert.deepEqual(readLockboxRuntimeConfig({
      env: {
        PROOF_LOCKBOX_URL: "https://lockbox.test",
        PROOF_LOCKBOX_APPLICATION_ID: "generic-worker",
        PROOF_LOCKBOX_GRANT_ID: "grant-1",
        PROOF_LOCKBOX_POLICY_DIGEST: "1".repeat(64),
        PROOF_LOCKBOX_DEPLOYMENT_ID: "42",
        PROOF_LOCKBOX_REQUESTED_SECRET_IDS: "api-token"
      }
    })?.requestedSecretIds, ["api-token"]);
  });

  it("signs canonical requests with runtime identity", async () => {
    const signedMessages: string[] = [];
    const request = await buildLockboxRuntimeJobSecretRequest({
      identityProvider: fakeIdentityProvider({ signedMessages }),
      config: lockboxConfig({ requestedSecretIds: ["file-config", "api-token"], nonce: "nonce-1" }),
      nowMs: 1_000
    });
    assert.equal(request.domain, LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN);
    assert.deepEqual(request.requestedSecretIds, ["api-token", "file-config"]);
    assert.equal(request.responseEncryptionKey, "ab".repeat(33));
    assert.equal(signedMessages[0], Buffer.from(lockboxRuntimeJobSecretRequestMessage(request)).toString("utf8"));
  });

  it("fetches, decrypts, verifies binding, installs env secrets, and keeps diagnostics redacted", async () => {
    const env: Record<string, string | undefined> = {};
    const diagnostics: unknown[] = [];
    const requests: LockboxRuntimeJobSecretSignedRequest[] = [];
    const plaintext = plaintextPayload([{ secretId: "api-token", name: "API_TOKEN", value: "super-secret-token" }]);

    const result = await loadLockboxRuntimeSecrets({
      identityProvider: fakeIdentityProvider({ plaintext }),
      config: lockboxConfig({ requestedSecretIds: ["api-token"], nonce: "nonce-1" }),
      env,
      nowMs: () => 1_000,
      diagnostics: (event) => {
        diagnostics.push(event);
      },
      fetchImpl: (async (_url, init) => {
        const request = JSON.parse(String(init?.body)) as LockboxRuntimeJobSecretSignedRequest;
        requests.push(request);
        return jsonResponse(lockboxResponse(request, plaintext));
      }) as typeof fetch
    });

    assert.equal(env.API_TOKEN, "super-secret-token");
    assert.equal(result.installed.env[0]?.name, "API_TOKEN");
    assert.equal(JSON.stringify({ result, diagnostics }).includes("super-secret-token"), false);
    assert.equal(requests[0]?.signature, "0x" + "22".repeat(64));
  });

  it("installs file secrets under the base dir and rejects path traversal", async () => {
    const writes: Array<{ path: string; data: string }> = [];
    const files: RuntimeFileWriter = {
      async mkdir() {},
      async writeFile(path, data) {
        writes.push({ path, data });
      },
      async chmod() {}
    };

    await installLockboxRuntimeSecrets({
      payload: parseLockboxPlaintextPayload(plaintextPayload([
        { secretId: "file-config", target: "file", name: "configs/service.json", value: "{\"enabled\":true}" }
      ])),
      fileBaseDir: "/tmp/slipway-js-lockbox",
      files
    });
    assert.equal(writes[0]?.path, "/tmp/slipway-js-lockbox/configs/service.json");
    assert.equal(writes[0]?.data, "{\"enabled\":true}");

    await assert.rejects(() => installLockboxRuntimeSecrets({
      payload: parseLockboxPlaintextPayload(plaintextPayload([
        { secretId: "file-config", target: "file", name: "../escape.txt", value: "secret" }
      ])),
      fileBaseDir: "/tmp/slipway-js-lockbox",
      files
    }), /escapes/u);
  });

  it("fails closed on plaintext digest and binding mismatches", async () => {
    const request = await buildLockboxRuntimeJobSecretRequest({
      identityProvider: fakeIdentityProvider(),
      config: lockboxConfig({ requestedSecretIds: ["api-token"], nonce: "nonce-1" }),
      nowMs: 1_000
    });
    const plaintext = plaintextPayload([{ secretId: "api-token", name: "API_TOKEN", value: "secret" }]);
    await assert.rejects(() => loadLockboxRuntimeSecrets({
      identityProvider: fakeIdentityProvider({ plaintext: { ...plaintext, jobId: "wrong-job" } }),
      config: lockboxConfig({ requestedSecretIds: ["api-token"], nonce: "nonce-1" }),
      fetchImpl: (async () => jsonResponse(lockboxResponse(request, { ...plaintext, jobId: "wrong-job" }))) as typeof fetch
    }), /jobId/u);

    const badResponse = lockboxResponse(request, plaintext);
    badResponse.encryptedPayload.plaintextDigest = "sha256:" + "0".repeat(64);
    badResponse.encryptedPayload.encryptedPayloadDigest = lockboxEncryptedPayloadDigest({
      domain: badResponse.encryptedPayload.domain,
      version: badResponse.encryptedPayload.version,
      curveName: badResponse.encryptedPayload.curveName,
      senderPublicKey: badResponse.encryptedPayload.senderPublicKey,
      saltHex: badResponse.encryptedPayload.saltHex,
      ciphertextHex: badResponse.encryptedPayload.ciphertextHex,
      plaintextDigest: badResponse.encryptedPayload.plaintextDigest
    });
    await assert.rejects(() => loadLockboxRuntimeSecrets({
      identityProvider: fakeIdentityProvider({ plaintext }),
      config: lockboxConfig({ requestedSecretIds: ["api-token"], nonce: "nonce-1" }),
      fetchImpl: (async () => jsonResponse(badResponse)) as typeof fetch
    }), /plaintext digest/u);
  });
});

function lockboxConfig(overrides: Partial<Parameters<typeof buildLockboxRuntimeJobSecretRequest>[0]["config"]> = {}) {
  return {
    lockboxUrl: "https://lockbox.test",
    applicationId: "generic-worker",
    grantId: "grant-1",
    policyDigest: "1".repeat(64),
    deploymentId: "42",
    requestedSecretIds: ["api-token"],
    ...overrides
  };
}

function fakeIdentityProvider(options: { signedMessages?: string[]; plaintext?: LockboxRuntimeJobSecretPlaintextPayload } = {}): RuntimeIdentityProvider {
  return {
    async resolveIdentity() {
      return { jobId: "job-1", processorId: "processor-1", responseEncryptionKey: "ab".repeat(33) };
    },
    async sign(message) {
      options.signedMessages?.push(Buffer.from(message).toString("utf8"));
      return "0x" + "22".repeat(64);
    },
    async decryptGrantPayload() {
      return Buffer.from(JSON.stringify(options.plaintext ?? plaintextPayload([
        { secretId: "api-token", name: "API_TOKEN", value: "secret" }
      ])), "utf8");
    }
  };
}

function plaintextPayload(
  secrets: Array<Partial<LockboxRuntimeJobSecretPlaintextPayload["secrets"][number]>>
): LockboxRuntimeJobSecretPlaintextPayload {
  return {
    domain: "proof.lockbox.job-secret-response.v1",
    requestId: "lockbox-request-1",
    grantId: "grant-1",
    applicationId: "generic-worker",
    repository: "proof-computer/generic-worker",
    policyDigest: "1".repeat(64),
    jobId: "job-1",
    deploymentId: "42",
    processorId: "processor-1",
    issuedAtMs: 1_000,
    secrets: secrets.map((secret) => ({
      secretId: secret.secretId ?? "api-token",
      versionId: secret.versionId ?? "version-1",
      target: secret.target ?? "env",
      name: secret.name ?? "API_TOKEN",
      required: secret.required ?? true,
      bundleId: secret.bundleId ?? "default",
      value: secret.value ?? "secret"
    }))
  };
}

function lockboxResponse(request: LockboxRuntimeJobSecretSignedRequest, plaintext: LockboxRuntimeJobSecretPlaintextPayload) {
  const plaintextText = JSON.stringify(plaintext);
  const encryptedBase = {
    domain: "proof.lockbox.job-secret-response.encrypted-payload.v1" as const,
    version: "acurast-p256-hkdf-aes-256-gcm-v1" as const,
    curveName: "secp256r1" as const,
    senderPublicKey: "0x" + "cd".repeat(33),
    saltHex: "0x" + "00".repeat(16),
    ciphertextHex: "0x" + "ef".repeat(16),
    plaintextDigest: `sha256:${createHash("sha256").update(plaintextText).digest("hex")}`
  };
  const encryptedPayload = {
    ...encryptedBase,
    encryptedPayloadDigest: lockboxEncryptedPayloadDigest(encryptedBase)
  };
  return {
    ok: true,
    requestId: plaintext.requestId,
    grantId: request.grantId,
    applicationId: request.applicationId,
    repository: plaintext.repository,
    policyDigest: request.policyDigest,
    jobId: request.jobId,
    deploymentId: request.deploymentId,
    processorId: request.processorId,
    requestedSecretIds: request.requestedSecretIds,
    responseKeyDigest: `sha256:${"1".repeat(64)}`,
    secretVersions: plaintext.secrets.map((secret) => ({
      secretId: secret.secretId,
      versionId: secret.versionId,
      target: secret.target,
      name: secret.name,
      required: secret.required,
      bundleId: secret.bundleId,
      encryptedPayloadDigest: `sha256:${"2".repeat(64)}`
    })),
    encryptedPayload
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
