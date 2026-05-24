import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import {
  bootstrapSlipwayRuntime,
  lockboxEncryptedPayloadDigest,
  type LockboxRuntimeJobSecretPlaintextPayload,
  type RuntimeIdentityProvider
} from "../src/index.js";

describe("top-level Slipway runtime bootstrap", () => {
  it("loads Slipway runtime env before Lockbox secrets and returns a refresh handle", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42"
      }),
      PROOF_LOCKBOX_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://lockbox.test",
        a: "generic-worker",
        g: "grant-1",
        p: "1".repeat(64),
        d: "42",
        s: ["api-token"]
      })
    };
    const order: string[] = [];
    const identityProvider = fakeIdentityProvider();
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider,
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        order.push(parsed.pathname);
        if (parsed.pathname === "/api/jobs/runtime-env") {
          return jsonResponse(runtimeEnvResponse());
        }
        const request = JSON.parse(String(init?.body)) as { requestedSecretIds: string[] };
        return jsonResponse(lockboxResponse(request));
      }) as typeof fetch
    });
    try {
      assert.deepEqual(order, ["/api/jobs/runtime-env", "/api/jobs/secret-requests"]);
      assert.equal(env.RUNTIME_VALUE, "ok");
      assert.equal(env.API_TOKEN, "secret");
      assert.equal(handle.runtimeEnv?.response.revision, "runtime-revision-1");
      assert.equal(handle.lockbox?.installed.env[0]?.name, "API_TOKEN");
    } finally {
      handle.stop();
    }
  });

  it("skips Lockbox when no Lockbox bootstrap is present", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42"
      })
    };
    const paths: string[] = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url) => {
        paths.push(new URL(String(url)).pathname);
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      assert.deepEqual(paths, ["/api/jobs/runtime-env"]);
      assert.equal(handle.lockbox, undefined);
    } finally {
      handle.stop();
    }
  });

  it("stops scheduled refresh timers", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42"
      })
    };
    let scheduled = 0;
    let cleared = 0;
    const timer = { unref() {} } as unknown as ReturnType<typeof setTimeout>;
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      setTimeoutImpl: ((() => {
        scheduled += 1;
        return timer;
      }) as unknown) as typeof setTimeout,
      clearTimeoutImpl: ((seen) => {
        assert.equal(seen, timer);
        cleared += 1;
      }) as typeof clearTimeout,
      fetchImpl: (async () => jsonResponse(runtimeEnvResponse())) as typeof fetch
    });
    handle.stop();
    assert.equal(scheduled, 1);
    assert.equal(cleared, 1);
  });

  it("posts best-effort runtime diagnostics when the Slipway bootstrap carries a token", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42",
        x: { t: "diagnostic-token" }
      })
    };
    const diagnosticBodies: Array<Record<string, unknown>> = [];
    await assert.rejects(() => bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        if (parsed.pathname === "/api/jobs/runtime-diagnostics") {
          diagnosticBodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
          return jsonResponse({ ok: true });
        }
        return new Response(JSON.stringify({ ok: false, error: "missing_job" }), {
          status: 404,
          headers: { "content-type": "application/json" }
        });
      }) as typeof fetch
    }), /rejected request/u);
    assert.equal(diagnosticBodies.some((body) => body.domain === "proof.slipway.runtime-diagnostic.v1"), true);
    assert.equal(diagnosticBodies.some((body) => body.status === "failed"), true);
  });
});

function fakeIdentityProvider(): RuntimeIdentityProvider {
  return {
    async resolveIdentity() {
      return { jobId: "job-1", processorId: "processor-1", responseEncryptionKey: "ab".repeat(33) };
    },
    async sign() {
      return "0x" + "11".repeat(64);
    },
    async decryptGrantPayload() {
      return Buffer.from(JSON.stringify(plaintextPayload()), "utf8");
    }
  };
}

function runtimeEnvResponse(): Record<string, unknown> {
  return {
    ok: true,
    domain: "proof.slipway.runtime-env-response.v1",
    requestId: "runtime-env-request-1",
    applicationId: "generic-worker",
    policyDigest: "1".repeat(64),
    jobId: "job-1",
    deploymentId: "42",
    processorId: "processor-1",
    revision: "runtime-revision-1",
    issuedAtMs: 1_000,
    expiresAtMs: 61_000,
    refreshAfterMs: 30_000,
    values: {
      RUNTIME_VALUE: "ok"
    }
  };
}

function plaintextPayload(): LockboxRuntimeJobSecretPlaintextPayload {
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
    secrets: [{
      secretId: "api-token",
      versionId: "version-1",
      target: "env",
      name: "API_TOKEN",
      required: true,
      bundleId: "default",
      value: "secret"
    }]
  };
}

function lockboxResponse(request: { requestedSecretIds: string[] }) {
  const plaintext = plaintextPayload();
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
  return {
    ok: true,
    requestId: plaintext.requestId,
    grantId: plaintext.grantId,
    applicationId: plaintext.applicationId,
    repository: plaintext.repository,
    policyDigest: plaintext.policyDigest,
    jobId: plaintext.jobId,
    deploymentId: plaintext.deploymentId,
    processorId: plaintext.processorId,
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
    encryptedPayload: {
      ...encryptedBase,
      encryptedPayloadDigest: lockboxEncryptedPayloadDigest(encryptedBase)
    }
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
