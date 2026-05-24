import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN,
  loadSlipwayRuntimeEnv,
  slipwayRuntimeEnvRequestMessage,
  startSlipwayRuntimeEnvRefresh,
  type RuntimeIdentityProvider,
  type SlipwayRuntimeEnvSignedRequest
} from "../src/index.js";

describe("Slipway runtime env", () => {
  it("signs the request, enforces HTTPS, and installs returned env values", async () => {
    const env: Record<string, string | undefined> = {};
    const signedMessages: string[] = [];
    const requests: Array<{ url: string; body: SlipwayRuntimeEnvSignedRequest }> = [];
    const identityProvider = fakeIdentityProvider({ signedMessages });

    const result = await loadSlipwayRuntimeEnv({
      identityProvider,
      config: {
        slipwayUrl: "https://slipway.test",
        applicationId: "generic-worker",
        policyDigest: "A".repeat(64),
        deploymentId: "42",
        nonce: "runtime-nonce"
      },
      env,
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        const body = JSON.parse(String(init?.body)) as SlipwayRuntimeEnvSignedRequest;
        requests.push({ url: String(url), body });
        assert.equal(body.domain, SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN);
        return jsonResponse({
          ok: true,
          domain: "proof.slipway.runtime-env-response.v1",
          requestId: "runtime-env-request-1",
          applicationId: "generic-worker",
          policyDigest: "a".repeat(64),
          jobId: "job-1",
          deploymentId: "42",
          processorId: "processor-1",
          revision: "runtime-revision-1",
          issuedAtMs: 1_000,
          expiresAtMs: 61_000,
          refreshAfterMs: 30_000,
          values: {
            PROOF_CONTROL_PLANE_URL: "https://control.example",
            WORK_MODE: "poll"
          }
        });
      }) as typeof fetch
    });

    assert.equal(requests[0]?.url, "https://slipway.test/api/jobs/runtime-env");
    assert.equal(requests[0]?.body.signature, "0x" + "11".repeat(64));
    assert.equal(signedMessages[0], Buffer.from(slipwayRuntimeEnvRequestMessage(requests[0]!.body)).toString("utf8"));
    assert.equal(env.PROOF_CONTROL_PLANE_URL, "https://control.example");
    assert.deepEqual(result.installed, ["PROOF_CONTROL_PLANE_URL", "WORK_MODE"]);
  });

  it("rejects insecure remote HTTP before fetch", async () => {
    let fetched = false;
    await assert.rejects(() => loadSlipwayRuntimeEnv({
      identityProvider: fakeIdentityProvider(),
      config: {
        slipwayUrl: "http://slipway.example",
        applicationId: "generic-worker",
        policyDigest: "1".repeat(64),
        deploymentId: "42"
      },
      fetchImpl: (async () => {
        fetched = true;
        return jsonResponse({});
      }) as typeof fetch
    }), /HTTPS/u);
    assert.equal(fetched, false);
  });

  it("dedupes concurrent manual refreshes", async () => {
    let fetchCount = 0;
    let release: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const handle = startSlipwayRuntimeEnvRefresh({
      identityProvider: fakeIdentityProvider(),
      config: {
        slipwayUrl: "https://slipway.test",
        applicationId: "generic-worker",
        policyDigest: "1".repeat(64),
        deploymentId: "42"
      },
      nowMs: () => 1_000,
      fetchImpl: (async () => {
        fetchCount += 1;
        await blocked;
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      const left = handle.refreshNow();
      const right = handle.refreshNow();
      release?.();
      await Promise.all([left, right]);
      assert.equal(fetchCount, 1);
    } finally {
      handle.stop();
    }
  });

  it("emits diagnostics for failed requests", async () => {
    const diagnostics: unknown[] = [];
    await assert.rejects(() => loadSlipwayRuntimeEnv({
      identityProvider: fakeIdentityProvider(),
      config: {
        slipwayUrl: "https://slipway.test",
        applicationId: "generic-worker",
        policyDigest: "1".repeat(64),
        deploymentId: "42"
      },
      diagnostics: (event) => {
        diagnostics.push(event);
      },
      fetchImpl: (async () => new Response(JSON.stringify({ ok: false, error: "missing_job" }), {
        status: 404,
        headers: { "content-type": "application/json" }
      })) as typeof fetch
    }), /rejected request/u);

    assert.equal((diagnostics.at(-1) as { ok?: boolean }).ok, false);
    assert.match((diagnostics.at(-1) as { errorCode?: string }).errorCode ?? "", /rejected request/u);
  });
});

function fakeIdentityProvider(options: { signedMessages?: string[] } = {}): RuntimeIdentityProvider {
  return {
    async resolveIdentity() {
      return { jobId: "job-1", processorId: "processor-1", responseEncryptionKey: "ab".repeat(33) };
    },
    async sign(message) {
      options.signedMessages?.push(Buffer.from(message).toString("utf8"));
      return "0x" + "11".repeat(64);
    },
    async decryptGrantPayload() {
      return new Uint8Array();
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

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
