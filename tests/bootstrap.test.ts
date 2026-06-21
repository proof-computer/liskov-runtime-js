import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import {
  bootstrapSlipwayRuntime,
  createAcurastHttpPostFetch,
  DEFAULT_LISKOV_SECRETS_URL,
  decryptProofLogRecord,
  generateProofLogEncryptionKey,
  liskovSignedBootstrapUrls,
  lockboxEncryptedPayloadDigest,
  type BlackboxLogBatch,
  type LockboxRuntimeJobSecretPlaintextPayload,
  type RuntimeIdentityProvider
} from "../src/index.js";

type LockboxPlaintextSecret = LockboxRuntimeJobSecretPlaintextPayload["secrets"][number];

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

  it("does not implicitly allowlist bootstrap hosts before network requests", async () => {
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
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: {
        net: {
          addAllowedHostnames: async (hostnames) => {
            order.push(`allow:${hostnames.join(",")}`);
          }
        }
      },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        order.push(`fetch:${parsed.pathname}`);
        if (parsed.pathname === "/api/jobs/runtime-env") {
          return jsonResponse(runtimeEnvResponse());
        }
        const request = JSON.parse(String(init?.body)) as { requestedSecretIds: string[] };
        return jsonResponse(lockboxResponse(request));
      }) as typeof fetch
    });
    try {
      assert.deepEqual(order, [
        "fetch:/api/jobs/runtime-env",
        "fetch:/api/jobs/secret-requests"
      ]);
    } finally {
      handle.stop();
    }
  });

  it("does not call Acurast hostname allowlisting when it is present", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42"
      })
    };
    let fetchedRuntimeEnv = false;
    let allowlistCalled = false;
    const startedAt = Date.now();
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: {
        net: {
          addAllowedHostnames: () => {
            allowlistCalled = true;
            return new Promise<never>(() => undefined);
          }
        }
      },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url) => {
        const parsed = new URL(String(url));
        fetchedRuntimeEnv = parsed.pathname === "/api/jobs/runtime-env";
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      assert.equal(fetchedRuntimeEnv, true);
      assert.equal(allowlistCalled, false);
      assert.ok(Date.now() - startedAt < 2_500);
    } finally {
      handle.stop();
    }
  });

  it("defaults signed secret bootstrap to the Liskov secrets host", () => {
    assert.equal(DEFAULT_LISKOV_SECRETS_URL, "https://secrets.liskov.proof.computer");
    assert.equal(liskovSignedBootstrapUrls({ env: {} }).secretsUrl, "https://secrets.liskov.proof.computer");
  });

  it("discovers runtime env and secrets with signed Liskov bootstrap when env bootstrap is absent", async () => {
    const env: Record<string, string | undefined> = {};
    const order: string[] = [];
    const signedMessages: string[] = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      bootstrap: {
        coreUrl: "https://liskov.test",
        secretsUrl: "https://secrets.liskov.test"
      },
      identityProvider: fakeIdentityProvider(plaintextPayload(), { signedMessages }),
      nowMs: () => 1_000,
      randomBytes: (size) => new Uint8Array(size).fill(7),
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        order.push(parsed.pathname);
        const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
        if (parsed.pathname === "/api/jobs/runtime-bootstrap") {
          assert.equal(request.domain, "proof.liskov.runtime-bootstrap-request.v1");
          assert.equal(request.applicationId, undefined);
          assert.equal(request.policyDigest, undefined);
          return jsonResponse(liskovRuntimeBootstrapResponse());
        }
        if (parsed.pathname === "/api/jobs/runtime-env") {
          assert.equal(request.applicationId, "generic-worker");
          assert.equal(request.policyDigest, "1".repeat(64));
          return jsonResponse(runtimeEnvResponse());
        }
        if (parsed.pathname === "/api/jobs/secret-bootstrap") {
          assert.equal(request.domain, "proof.liskov.secret-bootstrap-request.v1");
          assert.equal(request.grantId, undefined);
          assert.equal(request.responseEncryptionKey, "ab".repeat(33));
          return jsonResponse(liskovSecretBootstrapResponse());
        }
        if (parsed.pathname === "/api/jobs/secret-requests") {
          assert.equal(request.grantId, "grant-1");
          return jsonResponse(lockboxResponse(request as { requestedSecretIds: string[] }));
        }
        throw new Error(`unexpected path ${parsed.pathname}`);
      }) as typeof fetch
    });
    try {
      assert.deepEqual(order, [
        "/api/jobs/runtime-bootstrap",
        "/api/jobs/secret-bootstrap",
        "/api/jobs/runtime-env",
        "/api/jobs/secret-requests"
      ]);
      assert.equal(env.RUNTIME_VALUE, "ok");
      assert.equal(env.API_TOKEN, "secret");
      assert.equal(handle.runtimeEnv?.response.revision, "runtime-revision-1");
      assert.equal(handle.lockbox?.installed.env[0]?.name, "API_TOKEN");
      assert.equal(handle.status().capabilities.runtimeEnv.state, "ready");
      assert.equal(handle.status().capabilities.secrets.state, "ready");
      const runtimeBootstrapMessage = JSON.parse(signedMessages[0]!) as Record<string, unknown>;
      const secretBootstrapMessage = JSON.parse(signedMessages[1]!) as Record<string, unknown>;
      assert.equal(runtimeBootstrapMessage.domain, "proof.liskov.runtime-bootstrap-request.v1");
      assert.equal(runtimeBootstrapMessage.applicationId, undefined);
      assert.equal(secretBootstrapMessage.domain, "proof.liskov.secret-bootstrap-request.v1");
      assert.equal(secretBootstrapMessage.responseEncryptionKey, "ab".repeat(33));
    } finally {
      handle.stop();
    }
  });

  it("does not touch legacy environment lookup before signed bootstrap", async () => {
    const env: Record<string, string | undefined> = {};
    const order: string[] = [];
    const std = {
      job: {
        getId: () => "job-1",
        getEncryptionKeys: () => ({ p256: "0x" + "ab".repeat(33) })
      },
      device: {
        getAddress: () => "processor-1"
      },
      signers: {
        ed25519: {
          sign: () => "0x" + "11".repeat(64)
        },
        secp256r1: {
          encrypt: () => "0x00",
          decrypt: () => "0x" + Buffer.from(JSON.stringify(plaintextPayload()), "utf8").toString("hex")
        }
      }
    };
    const handle = await bootstrapSlipwayRuntime({
      env,
      std,
      environment() {
        throw new Error("legacy environment lookup should not run for signed bootstrap");
      },
      bootstrap: {
        coreUrl: "https://liskov.test",
        secretsUrl: "https://secrets.liskov.test"
      },
      nowMs: () => 1_000,
      randomBytes: (size) => new Uint8Array(size).fill(7),
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        order.push(parsed.pathname);
        const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
        if (parsed.pathname === "/api/jobs/runtime-bootstrap") {
          assert.equal(request.jobId, "job-1");
          assert.equal(request.processorId, "processor-1");
          return jsonResponse(liskovRuntimeBootstrapResponse());
        }
        if (parsed.pathname === "/api/jobs/secret-bootstrap") {
          assert.equal(request.responseEncryptionKey, "ab".repeat(33));
          return jsonResponse(liskovSecretBootstrapResponse());
        }
        if (parsed.pathname === "/api/jobs/runtime-env") return jsonResponse(runtimeEnvResponse());
        if (parsed.pathname === "/api/jobs/secret-requests") {
          return jsonResponse(lockboxResponse(request as { requestedSecretIds: string[] }));
        }
        throw new Error(`unexpected path ${parsed.pathname}`);
      }) as typeof fetch
    });
    try {
      assert.deepEqual(order, [
        "/api/jobs/runtime-bootstrap",
        "/api/jobs/secret-bootstrap",
        "/api/jobs/runtime-env",
        "/api/jobs/secret-requests"
      ]);
      assert.equal(env.RUNTIME_VALUE, "ok");
      assert.equal(env.API_TOKEN, "secret");
      assert.equal(handle.status().ready, true);
    } finally {
      handle.stop();
    }
  });

  it("retries transient signed bootstrap misses while Liskov catches up", async () => {
    const env: Record<string, string | undefined> = {};
    const sleeps: number[] = [];
    let runtimeBootstrapAttempts = 0;
    const handle = await bootstrapSlipwayRuntime({
      env,
      bootstrap: {
        coreUrl: "https://liskov.test",
        secretsUrl: "https://secrets.liskov.test",
        retry: { initialDelayMs: 5, intervalMs: 5, maxElapsedMs: 100, maxAttempts: 3 }
      },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      setTimeoutImpl: (((callback: () => void, delayMs?: number) => {
        sleeps.push(delayMs ?? 0);
        callback();
        return { unref() {} };
      }) as unknown) as typeof setTimeout,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        if (parsed.pathname === "/api/jobs/runtime-bootstrap") {
          runtimeBootstrapAttempts += 1;
          if (runtimeBootstrapAttempts === 1) {
            return new Response(JSON.stringify({
              ok: false,
              error: "runtime_bootstrap_job_not_found",
              reason: "not observed yet"
            }), {
              status: 404,
              headers: { "content-type": "application/json" }
            });
          }
          return jsonResponse(liskovRuntimeBootstrapResponse());
        }
        if (parsed.pathname === "/api/jobs/runtime-env") return jsonResponse(runtimeEnvResponse());
        if (parsed.pathname === "/api/jobs/secret-bootstrap") return jsonResponse(liskovSecretBootstrapResponse());
        const request = JSON.parse(String(init?.body)) as { requestedSecretIds: string[] };
        return jsonResponse(lockboxResponse(request));
      }) as typeof fetch
    });
    try {
      assert.equal(runtimeBootstrapAttempts, 2);
      assert.equal(sleeps[0], 5);
      assert.equal(handle.status().ready, true);
      assert.equal(env.API_TOKEN, "secret");
    } finally {
      handle.stop();
    }
  });

  it("retries through the Acurast httpPOST adapter when core reports a transient miss", async () => {
    // Regression: Acurast `httpPOST` surfaces a 404 through `onError` as a
    // formatted string. The adapter must recover the 404 so the bootstrap retry
    // fires instead of crashing on the first attempt.
    const env: Record<string, string | undefined> = {};
    const sleeps: number[] = [];
    let runtimeBootstrapAttempts = 0;
    const adapterFetch = createAcurastHttpPostFetch({
      httpPOST(url, _body, _headers, onSuccess, onError) {
        const parsed = new URL(url);
        if (parsed.pathname === "/api/jobs/runtime-bootstrap") {
          runtimeBootstrapAttempts += 1;
          if (runtimeBootstrapAttempts === 1) {
            onError(
              'HTTP Post failed with {"ok":false,"error":"runtime_bootstrap_job_not_found","reason":"not observed yet"} (404)'
            );
            return;
          }
          onSuccess(JSON.stringify(liskovRuntimeBootstrapResponse()), "cert");
          return;
        }
        if (parsed.pathname === "/api/jobs/runtime-env") {
          onSuccess(JSON.stringify(runtimeEnvResponse()), "cert");
          return;
        }
        if (parsed.pathname === "/api/jobs/secret-bootstrap") {
          onSuccess(JSON.stringify(liskovSecretBootstrapResponse()), "cert");
          return;
        }
        onSuccess(JSON.stringify(lockboxResponse({ requestedSecretIds: ["api-token"] })), "cert");
      }
    });
    const handle = await bootstrapSlipwayRuntime({
      env,
      bootstrap: {
        coreUrl: "https://liskov.test",
        secretsUrl: "https://secrets.liskov.test",
        retry: { initialDelayMs: 5, intervalMs: 5, maxElapsedMs: 100, maxAttempts: 3 }
      },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      setTimeoutImpl: (((callback: () => void, delayMs?: number) => {
        sleeps.push(delayMs ?? 0);
        callback();
        return { unref() {} };
      }) as unknown) as typeof setTimeout,
      fetchImpl: adapterFetch
    });
    try {
      assert.equal(runtimeBootstrapAttempts, 2);
      assert.equal(sleeps[0], 5);
      assert.equal(handle.status().ready, true);
      assert.equal(env.API_TOKEN, "secret");
    } finally {
      handle.stop();
    }
  });

  it("skips Lockbox when no Lockbox bootstrap is present", async () => {
    const env: Record<string, string | undefined> = {
      HOME: "/home/runtime",
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
      assert.equal(handle.home, "/home/runtime/.slipway");
      assert.deepEqual(paths, ["/api/jobs/runtime-env"]);
      assert.equal(handle.lockbox, undefined);
      assert.equal(handle.env.get("RUNTIME_VALUE"), "ok");
      assert.equal(handle.env.require("RUNTIME_VALUE"), "ok");
      const status = handle.status();
      assert.equal(status.ready, true);
      assert.equal(status.capabilities.runtimeEnv.state, "ready");
      assert.equal(status.capabilities.secrets.state, "off");
      assert.equal(status.capabilities.logging.state, "off");
      assert.equal((await handle.whenReady()).ready, true);
    } finally {
      handle.stop();
    }
  });

  it("fails closed when required Lockbox secrets are rejected", async () => {
    const env: Record<string, string | undefined> = {
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
    const diagnostics: Array<{ code?: string; message?: string; error?: string; attrs?: Record<string, unknown> }> = [];
    await assert.rejects(() => bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      diagnostics: (event) => {
        diagnostics.push({
          code: event.code,
          message: event.message,
          error: event.error,
          attrs: event.attrs
        });
      },
      fetchImpl: (async () => new Response(JSON.stringify({
        ok: false,
        error: "grant_pending",
        retryable: true
      }), {
        status: 409,
        headers: { "content-type": "application/json" }
      })) as typeof fetch
    }), /Lockbox rejected secret request/u);
    assert.equal(env.API_TOKEN, undefined);
    assert.equal(diagnostics.some((event) => event.code === "lockbox_secret_request_failed"), true);
    assert.equal(JSON.stringify(diagnostics).includes("api-token"), false);
    assert.equal(JSON.stringify(diagnostics).includes("API_TOKEN"), false);
  });

  it("returns before background secrets load, then retries and installs env secrets", async () => {
    const dek = generateProofLogEncryptionKey();
    const payload = plaintextPayload([
      {
        secretId: "api-token",
        versionId: "version-1",
        target: "env",
        name: "API_TOKEN",
        required: true,
        bundleId: "default",
        value: "secret"
      },
      {
        secretId: "blackbox-log-config",
        versionId: "version-blackbox-1",
        target: "env",
        name: "BLACKBOX_LOG_CONFIG",
        required: true,
        bundleId: "blackbox-log-config",
        value: JSON.stringify({
          factoryToken: "bbx_sf_background_secret",
          baseUrl: "https://logging.slipway.proof.computer",
          dek
        })
      }
    ]);
    const env: Record<string, string | undefined> = {
      PROOF_LOCKBOX_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://lockbox.test",
        a: "generic-worker",
        g: "grant-1",
        p: "1".repeat(64),
        d: "42",
        s: ["api-token", "blackbox-log-config"]
      })
    };
    const timers: Array<{ delayMs?: number; callback: () => void; timer: { unref(): void } }> = [];
    const paths: string[] = [];
    let secretRequests = 0;
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: blackboxRuntimeStd(),
      secrets: {
        mode: "background",
        retry: { intervalMs: 25, maxAttempts: 2, maxElapsedMs: 1_000 }
      },
      logging: { mode: "background", spoolMode: "memory" },
      identityProvider: fakeIdentityProvider(payload),
      nowMs: () => 1_000,
      setTimeoutImpl: (((callback: () => void, delayMs?: number) => {
        const timer = { unref() {} };
        timers.push({ delayMs, callback, timer });
        return timer;
      }) as unknown) as typeof setTimeout,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        paths.push(parsed.pathname);
        if (parsed.pathname === "/api/jobs/secret-requests") {
          secretRequests += 1;
          if (secretRequests === 1) {
            return new Response(JSON.stringify({ ok: false, error: "grant_pending", retryable: true }), {
              status: 409,
              headers: { "content-type": "application/json" }
            });
          }
          const request = JSON.parse(String(init?.body)) as { requestedSecretIds: string[] };
          return jsonResponse(lockboxResponse(request, payload));
        }
        if (parsed.pathname.endsWith("/job-sinks")) return jsonResponse({ sinkId: "sink-background-777" });
        return jsonResponse({ ok: true });
      }) as typeof fetch
    });
    try {
      assert.equal(secretRequests, 0);
      assert.equal(handle.status().ready, true);
      assert.equal(handle.status().capabilities.secrets.state, "pending");
      assert.equal(timers[0]?.delayMs, 0);

      timers[0]!.callback();
      await flushAsyncWork();
      assert.equal(secretRequests, 1);
      assert.equal(env.API_TOKEN, undefined);
      assert.equal(handle.status().capabilities.secrets.state, "degraded");
      assert.equal(handle.status().capabilities.secrets.code, "lockbox_secret_request_retrying");
      assert.equal(timers[1]?.delayMs, 25);

      timers[1]!.callback();
      await flushAsyncWork();
      assert.equal(secretRequests, 2);
      assert.equal(env.API_TOKEN, "secret");
      assert.equal(handle.lockbox?.installed.env.length, 2);
      assert.equal(handle.status().capabilities.secrets.state, "ready");
      assert.equal(handle.status().capabilities.logging.state, "ready");

      await handle.log("diagnostic.background");
      assert.deepEqual(paths.slice(-2), [
        "/v1/sink-factories/background/job-sinks",
        "/v1/sinks/sink-background-777/events"
      ]);
    } finally {
      handle.stop();
    }
  });

  it("keeps background secret failure non-blocking after retry exhaustion", async () => {
    const env: Record<string, string | undefined> = {
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
    const diagnostics: Array<{ code?: string; message?: string; error?: string; attrs?: Record<string, unknown> }> = [];
    const timers: Array<{ delayMs?: number; callback: () => void; timer: { unref(): void } }> = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      secrets: {
        mode: "background",
        retry: { maxAttempts: 1, maxElapsedMs: 1_000 }
      },
      identityProvider: fakeIdentityProvider(plaintextPayload([{
        secretId: "api-token",
        versionId: "version-1",
        target: "env",
        name: "API_TOKEN",
        required: true,
        bundleId: "default",
        value: "super-secret-background-value"
      }])),
      nowMs: () => 1_000,
      diagnostics: (event) => {
        diagnostics.push({
          code: event.code,
          message: event.message,
          error: event.error,
          attrs: event.attrs
        });
      },
      setTimeoutImpl: (((callback: () => void, delayMs?: number) => {
        const timer = { unref() {} };
        timers.push({ delayMs, callback, timer });
        return timer;
      }) as unknown) as typeof setTimeout,
      fetchImpl: (async () => new Response(JSON.stringify({
        ok: false,
        error: "grant_pending",
        retryable: true
      }), {
        status: 409,
        headers: { "content-type": "application/json" }
      })) as typeof fetch
    });
    try {
      assert.equal(handle.status().ready, true);
      timers[0]!.callback();
      await handle.refreshNow();
      const status = handle.status();
      assert.equal(status.ready, true);
      assert.equal(status.capabilities.secrets.state, "failed");
      assert.equal(status.capabilities.secrets.required, false);
      assert.equal(status.capabilities.secrets.code, "lockbox_secret_request_failed");
      assert.equal(env.API_TOKEN, undefined);
      assert.equal(timers.filter((timer) => timer.delayMs === 0).length, 1);
      assert.equal(timers.some((timer) => timer.delayMs === 5_000), false);
      assert.equal(JSON.stringify(diagnostics).includes("super-secret-background-value"), false);
    } finally {
      handle.stop();
    }
  });

  it("stops scheduled background secret retries", async () => {
    const env: Record<string, string | undefined> = {
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
    let scheduled = 0;
    let cleared = 0;
    let secretRequests = 0;
    const timer = { unref() {} } as unknown as ReturnType<typeof setTimeout>;
    const handle = await bootstrapSlipwayRuntime({
      env,
      secrets: { mode: "background" },
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
      fetchImpl: (async () => {
        secretRequests += 1;
        return jsonResponse({});
      }) as typeof fetch
    });
    handle.stop();
    assert.equal(scheduled, 1);
    assert.equal(cleared, 1);
    assert.equal(secretRequests, 0);
  });

  it("uses SLIPWAY_HOME and attaches env-delivered factory-token logging", async () => {
    const dek = generateProofLogEncryptionKey();
    const env: Record<string, string | undefined> = {
      SLIPWAY_HOME: "/runtime/slipway",
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken: "bbx_sf_test_secret",
        baseUrl: "https://logging.slipway.proof.computer",
        applicationId: "diagnostic",
        dek
      })
    };
    const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: blackboxRuntimeStd(),
      bootstrap: { mode: "off" },
      logging: { mode: "background", spoolMode: "memory" },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        calls.push({
          url: String(url),
          headers: init?.headers as Record<string, string>,
          body: String(init?.body)
        });
        return String(url).endsWith("/job-sinks")
          ? jsonResponse({ sink: { sinkId: "sink-job-777" } })
          : jsonResponse({ ok: true });
      }) as typeof fetch
    });
    try {
      assert.equal(handle.home, "/runtime/slipway");
      const status = handle.status();
      assert.equal(status.ready, true);
      assert.equal(status.capabilities.logging.state, "ready");
      assert.equal(status.capabilities.logging.required, false);
      assert.match(status.capabilities.logging.fingerprint ?? "", /^0x[0-9a-f]{64}$/u);
      await handle.log("diagnostic.boot", { ok: true }, { severity: "debug", labels: { app: "diagnostic" } });
      assert.equal(calls[0]?.url, "https://logging.slipway.proof.computer/v1/sink-factories/test/job-sinks");
      assert.equal(calls[0]?.headers["x-blackbox-sink-factory-token"], "bbx_sf_test_secret");
      assert.deepEqual(JSON.parse(calls[0]!.body), { applicationId: "diagnostic", jobId: "777" });

      assert.equal(calls[1]?.url, "https://logging.slipway.proof.computer/v1/sinks/sink-job-777/events");
      const batch = JSON.parse(calls[1]!.body) as BlackboxLogBatch;
      const record = decryptProofLogRecord<Record<string, unknown>>(dek, batch.encrypted[0]!);
      const details = record.details as { ok?: boolean; _slipwayRuntime?: { severity?: string; labels?: Record<string, string> } };
      assert.equal(record.event, "diagnostic.boot");
      assert.deepEqual(details.ok, true);
      assert.deepEqual(details._slipwayRuntime?.severity, "debug");
      assert.deepEqual(details._slipwayRuntime?.labels, { app: "diagnostic" });
      assert.deepEqual(await handle.flush(), { ok: true, state: "ready", flushed: 0, pending: 0, dropped: 0, message: undefined });
    } finally {
      handle.stop();
    }
  });

  it("attaches Lockbox-delivered logging config before runtime.log writes", async () => {
    const dek = generateProofLogEncryptionKey();
    const payload = plaintextPayload([{
      secretId: "blackbox-log-config",
      versionId: "version-blackbox-1",
      target: "env",
      name: "BLACKBOX_LOG_CONFIG",
      required: true,
      bundleId: "blackbox-log-config",
      value: JSON.stringify({
        factoryToken: "bbx_sf_lockbox_secret",
        baseUrl: "https://logging.slipway.proof.computer",
        dek
      })
    }]);
    const env: Record<string, string | undefined> = {
      PROOF_LOCKBOX_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://lockbox.test",
        a: "generic-worker",
        g: "grant-1",
        p: "1".repeat(64),
        d: "42",
        s: ["blackbox-log-config"]
      })
    };
    const calls: string[] = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: blackboxRuntimeStd(),
      logging: { mode: "required", spoolMode: "memory" },
      identityProvider: fakeIdentityProvider(payload),
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        calls.push(parsed.pathname);
        if (parsed.pathname === "/api/jobs/secret-requests") {
          const request = JSON.parse(String(init?.body)) as { requestedSecretIds: string[] };
          return jsonResponse(lockboxResponse(request, payload));
        }
        if (parsed.pathname.endsWith("/job-sinks")) return jsonResponse({ sinkId: "sink-lockbox-777" });
        return jsonResponse({ ok: true });
      }) as typeof fetch
    });
    try {
      const status = handle.status();
      assert.equal(status.ready, true);
      assert.equal(status.capabilities.logging.state, "ready");
      assert.equal(env.BLACKBOX_LOG_CONFIG, payload.secrets[0]?.value);
      await handle.log("diagnostic.lockbox");
      assert.deepEqual(calls, [
        "/api/jobs/secret-requests",
        "/v1/sink-factories/lockbox/job-sinks",
        "/v1/sinks/sink-lockbox-777/events"
      ]);
    } finally {
      handle.stop();
    }
  });

  it("drains logs buffered before config appears on refresh", async () => {
    const dek = generateProofLogEncryptionKey();
    const env: Record<string, string | undefined> = {};
    const batches: BlackboxLogBatch[] = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: blackboxRuntimeStd(),
      bootstrap: { mode: "off" },
      logging: { mode: "background", spoolMode: "memory", earlyBufferMaxRecords: 2 },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/job-sinks")) return jsonResponse({ sinkId: "sink-refresh-777" });
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return jsonResponse({ ok: true });
      }) as typeof fetch
    });
    try {
      await handle.log("before-config", { boot: true });
      assert.equal(handle.status().capabilities.logging.state, "pending");
      env.BLACKBOX_LOG_CONFIG = JSON.stringify({
        factoryToken: "bbx_sf_refresh_secret",
        baseUrl: "https://logging.slipway.proof.computer",
        dek
      });
      await handle.refreshNow();
      assert.equal(handle.status().capabilities.logging.state, "ready");
      assert.equal(batches.length, 1);
      const events = batches[0]!.encrypted.map((record) =>
        decryptProofLogRecord<Record<string, unknown>>(dek, record).event
      );
      assert.deepEqual(events, ["before-config"]);
      assert.deepEqual(await handle.flush(), { ok: true, state: "ready", flushed: 0, pending: 0, dropped: 0, message: undefined });
    } finally {
      handle.stop();
    }
  });

  it("reports invalid required logging config as a readiness blocker", async () => {
    const diagnostics: Array<{ code?: string; stage: string; status: string }> = [];
    const env: Record<string, string | undefined> = {
      BLACKBOX_LOG_CONFIG: JSON.stringify({ mystery: true })
    };
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: blackboxRuntimeStd(),
      bootstrap: { mode: "off" },
      logging: { mode: "required", spoolMode: "memory" },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      diagnostics: (event) => {
        diagnostics.push({ code: event.code, stage: event.stage, status: event.status });
      }
    });
    try {
      const status = handle.status();
      assert.equal(status.ready, false);
      assert.equal(status.capabilities.logging.state, "failed");
      assert.equal(status.blockers[0]?.capability, "logging");
      assert.equal(status.blockers[0]?.code, "slipway_logging_config_invalid");
      assert.equal(diagnostics.some((event) => event.code === "slipway_logging_config_invalid"), true);
      await assert.rejects(() => handle.whenReady(), /slipway_logging_config_invalid/u);
    } finally {
      handle.stop();
    }
  });

  it("recreates the logger after refreshed logging config changes", async () => {
    const firstDek = generateProofLogEncryptionKey();
    const secondDek = generateProofLogEncryptionKey();
    const env: Record<string, string | undefined> = {
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken: "bbx_sf_first_secret",
        baseUrl: "https://logging.slipway.proof.computer",
        dek: firstDek
      })
    };
    const registerPaths: string[] = [];
    const batches: BlackboxLogBatch[] = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      std: blackboxRuntimeStd(),
      bootstrap: { mode: "off" },
      logging: { mode: "background", spoolMode: "memory" },
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        if (parsed.pathname.endsWith("/job-sinks")) {
          registerPaths.push(parsed.pathname);
          return jsonResponse({ sinkId: `sink-${registerPaths.length}` });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return jsonResponse({ ok: true });
      }) as typeof fetch
    });
    try {
      await handle.log("first");
      const firstFingerprint = handle.status().capabilities.logging.fingerprint;
      env.BLACKBOX_LOG_CONFIG = JSON.stringify({
        factoryToken: "bbx_sf_second_secret",
        baseUrl: "https://logging.slipway.proof.computer",
        dek: secondDek
      });
      await handle.refreshNow();
      await handle.log("second");
      assert.deepEqual(registerPaths, [
        "/v1/sink-factories/first/job-sinks",
        "/v1/sink-factories/second/job-sinks"
      ]);
      assert.notEqual(handle.status().capabilities.logging.fingerprint, firstFingerprint);
      assert.equal(decryptProofLogRecord<Record<string, unknown>>(firstDek, batches[0]!.encrypted[0]!).event, "first");
      assert.equal(decryptProofLogRecord<Record<string, unknown>>(secondDek, batches[1]!.encrypted[0]!).event, "second");
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

  it("starts and stops configurable runtime health diagnostics", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42",
        x: { t: "diagnostic-token", h: { i: 7, d: 5, to: 11 } }
      })
    };
    const scheduled: Array<{ delayMs?: number; callback: () => void; timer: { unref(): void } }> = [];
    let cleared = 0;
    let sawHealth: () => void;
    const healthSeen = new Promise<void>((resolve) => {
      sawHealth = resolve;
    });
    const diagnosticBodies: Array<Record<string, unknown>> = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      setTimeoutImpl: (((callback: () => void, delayMs?: number) => {
        const timer = { unref() {} };
        scheduled.push({ delayMs, callback, timer });
        return timer;
      }) as unknown) as typeof setTimeout,
      clearTimeoutImpl: ((timer) => {
        assert.equal(typeof timer, "object");
        cleared += 1;
      }) as typeof clearTimeout,
      fetchImpl: (async (url, init) => {
        const parsed = new URL(String(url));
        if (parsed.pathname === "/api/jobs/runtime-diagnostics") {
          const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
          diagnosticBodies.push(body);
          if (body.stage === "runtime.health") sawHealth();
          return jsonResponse({ ok: true });
        }
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      const healthTimer = scheduled.find((item) => item.delayMs === 5);
      assert.ok(healthTimer);
      healthTimer.callback();
      await healthSeen;
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.equal(diagnosticBodies.some((body) => body.stage === "runtime.health"), true);
      assert.equal(scheduled.some((item) => item.delayMs === 7), true);
    } finally {
      handle.stop();
    }
    assert.equal(cleared >= 2, true);
  });

  it("disables runtime health when interval is zero", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42",
        x: { t: "diagnostic-token", h: { i: 0 } }
      })
    };
    const scheduled: Array<number | undefined> = [];
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      setTimeoutImpl: (((_callback: () => void, delayMs?: number) => {
        scheduled.push(delayMs);
        return { unref() {} };
      }) as unknown) as typeof setTimeout,
      fetchImpl: (async (url) => {
        const parsed = new URL(String(url));
        if (parsed.pathname === "/api/jobs/runtime-diagnostics") return jsonResponse({ ok: true });
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      assert.equal(scheduled.filter((delayMs) => delayMs === 30_000).length, 1);
    } finally {
      handle.stop();
    }
  });

  it("bounds remote diagnostic sends with a timeout", async () => {
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
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => 1_000,
      runtimeHealth: { intervalMs: 0 },
      diagnosticSendTimeoutMs: 1,
      fetchImpl: (async (url) => {
        const parsed = new URL(String(url));
        if (parsed.pathname === "/api/jobs/runtime-diagnostics") {
          return new Promise<Response>((resolve) => {
            setTimeout(() => resolve(jsonResponse({ ok: true })), 25);
          });
        }
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      assert.equal(handle.runtimeEnv?.response.revision, "runtime-revision-1");
    } finally {
      handle.stop();
    }
  });

  it("bounds local diagnostic callbacks so they cannot block runtime env handoff", async () => {
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
      diagnosticSendTimeoutMs: 1,
      diagnostics: () => new Promise<void>((resolve) => {
        setTimeout(resolve, 25);
      }),
      fetchImpl: (async (url) => {
        paths.push(new URL(String(url)).pathname);
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      assert.deepEqual(paths, ["/api/jobs/runtime-env"]);
      assert.equal(handle.runtimeEnv?.response.revision, "runtime-revision-1");
    } finally {
      handle.stop();
    }
  });

  it("backs off remote diagnostics after a failed send and resumes after the backoff window", async () => {
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
        v: 1,
        u: "https://slipway.test",
        a: "generic-worker",
        p: "1".repeat(64),
        d: "42",
        x: { t: "diagnostic-token", h: { i: 0 } }
      })
    };
    let now = 1_000;
    let diagnosticAttempts = 0;
    const handle = await bootstrapSlipwayRuntime({
      env,
      identityProvider: fakeIdentityProvider(),
      nowMs: () => now,
      diagnosticRemoteBackoffMs: 30_000,
      fetchImpl: (async (url) => {
        const parsed = new URL(String(url));
        if (parsed.pathname === "/api/jobs/runtime-diagnostics") {
          diagnosticAttempts += 1;
          return new Response("temporary failure", { status: 503 });
        }
        return jsonResponse(runtimeEnvResponse());
      }) as typeof fetch
    });
    try {
      assert.equal(diagnosticAttempts, 1);
      await handle.runtimeHealth?.sendNow();
      assert.equal(diagnosticAttempts, 1);
      now = 31_001;
      await handle.runtimeHealth?.sendNow();
      assert.equal(diagnosticAttempts, 2);
    } finally {
      handle.stop();
    }
  });
});

async function flushAsyncWork(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
  await Promise.resolve();
}

function fakeIdentityProvider(
  payload: LockboxRuntimeJobSecretPlaintextPayload = plaintextPayload(),
  options: { signedMessages?: string[] } = {}
): RuntimeIdentityProvider {
  return {
    async resolveIdentity() {
      return { jobId: "job-1", processorId: "processor-1", responseEncryptionKey: "ab".repeat(33) };
    },
    async sign(message) {
      options.signedMessages?.push(Buffer.from(message).toString("utf8"));
      return "0x" + "11".repeat(64);
    },
    async decryptGrantPayload() {
      return Buffer.from(JSON.stringify(payload), "utf8");
    }
  };
}

function blackboxRuntimeStd() {
  return {
    job: {
      getId: () => "777",
      getPublicKeys: () => ({ ed25519: "a".repeat(64) })
    },
    signers: {
      ed25519: {
        sign: () => "b".repeat(128)
      }
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

function liskovRuntimeBootstrapResponse(): Record<string, unknown> {
  return {
    ok: true,
    domain: "proof.liskov.runtime-bootstrap-response.v1",
    applicationId: "generic-worker",
    policyDigest: "1".repeat(64),
    deploymentId: "42",
    jobId: "job-1",
    processorId: "processor-1",
    slipwayUrl: "https://slipway.test",
    runtimeEnv: {
      enabled: true,
      url: "https://slipway.test"
    },
    secrets: {
      required: true,
      url: "https://secrets.liskov.test"
    }
  };
}

function liskovSecretBootstrapResponse(): Record<string, unknown> {
  return {
    ok: true,
    domain: "proof.liskov.secret-bootstrap-response.v1",
    lockboxUrl: "https://lockbox.test",
    applicationId: "generic-worker",
    grantId: "grant-1",
    policyDigest: "1".repeat(64),
    deploymentId: "42",
    jobId: "job-1",
    processorId: "processor-1",
    requestedSecretIds: ["api-token"],
    fileBaseDir: "./.slipway-lockbox"
  };
}

function plaintextPayload(secrets: LockboxPlaintextSecret[] = [{
  secretId: "api-token",
  versionId: "version-1",
  target: "env",
  name: "API_TOKEN",
  required: true,
  bundleId: "default",
  value: "secret"
}]): LockboxRuntimeJobSecretPlaintextPayload {
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
    secrets
  };
}

function lockboxResponse(
  request: { requestedSecretIds: string[] },
  plaintext: LockboxRuntimeJobSecretPlaintextPayload = plaintextPayload()
) {
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
