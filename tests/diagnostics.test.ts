import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import type { RuntimeIdentityProvider } from "../src/acurast.js";
import {
  createSlipwayRuntimeDiagnosticEmitter,
  canonicalLiskovRuntimeDiagnosticV2Payload,
  canonicalLiskovRuntimeDiagnosticV3Payload,
  liskovRuntimeDiagnosticV2Message,
  liskovRuntimeDiagnosticV3Message,
  startSlipwayRuntimeHealth,
  slipwayRuntimeDiagnosticRequestMessage
} from "../src/diagnostics.js";
import type { SlipwayRuntimeEnvConfig } from "../src/runtime-env.js";

// ADR-0003 Phase 5b — the cross-repo signature parity anchor. This exact byte string is
// asserted identically in the Rust test (slipway-executor `runtime_diagnostics.rs`); the
// server verifies the processor's ed25519 signature over it. If you change the canonical
// shape, change it in BOTH repos or signed check-ins silently fail to verify.
const SIGNED_MESSAGE_GOLDEN =
  '{"applicationId":"app-1","deploymentId":"dep-1","domain":"proof.slipway.runtime-diagnostic.v1","policyDigest":"abcdef","sequence":0,"stage":"runtime.health","status":"info","timestampMs":1719230000000}';

const FIXED_NOW = 1719230000000;
const FIXED_SIGNATURE = "0x" + "ab".repeat(64);
const V2_VECTORS = JSON.parse(
  readFileSync(new URL("./vectors/diagnostics-v2.json", import.meta.url), "utf8")
) as {
  golden: { input: Parameters<typeof liskovRuntimeDiagnosticV2Message>[0]; message: string };
  redaction: {
    input: Parameters<typeof canonicalLiskovRuntimeDiagnosticV2Payload>[0];
    normalized: ReturnType<typeof canonicalLiskovRuntimeDiagnosticV2Payload>;
  };
};

function baseBootstrap(overrides: Partial<SlipwayRuntimeEnvConfig> = {}): SlipwayRuntimeEnvConfig {
  return {
    slipwayUrl: "https://slipway.test",
    applicationId: "app-1",
    policyDigest: "ABCDEF",
    deploymentId: "dep-1",
    ...overrides
  };
}

function recordingIdentityProvider(signedMessages: string[]): RuntimeIdentityProvider {
  return {
    async resolveIdentity() {
      return { jobId: "job-1", processorId: "0xproc" };
    },
    async sign(message) {
      signedMessages.push(Buffer.from(message).toString("utf8"));
      return FIXED_SIGNATURE;
    },
    async decryptGrantPayload() {
      return Buffer.from("{}", "utf8");
    }
  };
}

interface RecordedCall {
  url: string;
  body: Record<string, unknown>;
}

function recordingFetch(calls: RecordedCall[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
    return { ok: true, status: 200, async text() { return ""; } } as Response;
  }) as unknown as typeof fetch;
}

describe("ADR-0003 5b signed runtime diagnostics", () => {
  it("builds the canonical signed message byte-identically to the Rust golden", () => {
    // `policyDigest` is supplied upper-cased to exercise the lower-casing the server expects.
    const message = slipwayRuntimeDiagnosticRequestMessage({
      applicationId: "app-1",
      policyDigest: "ABCDEF",
      deploymentId: "dep-1",
      stage: "runtime.health",
      status: "info",
      sequence: 0,
      timestampMs: FIXED_NOW
    });
    assert.equal(Buffer.from(message).toString("utf8"), SIGNED_MESSAGE_GOLDEN);
  });

  it("signs and sends a check-in with no diagnostics token (identity provider only)", async () => {
    const calls: RecordedCall[] = [];
    const signed: string[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      bootstrap: baseBootstrap(),
      identityProvider: recordingIdentityProvider(signed),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });

    await emitter.emit({ stage: "runtime.health", status: "info", ok: true });

    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /\/api\/jobs\/runtime-diagnostics$/u);
    assert.equal(calls[0].body.signature, FIXED_SIGNATURE);
    assert.equal(calls[0].body.token, undefined);
    // The bytes the runtime actually signed are exactly the canonical golden.
    assert.equal(signed[0], SIGNED_MESSAGE_GOLDEN);
  });

  it("keeps sending the token and also signs during the accept-both window", async () => {
    const calls: RecordedCall[] = [];
    const signed: string[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      bootstrap: baseBootstrap({ diagnosticsToken: "srd1_legacy" }),
      identityProvider: recordingIdentityProvider(signed),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });

    await emitter.emit({ stage: "runtime.health", status: "info", ok: true });

    assert.equal(calls[0].body.token, "srd1_legacy");
    assert.equal(calls[0].body.signature, FIXED_SIGNATURE);
  });

  it("does not send remotely when there is neither a token nor an identity provider", async () => {
    const calls: RecordedCall[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      bootstrap: baseBootstrap(),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });

    await emitter.emit({ stage: "runtime.health", status: "info", ok: true });

    assert.equal(calls.length, 0);
  });
});

describe("identity-bound v2 terminal diagnostics", () => {
  it("matches the Rust canonical-byte golden and redaction vector", () => {
    assert.equal(
      Buffer.from(liskovRuntimeDiagnosticV2Message(V2_VECTORS.golden.input)).toString("utf8"),
      V2_VECTORS.golden.message
    );
    assert.deepEqual(
      canonicalLiskovRuntimeDiagnosticV2Payload(V2_VECTORS.redaction.input),
      V2_VECTORS.redaction.normalized
    );
  });

  it("sends the signature-only complete v2 payload", async () => {
    const calls: RecordedCall[] = [];
    const signed: string[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      identityProvider: recordingIdentityProvider(signed),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });

    await emitter.report({
      stage: "runtime.application_start",
      status: "succeeded",
      component: "test",
      code: "ok",
      message: "ready",
      attrs: { attempt: 1 }
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.domain, "proof.liskov.runtime-diagnostic.v2");
    assert.equal(calls[0].body.jobId, "job-1");
    assert.equal(calls[0].body.processorId, "0xproc");
    assert.equal(calls[0].body.token, undefined);
    assert.equal(calls[0].body.signature, FIXED_SIGNATURE);
    assert.equal(signed[0], Buffer.from(liskovRuntimeDiagnosticV2Message({
      jobId: "job-1",
      processorId: "0xproc",
      stage: "runtime.application_start",
      status: "succeeded",
      sequence: 0,
      timestampMs: FIXED_NOW,
      component: "test",
      code: "ok",
      message: "ready",
      attrs: { attempt: 1 }
    })).toString("utf8"));
  });

  it("makes the first fatal call win, closes synchronously, and suppresses later work", async () => {
    const calls: RecordedCall[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      identityProvider: recordingIdentityProvider([]),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });
    const first = emitter.fatal({
      kind: "application_start",
      code: "configuration_invalid",
      message: "bad target"
    });
    const racing = emitter.fatal({ kind: "explicit", code: "must_not_win" });
    assert.equal(first, racing);
    assert.equal(emitter.isClosed(), true);
    await emitter.report({ stage: "runtime.after_fatal", status: "info" });
    await first;

    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.stage, "runtime.fatal.application_start");
    assert.equal(calls[0].body.code, "configuration_invalid");
    await assert.rejects(
      emitter.report({ stage: "runtime.fatal", status: "failed" }),
      /must use fatal/u
    );
  });

  it("keeps terminal reporting first-call-wins when synchronous cleanup fails", async () => {
    const calls: RecordedCall[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      identityProvider: recordingIdentityProvider([]),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW,
      onFatal() { throw new Error("cleanup failed"); }
    });
    const first = emitter.fatal({ kind: "explicit", code: "stop" });
    const racing = emitter.fatal({ kind: "uncaught_exception", code: "must_not_win" });
    assert.equal(first, racing);
    await first;
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.code, "stop");
  });

  it("bypasses diagnostic backoff once for fatal and remains bounded on hanging transport", async () => {
    let callCount = 0;
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      identityProvider: recordingIdentityProvider([]),
      fetchImpl: (async () => {
        callCount += 1;
        if (callCount === 1) throw new Error("offline");
        return await new Promise<Response>(() => undefined);
      }) as typeof fetch,
      nowMs: () => FIXED_NOW,
      diagnosticRemoteBackoffMs: 60_000,
      diagnosticSendTimeoutMs: 20
    });
    await emitter.report({ stage: "runtime.health", status: "info" });
    const started = Date.now();
    await emitter.fatal({ kind: "explicit", code: "stop" });
    assert.equal(callCount, 2);
    assert.ok(Date.now() - started < 500);
  });

  it("bounds terminal identity and signing hangs before transport begins", async () => {
    let fetched = false;
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      identityProvider: {
        async resolveIdentity() { return await new Promise(() => undefined); },
        async sign() { return "unused"; },
        async decryptGrantPayload() { return Buffer.from("{}"); }
      },
      fetchImpl: (async () => {
        fetched = true;
        return new Response("{}");
      }) as typeof fetch,
      diagnosticSendTimeoutMs: 20
    });
    const started = Date.now();
    await emitter.fatal({ kind: "bootstrap", code: "identity_unavailable" });
    assert.equal(fetched, false);
    assert.ok(Date.now() - started < 500);
  });

  it("allocates lower sequences to in-flight health before fatal and stops health afterward", async () => {
    const observed: number[] = [];
    let releaseFirst: (() => void) | undefined;
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      nowMs: () => FIXED_NOW,
      diagnosticSendTimeoutMs: 25,
      diagnostics: async (event) => {
        observed.push(event.sequence);
        if (event.sequence === 0) await new Promise<void>((resolve) => { releaseFirst = resolve; });
      }
    });
    const health = startSlipwayRuntimeHealth({ emitter, intervalMs: 0 });
    const inFlight = health.sendNow();
    const fatal = emitter.fatal({ kind: "explicit", code: "stop" });
    health.stop();
    await health.sendNow();
    releaseFirst?.();
    await Promise.all([inFlight, fatal]);
    assert.deepEqual(observed, [0, 1]);
  });
});

describe("runtime-instance v3 diagnostics", () => {
  it("matches the canonical v3 byte vector", () => {
    const payload = canonicalLiskovRuntimeDiagnosticV3Payload({
      jobId: "job-1",
      processorId: "processor-1",
      runtimeInstanceId: "instance-2",
      stage: "runtime.health",
      status: "info",
      sequence: 0,
      timestampMs: FIXED_NOW,
      component: "runtime-health",
      code: null,
      message: null,
      attrs: { ready: true }
    });
    assert.equal(
      Buffer.from(liskovRuntimeDiagnosticV3Message(payload)).toString("utf8"),
      '{"attrs":{"ready":true},"code":null,"component":"runtime-health","domain":"proof.liskov.runtime-diagnostic.v3","jobId":"job-1","message":null,"processorId":"processor-1","runtimeInstanceId":"instance-2","sequence":0,"stage":"runtime.health","status":"info","timestampMs":1719230000000}'
    );
  });

  it("uses v3 when bootstrap returns an instance and v2 for an older backend", async () => {
    const calls: RecordedCall[] = [];
    const signed: string[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      bootstrap: baseBootstrap({ runtimeInstanceId: "instance-new" }),
      identityProvider: recordingIdentityProvider(signed),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });
    await emitter.report({ stage: "runtime.health", status: "info" });
    assert.equal(calls[0].body.domain, "proof.liskov.runtime-diagnostic.v3");
    assert.equal(calls[0].body.runtimeInstanceId, "instance-new");
    assert.match(signed[0], /"runtimeInstanceId":"instance-new"/u);

    const oldCalls: RecordedCall[] = [];
    const oldEmitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      bootstrap: baseBootstrap(),
      identityProvider: recordingIdentityProvider([]),
      fetchImpl: recordingFetch(oldCalls),
      nowMs: () => FIXED_NOW
    });
    await oldEmitter.report({ stage: "runtime.health", status: "info" });
    assert.equal(oldCalls[0].body.domain, "proof.liskov.runtime-diagnostic.v2");
    assert.equal(oldCalls[0].body.runtimeInstanceId, undefined);
  });

  it("lets separate process emitters both begin at sequence zero", async () => {
    const first: RecordedCall[] = [];
    const second: RecordedCall[] = [];
    for (const calls of [first, second]) {
      const emitter = createSlipwayRuntimeDiagnosticEmitter({
        coreUrl: "https://liskov.test",
        bootstrap: baseBootstrap({ runtimeInstanceId: calls === first ? "instance-a" : "instance-b" }),
        identityProvider: recordingIdentityProvider([]),
        fetchImpl: recordingFetch(calls),
        nowMs: () => FIXED_NOW
      });
      await emitter.report({ stage: "runtime.start", status: "started" });
    }
    assert.equal(first[0].body.sequence, 0);
    assert.equal(second[0].body.sequence, 0);
  });
});
