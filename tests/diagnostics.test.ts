import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import type { RuntimeIdentityProvider } from "../src/acurast.js";
import {
  createSlipwayRuntimeDiagnosticEmitter,
  canonicalLiskovRuntimeDiagnosticV2Payload,
  canonicalLiskovRuntimeDiagnosticV3Payload,
  canonicalLiskovRuntimeDiagnosticV4Payload,
  liskovRuntimeDiagnosticV2Message,
  liskovRuntimeDiagnosticV3Message,
  liskovRuntimeDiagnosticV4Message,
  parseRuntimeCeaseControl,
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

function ceaseControl(commandId = "cease-1") {
  return {
    schema: "proof.liskov.runtime-control.v1",
    command: {
      kind: "cease",
      commandId,
      reason: "successor_runtime_ready",
      issuedAtMs: FIXED_NOW - 1,
      expiresAtMs: FIXED_NOW + 60_000,
      binding: {
        applicationUid: "app-0123456789abcdef0123456789abcdef",
        policyDigest: "ABCDEF",
        deploymentId: "dep-1",
        jobId: "job-1",
        runtimeInstanceId: "instance-new"
      }
    }
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

  it("does not advertise cooperative cease on v2 or v3 paths that cannot receive bound control", async () => {
    for (const [bootstrap, expectedDomain] of [
      [baseBootstrap(), "proof.liskov.runtime-diagnostic.v2"],
      [baseBootstrap({ runtimeInstanceId: "instance-new" }), "proof.liskov.runtime-diagnostic.v3"]
    ] as const) {
      const calls: RecordedCall[] = [];
      const emitter = createSlipwayRuntimeDiagnosticEmitter({
        coreUrl: "https://liskov.test",
        bootstrap,
        identityProvider: recordingIdentityProvider([]),
        fetchImpl: recordingFetch(calls),
        nowMs: () => FIXED_NOW,
        async onCease() {}
      });
      await emitter.report({ stage: "runtime.health", status: "info" });
      assert.equal(calls[0].body.domain, expectedDomain);
      assert.equal((calls[0].body.attrs as Record<string, unknown> | null)?.capabilities, undefined);
    }
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

describe("UID-bound v4 diagnostics", () => {
  it("matches the cross-language canonical byte vector", () => {
    const payload = canonicalLiskovRuntimeDiagnosticV4Payload({
      jobId: "job-1",
      processorId: "processor-1",
      runtimeInstanceId: "instance-2",
      applicationUid: "app-0123456789abcdef0123456789abcdef",
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
      Buffer.from(liskovRuntimeDiagnosticV4Message(payload)).toString("utf8"),
      '{"applicationUid":"app-0123456789abcdef0123456789abcdef","attrs":{"ready":true},"code":null,"component":"runtime-health","domain":"proof.liskov.runtime-diagnostic.v4","jobId":"job-1","message":null,"processorId":"processor-1","runtimeInstanceId":"instance-2","sequence":0,"stage":"runtime.health","status":"info","timestampMs":1719230000000}'
    );
  });

  it("uses v4 only when both the runtime instance and UID are authenticated", async () => {
    const calls: RecordedCall[] = [];
    const signed: string[] = [];
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      bootstrap: baseBootstrap({
        runtimeInstanceId: "instance-new",
        applicationUid: "app-0123456789abcdef0123456789abcdef"
      }),
      identityProvider: recordingIdentityProvider(signed),
      fetchImpl: recordingFetch(calls),
      nowMs: () => FIXED_NOW
    });
    await emitter.report({ stage: "runtime.health", status: "info" });
    assert.equal(calls[0].body.domain, "proof.liskov.runtime-diagnostic.v4");
    assert.equal(calls[0].body.applicationUid, "app-0123456789abcdef0123456789abcdef");
    assert.match(signed[0], /"applicationUid":"app-0123456789abcdef0123456789abcdef"/u);
  });

  it("retries a rejected acknowledgement after backoff and redelivery without reinvoking", async () => {
    const calls: RecordedCall[] = [];
    let nowMs = FIXED_NOW;
    let ceaseCalls = 0;
    let acknowledgementCount = 0;
    let firstAcknowledgementSettled!: () => void;
    const firstAcknowledgement = new Promise<void>((resolve) => { firstAcknowledgementSettled = resolve; });
    let acknowledgedTwice!: () => void;
    const twoAcknowledgements = new Promise<void>((resolve) => { acknowledgedTwice = resolve; });
    const control = ceaseControl();
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ url: String(input), body });
      if (body.stage === "runtime.ceased") {
        acknowledgementCount += 1;
        if (acknowledgementCount === 1) firstAcknowledgementSettled();
        if (acknowledgementCount === 2) acknowledgedTwice();
      }
      return {
        ok: body.stage !== "runtime.ceased" || acknowledgementCount > 1,
        status: body.stage === "runtime.ceased" && acknowledgementCount === 1 ? 503 : 200,
        async text() {
          return JSON.stringify(body.stage === "runtime.ceased"
            ? { ok: acknowledgementCount > 1 }
            : { ok: true, control });
        }
      } as Response;
    }) as typeof fetch;
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      bootstrap: baseBootstrap({
        runtimeInstanceId: "instance-new",
        applicationUid: "app-0123456789abcdef0123456789abcdef"
      }),
      identityProvider: recordingIdentityProvider([]),
      fetchImpl,
      nowMs: () => nowMs,
      async onCease(command) {
        ceaseCalls += 1;
        assert.equal(command.commandId, "cease-1");
      }
    });

    await emitter.report({ stage: "runtime.health", status: "info" });
    await firstAcknowledgement;
    await new Promise((resolve) => setImmediate(resolve));
    const callsBeforeBackoffProbe = calls.length;
    nowMs += 29_999;
    await emitter.report({ stage: "runtime.health", status: "info" });
    assert.equal(calls.length, callsBeforeBackoffProbe);

    nowMs += 1;
    await emitter.report({ stage: "runtime.health", status: "info" });
    await twoAcknowledgements;

    assert.equal((calls[0].body.attrs as Record<string, unknown>).capabilities, "cooperative_cease.v1");
    assert.equal(ceaseCalls, 1);
    assert.equal(calls.filter((call) => call.body.stage === "runtime.ceased").length, 2);
  });

  it("retries a lost failure acknowledgement without reinvoking the failed handler", async () => {
    const calls: RecordedCall[] = [];
    let ceaseCalls = 0;
    let failureCount = 0;
    let failedTwice!: () => void;
    const twoFailures = new Promise<void>((resolve) => { failedTwice = resolve; });
    const control = ceaseControl("cease-failure");
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ url: String(input), body });
      if (body.stage === "runtime.cease_failed") {
        failureCount += 1;
        if (failureCount === 2) failedTwice();
      }
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify(body.stage === "runtime.cease_failed" ? { ok: true } : { ok: true, control });
        }
      } as Response;
    }) as typeof fetch;
    const emitter = createSlipwayRuntimeDiagnosticEmitter({
      coreUrl: "https://liskov.test",
      bootstrap: baseBootstrap({
        runtimeInstanceId: "instance-new",
        applicationUid: "app-0123456789abcdef0123456789abcdef"
      }),
      identityProvider: recordingIdentityProvider([]),
      fetchImpl,
      nowMs: () => FIXED_NOW,
      async onCease() {
        ceaseCalls += 1;
        throw new Error("diagnostic cease failed");
      }
    });

    await emitter.report({ stage: "runtime.health", status: "info" });
    await new Promise((resolve) => setImmediate(resolve));
    await emitter.report({ stage: "runtime.health", status: "info" });
    await twoFailures;

    assert.equal(ceaseCalls, 1);
    assert.equal(calls.filter((call) => call.body.stage === "runtime.cease_failed").length, 2);
    assert.equal(
      calls.find((call) => call.body.stage === "runtime.cease_failed")?.body.message,
      "diagnostic cease failed"
    );
  });

  it("allows a still-pending command to run once again after process restart", async () => {
    let ceaseCalls = 0;
    const runProcess = async () => {
      let delivered = false;
      let acknowledged!: () => void;
      const acknowledgement = new Promise<void>((resolve) => { acknowledged = resolve; });
      const emitter = createSlipwayRuntimeDiagnosticEmitter({
        coreUrl: "https://liskov.test",
        bootstrap: baseBootstrap({
          runtimeInstanceId: "instance-new",
          applicationUid: "app-0123456789abcdef0123456789abcdef"
        }),
        identityProvider: recordingIdentityProvider([]),
        nowMs: () => FIXED_NOW,
        fetchImpl: (async (_input, init) => {
          const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
          if (body.stage === "runtime.ceased") acknowledged();
          const response = !delivered && body.stage === "runtime.health"
            ? { ok: true, control: ceaseControl("cease-restart") }
            : { ok: true };
          delivered = true;
          return {
            ok: true,
            status: 200,
            async text() { return JSON.stringify(response); }
          } as Response;
        }) as typeof fetch,
        async onCease() {
          ceaseCalls += 1;
        }
      });
      await emitter.report({ stage: "runtime.health", status: "info" });
      await acknowledgement;
    };

    await runProcess();
    await runProcess();
    assert.equal(ceaseCalls, 2);
  });

  it("rejects stale and foreign controls without invoking application work", () => {
    const expected = {
      applicationUid: "app-uid",
      policyDigest: "digest",
      deploymentId: "dep",
      jobId: "job",
      runtimeInstanceId: "runtime"
    };
    const base = {
      schema: "proof.liskov.runtime-control.v1",
      command: {
        kind: "cease",
        commandId: "cease-1",
        reason: "update",
        issuedAtMs: 1,
        expiresAtMs: 100,
        binding: expected
      }
    };
    assert.deepEqual(parseRuntimeCeaseControl(base, expected, 100), { error: "control_expired" });
    assert.deepEqual(
      parseRuntimeCeaseControl({
        ...base,
        command: {
          ...base.command,
          expiresAtMs: 200,
          binding: { ...expected, jobId: "foreign" }
        }
      }, expected, 100),
      { error: "control_binding_mismatch" }
    );
  });
});
