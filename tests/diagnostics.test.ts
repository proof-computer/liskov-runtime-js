import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { RuntimeIdentityProvider } from "../src/acurast.js";
import {
  createSlipwayRuntimeDiagnosticEmitter,
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
