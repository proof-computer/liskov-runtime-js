import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { Buffer } from "node:buffer";

import {
  canonicalLiskovProcessorCoverageResultV1,
  liskovProcessorCoverageResultV1Message,
  type LiskovProcessorCoverageResultV1
} from "../src/processor-coverage.js";
import {
  decodeTraversalCapability,
  normalizeNetworkTraversal,
  settleJsTraversalGrant,
  type InjectedTraversalTransport,
  type TraversalDescriptorV1
} from "../src/network-traversal.js";

const VECTOR = JSON.parse(
  readFileSync(new URL("./vectors/network-traversal-v1.json", import.meta.url), "utf8")
) as {
  testOnlyMacKeyHex: string;
  descriptors: Array<{ name: string; canonicalCapability: string; descriptor: TraversalDescriptorV1 }>;
  results: Array<{ name: string; networkTraversal: unknown }>;
  coverageResult: LiskovProcessorCoverageResultV1;
  canonicalCoverageSigningPayload: string;
};

const macKey = Buffer.from(VECTOR.testOnlyMacKeyHex, "hex");

function transport(nowMs: number, options: { cancelled?: boolean; offeredPayload?: Uint8Array } = {}): InjectedTraversalTransport & { sent: Uint8Array[] } {
  const sent: Uint8Array[] = [];
  return {
    sent,
    nowMs: () => nowMs,
    cancelled: () => options.cancelled === true,
    offeredPayload: options.offeredPayload,
    send(payload) {
      sent.push(payload);
    }
  };
}

function spies() {
  const calls = { bandwidth: 0, mutation: 0 };
  return {
    calls,
    bandwidthLadder: () => { calls.bandwidth += 1; },
    mutateRouter: () => { calls.mutation += 1; }
  };
}

describe("owner traversal vectors", () => {
  it("matches the present coverage signing payload and leaves absence unchanged", () => {
    const canonical = canonicalLiskovProcessorCoverageResultV1(VECTOR.coverageResult);
    assert.equal(canonical.networkSample, undefined);
    assert.equal(
      Buffer.from(liskovProcessorCoverageResultV1Message(canonical)).toString("utf8"),
      VECTOR.canonicalCoverageSigningPayload
    );
    for (const name of ["processor-coverage-result-v1.json", "processor-coverage-network-v1.json", "processor-coverage-inbound-v1.json"]) {
      const raw = readFileSync(new URL(`./vectors/${name}`, import.meta.url), "utf8");
      assert.equal(raw.includes("networkTraversal"), false);
    }
    const absent = JSON.parse(readFileSync(new URL("./vectors/processor-coverage-result-v1.json", import.meta.url), "utf8")) as {
      result: LiskovProcessorCoverageResultV1;
      canonicalSigningPayload: string;
    };
    assert.equal(
      Buffer.from(liskovProcessorCoverageResultV1Message(absent.result)).toString("utf8"),
      absent.canonicalSigningPayload
    );
  });

  it("accepts every owner result block and refuses a forged field or version", () => {
    for (const result of VECTOR.results) normalizeNetworkTraversal(result.networkTraversal);
    const forged = structuredClone(VECTOR.coverageResult.networkTraversal) as unknown as Record<string, unknown>;
    forged.gatewayAddress = "192.0.2.1";
    assert.throws(() => canonicalLiskovProcessorCoverageResultV1({ ...VECTOR.coverageResult, networkTraversal: forged as never }), /networkTraversal: Malformed/u);
    const version = structuredClone(VECTOR.coverageResult.networkTraversal) as { version: number };
    version.version = 2;
    assert.throws(() => normalizeNetworkTraversal(version), /UnknownVersion/u);
    const huge = { ...VECTOR.coverageResult, applicationId: "x".repeat(20_000) };
    assert.throws(() => canonicalLiskovProcessorCoverageResultV1(huge), /networkTraversal envelope: Oversize/u);
  });

  it("decodes every owner capability with the test MAC key", () => {
    for (const entry of VECTOR.descriptors) {
      const now = entry.descriptor.issuedAtMs + 1000;
      const decoded = decodeTraversalCapability(entry.canonicalCapability, macKey, now);
      assert.equal(decoded.runId, entry.descriptor.runId);
      assert.equal(decoded.mode, entry.descriptor.mode);
    }
  });
});

describe("JS traversal grants", () => {
  const observe = VECTOR.descriptors[0]!;
  const claim = observe.descriptor.claimAuthorityDigest;
  const openNow = observe.descriptor.issuedAtMs + 1000;

  function settle(grant: unknown, nowMs: number, options: { cancelled?: boolean; offeredPayload?: Uint8Array; claim?: string } = {}) {
    const probe = transport(nowMs, options);
    const effect = spies();
    const settlement = settleJsTraversalGrant({
      grant,
      macKey,
      claimAuthorityDigest: options.claim ?? claim,
      jobExpiresAtMs: observe.descriptor.expiresAtMs,
      deliveryReserveMs: 1000,
      transport: probe,
      bandwidthLadder: effect.bandwidthLadder,
      mutateRouter: effect.mutateRouter
    });
    return { settlement, probe, effect };
  }

  it("does not run the bandwidth ladder and reports missing primitives without sending", () => {
    const { settlement, probe, effect } = settle(observe.canonicalCapability, openNow, { offeredPayload: Uint8Array.of(1, 2, 3) });
    assert.equal(effect.calls.bandwidth, 0);
    assert.equal(effect.calls.mutation, 0);
    assert.equal(probe.sent.length, 0);
    assert.equal(settlement.effects, "unsupported");
    assert.equal(settlement.routerMutationAuthorized, false);
    assert.deepEqual(settlement.primitives.sort(), ["gateway", "listener", "socket"]);
    assert.ok(settlement.networkTraversal);
    assert.equal(settlement.networkTraversal.proofs.length, 0);
    assert.ok(settlement.networkTraversal.phases.every((phase) => phase.outcome === "unsupported_runtime_api" && phase.errorClass === null && phase.proofDigest === null));
  });

  it("gives a generic coverage grant no router mutation and no traversal effects", () => {
    const { settlement, probe, effect } = settle({ kind: "coverage" }, openNow);
    assert.equal(settlement.reason, "coverage-grant");
    assert.equal(settlement.effects, "none");
    assert.equal(settlement.networkTraversal, undefined);
    assert.equal(effect.calls.bandwidth, 0);
    assert.equal(effect.calls.mutation, 0);
    assert.equal(probe.sent.length, 0);
  });

  it("causes no effects for unknown, misbound, and expired grants", () => {
    for (const [grant, now, boundClaim, reason] of [
      [{ kind: "not-a-grant" }, openNow, claim, "unknown-grant"],
      [observe.canonicalCapability, openNow, `sha256:${"ab".repeat(32)}`, "misbound"],
      [observe.canonicalCapability, observe.descriptor.expiresAtMs, claim, "expired"]
    ] as const) {
      const { settlement, probe, effect } = settle(grant, now, { claim: boundClaim });
      assert.equal(settlement.reason, reason);
      assert.equal(settlement.effects, "none");
      assert.equal(settlement.networkTraversal, undefined);
      assert.equal(effect.calls.bandwidth, 0);
      assert.equal(effect.calls.mutation, 0);
      assert.equal(probe.sent.length, 0);
    }
  });

  it("stops on cancellation, an impossible deadline, and an over-cap payload before any send", () => {
    const cancelled = settle(observe.canonicalCapability, openNow, { cancelled: true });
    assert.equal(cancelled.settlement.reason, "cancelled");
    assert.equal(cancelled.probe.sent.length, 0);
    assert.equal(cancelled.effect.calls.bandwidth, 0);

    const deadline = settle(observe.canonicalCapability, observe.descriptor.deadlineMs - 1000);
    assert.equal(deadline.settlement.reason, "deadline");
    assert.equal(deadline.probe.sent.length, 0);
    assert.equal(deadline.settlement.networkTraversal, undefined);

    const capped = settle(observe.canonicalCapability, openNow, { offeredPayload: new Uint8Array(513) });
    assert.equal(capped.settlement.reason, "payload-cap");
    assert.equal(capped.probe.sent.length, 0);
    assert.equal(capped.effect.calls.mutation, 0);
    assert.equal(capped.effect.calls.bandwidth, 0);
  });
});
