import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
  canonicalLiskovProcessorCoverageResultV1,
  LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1,
  liskovProcessorCoverageResultV1Message,
  signLiskovProcessorCoverageResultV1,
  type LiskovProcessorCoverageResultV1,
  type InboundReachabilityV1
} from "../src/processor-coverage.js";

const VECTOR = JSON.parse(
  readFileSync(new URL("./vectors/processor-coverage-result-v1.json", import.meta.url), "utf8")
) as { result: LiskovProcessorCoverageResultV1; canonicalSigningPayload: string };

describe("proof.liskov.processor-coverage-result.v1", () => {
  it("matches the shared canonical signing vector without changing diagnostics", () => {
    const canonical = canonicalLiskovProcessorCoverageResultV1(VECTOR.result);
    assert.equal(canonical.domain, LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1);
    assert.equal(
      Buffer.from(liskovProcessorCoverageResultV1Message(canonical)).toString("utf8"),
      VECTOR.canonicalSigningPayload
    );
  });

  it("signs exactly the canonical payload", async () => {
    const messages: string[] = [];
    const signed = await signLiskovProcessorCoverageResultV1(VECTOR.result, {
      async resolveIdentity() {
        return { jobId: "job-7", processorId: "processor-acurast-1" };
      },
      async sign(message) {
        messages.push(Buffer.from(message).toString("utf8"));
        return `0x${"22".repeat(64)}`;
      },
      async decryptGrantPayload() {
        throw new Error("not used by coverage signing");
      }
    });

    assert.equal(messages[0], VECTOR.canonicalSigningPayload);
    assert.equal(signed.signature, `0x${"22".repeat(64)}`);
  });

  it("rejects unbounded errors, inconsistent durations, and mismatched domains", () => {
    assert.throws(() => canonicalLiskovProcessorCoverageResultV1({
      ...VECTOR.result,
      domain: "proof.liskov.runtime-diagnostic.v4" as typeof LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1
    }), /domain must be proof\.liskov\.processor-coverage-result\.v1/u);

    assert.throws(() => canonicalLiskovProcessorCoverageResultV1({
      ...VECTOR.result,
      outcomes: [{ ...VECTOR.result.outcomes[0]!, durationMs: 999 }]
    }), /durationMs must equal/u);

    assert.throws(() => canonicalLiskovProcessorCoverageResultV1({
      ...VECTOR.result,
      outcomes: [{
        ...VECTOR.result.outcomes[0]!,
        errors: Array.from({ length: 17 }, () => ({ code: "bounded", message: "bounded" }))
      }]
    }), /at most 16/u);
  });
});

it("preserves and validates the shared signed network sample", () => {
  const vector = JSON.parse(readFileSync(new URL("./vectors/processor-coverage-network-v1.json", import.meta.url), "utf8")) as { result: LiskovProcessorCoverageResultV1; canonicalSigningPayload: string };
  assert.equal(Buffer.from(liskovProcessorCoverageResultV1Message(vector.result)).toString("utf8"), vector.canonicalSigningPayload);
  const corrupt = structuredClone(vector.result);
  corrupt.networkSample!.metrics.lossBps = 0;
  assert.throws(() => canonicalLiskovProcessorCoverageResultV1(corrupt), /invalid network sample/u);
});

it("carries the shared inbound reachability block through canonicalization", () => {
  const network = JSON.parse(readFileSync(new URL("./vectors/processor-coverage-network-v1.json", import.meta.url), "utf8")) as { result: LiskovProcessorCoverageResultV1 };
  const inbound = JSON.parse(readFileSync(new URL("./vectors/processor-coverage-inbound-v1.json", import.meta.url), "utf8")) as { inboundReachability: InboundReachabilityV1 };
  const result = { ...structuredClone(network.result), inboundReachability: inbound.inboundReachability };

  // The normalizer rebuilds the envelope from a known key set, so a block it
  // does not know about is dropped silently and the signature stops
  // reproducing. This is the assertion that catches that.
  const canonical = canonicalLiskovProcessorCoverageResultV1(result);
  assert.deepEqual(canonical.inboundReachability, inbound.inboundReachability);

  // Absence still canonicalizes to the exact bytes it always did.
  assert.equal(
    Buffer.from(liskovProcessorCoverageResultV1Message(network.result)).toString("utf8"),
    (JSON.parse(readFileSync(new URL("./vectors/processor-coverage-network-v1.json", import.meta.url), "utf8")) as { canonicalSigningPayload: string }).canonicalSigningPayload
  );

  for (const corrupt of [
    // A verdict claiming a path without the signature that proves it.
    (r: LiskovProcessorCoverageResultV1) => { r.inboundReachability!.families[0]!.signature = null; },
    // An unreachable family carrying one anyway.
    (r: LiskovProcessorCoverageResultV1) => { r.inboundReachability!.families[1]!.signature = `0x${"c".repeat(128)}`; },
    // Two verdicts for the same family.
    (r: LiskovProcessorCoverageResultV1) => { r.inboundReachability!.families[1]!.family = "v4"; },
    // Verdicts from two different probes spliced together.
    (r: LiskovProcessorCoverageResultV1) => { r.inboundReachability!.families[1]!.challengeDigest = `sha256:${"2".repeat(64)}`; },
    // A timeout that did not consume the wait it claims.
    (r: LiskovProcessorCoverageResultV1) => { r.inboundReachability!.families[1]!.connectMs = 5; },
    // A field the contract owner does not define.
    (r: LiskovProcessorCoverageResultV1) => { (r.inboundReachability!.families[0] as unknown as Record<string, unknown>)["peerAddress"] = "203.0.113.1"; }
  ]) {
    const mutated = structuredClone(result);
    corrupt(mutated);
    assert.throws(() => canonicalLiskovProcessorCoverageResultV1(mutated), /invalid inbound reachability/u);
  }
});
