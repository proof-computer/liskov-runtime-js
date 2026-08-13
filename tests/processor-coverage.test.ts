import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
  canonicalLiskovProcessorCoverageResultV1,
  LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1,
  liskovProcessorCoverageResultV1Message,
  signLiskovProcessorCoverageResultV1,
  type LiskovProcessorCoverageResultV1
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
