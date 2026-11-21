import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { it } from "node:test";

import {
  canonicalLiskovProcessorCoverageResultV1,
  type LiskovProcessorCoverageResultV1
} from "../src/processor-coverage.js";
import { normalizeWebViewRuntime, type WebViewRuntimeV1 } from "../src/index.js";

const VECTOR = JSON.parse(
  readFileSync(new URL("./vectors/processor-coverage-webview-v1.json", import.meta.url), "utf8")
) as { result: LiskovProcessorCoverageResultV1 };

const observed = {
  version: 1,
  status: "observed",
  chromeVersion: "138.0.7204.179",
  durationMs: 1840
};

function envelope(block: unknown): LiskovProcessorCoverageResultV1 {
  const result = structuredClone(VECTOR.result);
  (result as { webview: unknown }).webview = block;
  return result;
}

function refuses(block: unknown): void {
  assert.throws(() => canonicalLiskovProcessorCoverageResultV1(envelope(block)), /webview:/u);
}

it("accepts the shapes liskov-rs accepts, including durationMs 20000", () => {
  const atBound: WebViewRuntimeV1 = normalizeWebViewRuntime({
    version: 1,
    status: "observed",
    chromeVersion: "0.0.0.0",
    durationMs: 20000
  });
  assert.deepEqual(canonicalLiskovProcessorCoverageResultV1(envelope(atBound)).webview, atBound);
  assert.deepEqual(
    canonicalLiskovProcessorCoverageResultV1(envelope({
      version: 1,
      status: "failed",
      errorCode: "timed_out",
      durationMs: 0
    })).webview,
    { version: 1, status: "failed", errorCode: "timed_out", durationMs: 0 }
  );
  assert.deepEqual(
    canonicalLiskovProcessorCoverageResultV1(envelope({
      version: 1,
      status: "unavailable",
      errorCode: "webview_api_absent",
      durationMs: 0
    })).webview,
    { version: 1, status: "unavailable", errorCode: "webview_api_absent", durationMs: 0 }
  );
});

it("throws on each webview value liskov-rs refuses", () => {
  const failed = { version: 1, status: "failed", errorCode: "timed_out", durationMs: 0 };
  const unavailable = { version: 1, status: "unavailable", errorCode: "webview_api_absent", durationMs: 0 };
  for (const block of [
    { ...failed, chromeVersion: "138.0.1.1" },
    { ...failed, errorCode: "nope" },
    { ...failed, errorCode: "webview_api_absent" },
    { ...unavailable, errorCode: "timed_out" },
    { ...observed, chromeVersion: "138.0" },
    { ...observed, chromeVersion: "0138.0.1.1" },
    { ...observed, chromeVersion: "10000.0.1.1" },
    { ...observed, chromeVersion: "1.0.1000000.1" },
    { ...observed, chromeVersion: "-1.0.1.1" },
    { ...observed, chromeVersion: "1.0.1.1.1" },
    { ...observed, errorCode: null },
    { ...observed, durationMs: 20001 },
    { ...observed, durationMs: -1 },
    { ...observed, version: 2 },
    { ...observed, userAgent: "unexpected" },
    { version: 1, status: "observed", durationMs: 1840 },
    { version: 1, status: "failed", durationMs: 0 },
    null
  ]) refuses(block);
});
