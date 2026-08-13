import { Buffer } from "node:buffer";

import type { RuntimeIdentityProvider } from "./acurast.js";
import {
  canonicalJson,
  integerTimestamp,
  normalizeHex,
  requiredString
} from "./shared.js";

export const LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1 =
  "proof.liskov.processor-coverage-result.v1";

const MAX_OUTCOMES = 64;
const MAX_ERRORS = 16;
const MAX_ERROR_CODE_LENGTH = 96;
const MAX_ERROR_MESSAGE_LENGTH = 500;

export type LiskovProcessorCoverageRuntime = "javascript" | "native_image";
export type LiskovProcessorCoverageRelease = "source" | "pinned";
export type LiskovProcessorCoverageOutcomeStatus =
  | "succeeded"
  | "failed"
  | "timed_out"
  | "unsupported";

export interface LiskovProcessorCoverageTarget {
  targetId: string;
  provider: string;
  runtime: LiskovProcessorCoverageRuntime;
  release: LiskovProcessorCoverageRelease;
}

export interface LiskovProcessorCoverageError {
  code: string;
  message: string;
}

export interface LiskovProcessorCoverageOutcome {
  probeId: string;
  status: LiskovProcessorCoverageOutcomeStatus;
  region: string;
  startedAtMs: number;
  completedAtMs: number;
  durationMs: number;
  bytesSent: number;
  bytesReceived: number;
  errors: LiskovProcessorCoverageError[];
}

export interface LiskovProcessorCoverageResultV1 {
  domain: typeof LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1;
  applicationId: string;
  policyVersionId: string;
  policyDigest: string;
  artifactDigest: string;
  cycleId: string;
  target: LiskovProcessorCoverageTarget;
  deploymentId: string;
  jobId: string;
  processorId: string;
  probeVersion: string;
  profileVersion: string;
  sequence: number;
  issuedAtMs: number;
  expiresAtMs: number;
  outcomes: LiskovProcessorCoverageOutcome[];
  normalizedMetricDigest: string;
  challenge: string;
  replaySubject: string;
}

export interface LiskovSignedProcessorCoverageResultV1 extends LiskovProcessorCoverageResultV1 {
  signature: string;
}

export function canonicalLiskovProcessorCoverageResultV1(
  input: LiskovProcessorCoverageResultV1 | LiskovSignedProcessorCoverageResultV1
): LiskovProcessorCoverageResultV1 {
  const { signature: _signature, ...unsigned } = input as LiskovSignedProcessorCoverageResultV1;
  const record = unsigned as unknown as Record<string, unknown>;
  if (unsigned.domain !== LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1) {
    throw new Error(`domain must be ${LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1}`);
  }
  if (!Number.isSafeInteger(unsigned.sequence) || unsigned.sequence < 0) {
    throw new Error("sequence must be a non-negative safe integer");
  }
  const issuedAtMs = integerTimestamp(unsigned.issuedAtMs, "issuedAtMs");
  const expiresAtMs = integerTimestamp(unsigned.expiresAtMs, "expiresAtMs");
  if (expiresAtMs <= issuedAtMs) throw new Error("expiresAtMs must be later than issuedAtMs");
  if (!Array.isArray(unsigned.outcomes) || unsigned.outcomes.length === 0 || unsigned.outcomes.length > MAX_OUTCOMES) {
    throw new Error(`outcomes must contain between 1 and ${MAX_OUTCOMES} entries`);
  }

  return {
    domain: LISKOV_PROCESSOR_COVERAGE_RESULT_DOMAIN_V1,
    applicationId: requiredString(record, "applicationId"),
    policyVersionId: requiredString(record, "policyVersionId"),
    policyDigest: normalizeSha256Digest(unsigned.policyDigest, "policyDigest"),
    artifactDigest: normalizeSha256Digest(unsigned.artifactDigest, "artifactDigest"),
    cycleId: requiredString(record, "cycleId"),
    target: normalizeTarget(unsigned.target),
    deploymentId: requiredString(record, "deploymentId"),
    jobId: requiredString(record, "jobId"),
    processorId: requiredString(record, "processorId"),
    probeVersion: requiredString(record, "probeVersion"),
    profileVersion: requiredString(record, "profileVersion"),
    sequence: unsigned.sequence,
    issuedAtMs,
    expiresAtMs,
    outcomes: unsigned.outcomes.map(normalizeOutcome),
    normalizedMetricDigest: normalizeSha256Digest(
      unsigned.normalizedMetricDigest,
      "normalizedMetricDigest"
    ),
    challenge: normalizeHex(requiredString(record, "challenge")),
    replaySubject: requiredString(record, "replaySubject")
  };
}

export function liskovProcessorCoverageResultV1Message(
  result: LiskovProcessorCoverageResultV1 | LiskovSignedProcessorCoverageResultV1
): Uint8Array {
  return Buffer.from(canonicalJson(canonicalLiskovProcessorCoverageResultV1(result)), "utf8");
}

export async function signLiskovProcessorCoverageResultV1(
  result: LiskovProcessorCoverageResultV1,
  identityProvider: RuntimeIdentityProvider
): Promise<LiskovSignedProcessorCoverageResultV1> {
  const canonical = canonicalLiskovProcessorCoverageResultV1(result);
  return {
    ...canonical,
    signature: await identityProvider.sign(liskovProcessorCoverageResultV1Message(canonical))
  };
}

function normalizeTarget(target: LiskovProcessorCoverageTarget): LiskovProcessorCoverageTarget {
  if (target === null || typeof target !== "object" || Array.isArray(target)) {
    throw new Error("target must be an object");
  }
  const record = target as unknown as Record<string, unknown>;
  if (target.runtime !== "javascript" && target.runtime !== "native_image") {
    throw new Error("target.runtime must be javascript or native_image");
  }
  if (target.release !== "source" && target.release !== "pinned") {
    throw new Error("target.release must be source or pinned");
  }
  return {
    targetId: requiredString(record, "targetId"),
    provider: requiredString(record, "provider"),
    runtime: target.runtime,
    release: target.release
  };
}

function normalizeOutcome(outcome: LiskovProcessorCoverageOutcome): LiskovProcessorCoverageOutcome {
  if (outcome === null || typeof outcome !== "object" || Array.isArray(outcome)) {
    throw new Error("outcomes[] must be an object");
  }
  const record = outcome as unknown as Record<string, unknown>;
  if (!["succeeded", "failed", "timed_out", "unsupported"].includes(outcome.status)) {
    throw new Error("outcomes[].status is unsupported");
  }
  const startedAtMs = integerTimestamp(outcome.startedAtMs, "outcomes[].startedAtMs");
  const completedAtMs = integerTimestamp(outcome.completedAtMs, "outcomes[].completedAtMs");
  if (completedAtMs < startedAtMs) throw new Error("outcomes[].completedAtMs precedes startedAtMs");
  const durationMs = nonNegativeInteger(outcome.durationMs, "outcomes[].durationMs");
  if (durationMs !== completedAtMs - startedAtMs) {
    throw new Error("outcomes[].durationMs must equal completedAtMs - startedAtMs");
  }
  if (!Array.isArray(outcome.errors) || outcome.errors.length > MAX_ERRORS) {
    throw new Error(`outcomes[].errors must contain at most ${MAX_ERRORS} entries`);
  }
  return {
    probeId: requiredString(record, "probeId"),
    status: outcome.status,
    region: requiredString(record, "region"),
    startedAtMs,
    completedAtMs,
    durationMs,
    bytesSent: nonNegativeInteger(outcome.bytesSent, "outcomes[].bytesSent"),
    bytesReceived: nonNegativeInteger(outcome.bytesReceived, "outcomes[].bytesReceived"),
    errors: outcome.errors.map((error) => normalizeError(error))
  };
}

function normalizeError(error: LiskovProcessorCoverageError): LiskovProcessorCoverageError {
  if (error === null || typeof error !== "object" || Array.isArray(error)) {
    throw new Error("outcomes[].errors[] must be an object");
  }
  const record = error as unknown as Record<string, unknown>;
  const code = requiredString(record, "code");
  const message = requiredString(record, "message");
  if (code.length > MAX_ERROR_CODE_LENGTH) throw new Error("coverage error code is too long");
  if (message.length > MAX_ERROR_MESSAGE_LENGTH) throw new Error("coverage error message is too long");
  return { code, message };
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function normalizeSha256Digest(value: string, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a SHA-256 digest`);
  const normalized = value.trim().toLowerCase();
  if (!/^sha256:[0-9a-f]{64}$/u.test(normalized)) {
    throw new Error(`${label} must use sha256:<64 lowercase hex>`);
  }
  return normalized;
}
