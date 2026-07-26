import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
  LISKOV_RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2,
  liskovRuntimeBootstrapRequestMessage
} from "../src/bootstrap.js";
import { liskovRuntimeDiagnosticV4Message } from "../src/diagnostics.js";
import {
  LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN_V2,
  lockboxRuntimeJobSecretRequestMessage,
  lockboxRuntimeResponseAad
} from "../src/lockbox.js";
import {
  SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN_V2,
  slipwayRuntimeEnvRequestMessage
} from "../src/runtime-env.js";

const CORPUS_SHA256 = "c4433affeaad4bddb1a54bc115a746627ad5f1c2447a82c638a7f046e2b744a7";
const CORPUS_BYTES = readFileSync(
  new URL("./vectors/uid2-consumer-contracts.json", import.meta.url)
);
const CORPUS = JSON.parse(CORPUS_BYTES.toString("utf8")) as {
  schema: string;
  authority: string;
  runtimeBootstrapV2: {
    requestCanonical: string;
  };
  runtimeEnvironmentV2: {
    requestCanonical: string;
  };
  lockboxV2: {
    requestCanonical: string;
    responseAad: string;
  };
  runtimeDiagnosticsV4: {
    canonical: string;
  };
  blackboxLogConfigurationV2: {
    requiredBindings: string[];
  };
  negativeCases: Array<{
    protocol: string;
    mutation: string;
    expected: string;
  }>;
};

const APPLICATION_UID = "app-0123456789abcdef0123456789abcdef";
const POLICY_DIGEST = "1".repeat(64);

describe("UID-2 cross-language contract corpus", () => {
  it("matches the authoritative liskov-rs corpus digest and required coverage", () => {
    assert.equal(createHash("sha256").update(CORPUS_BYTES).digest("hex"), CORPUS_SHA256);
    assert.equal(CORPUS.schema, "proof.liskov.uid2-consumer-contracts.v1");
    assert.equal(CORPUS.authority, "proof-computer/liskov-rs");
    assert.deepEqual(CORPUS.blackboxLogConfigurationV2.requiredBindings, [
      "applicationUid",
      "applicationId",
      "jobId",
      "profileRevision"
    ]);
    assert.deepEqual(
      new Set(CORPUS.negativeCases.map(({ mutation }) => mutation)),
      new Set([
        "response.applicationUid",
        "response.applicationId",
        "plaintext.jobId",
        "response.domain=v1",
        "signature",
        "profileRevision",
        "applicationUid"
      ])
    );
  });

  it("pins bootstrap, runtime-env, Lockbox, AAD, and diagnostics canonical bytes", () => {
    assert.equal(Buffer.from(liskovRuntimeBootstrapRequestMessage({
      domain: LISKOV_RUNTIME_BOOTSTRAP_REQUEST_DOMAIN_V2,
      jobId: "job-1",
      processorId: "processor-1",
      nonce: "bootstrap-nonce",
      issuedAtMs: 1_000,
      expiresAtMs: 61_000
    })).toString("utf8"), CORPUS.runtimeBootstrapV2.requestCanonical);

    assert.equal(Buffer.from(slipwayRuntimeEnvRequestMessage({
      domain: SLIPWAY_RUNTIME_ENV_REQUEST_DOMAIN_V2,
      applicationUid: APPLICATION_UID,
      applicationId: "generic-worker",
      policyDigest: POLICY_DIGEST,
      jobId: "job-1",
      deploymentId: "42",
      processorId: "processor-1",
      nonce: "runtime-nonce",
      issuedAtMs: 1_000,
      expiresAtMs: 61_000
    })).toString("utf8"), CORPUS.runtimeEnvironmentV2.requestCanonical);

    const lockboxRequest: Parameters<typeof lockboxRuntimeJobSecretRequestMessage>[0] = {
      domain: LOCKBOX_RUNTIME_JOB_SECRET_REQUEST_DOMAIN_V2,
      applicationUid: APPLICATION_UID,
      applicationId: "generic-worker",
      grantId: "grant-1",
      policyDigest: POLICY_DIGEST,
      jobId: "job-1",
      deploymentId: "42",
      processorId: "processor-1",
      requestedSecretIds: ["file-config", "api-token"],
      nonce: "nonce-1",
      issuedAtMs: 1_000,
      expiresAtMs: 61_000,
      responseEncryptionKey: "ab".repeat(33)
    };
    assert.equal(
      Buffer.from(lockboxRuntimeJobSecretRequestMessage(lockboxRequest)).toString("utf8"),
      CORPUS.lockboxV2.requestCanonical
    );
    assert.equal(
      lockboxRuntimeResponseAad({
        request: lockboxRequest,
        response: { requestId: "lockbox-request-1" }
      }),
      CORPUS.lockboxV2.responseAad
    );

    assert.equal(Buffer.from(liskovRuntimeDiagnosticV4Message({
      applicationUid: APPLICATION_UID,
      jobId: "job-1",
      processorId: "processor-1",
      runtimeInstanceId: "07".repeat(16),
      stage: "runtime.health",
      status: "info",
      sequence: 0,
      timestampMs: 1_719_230_000_000,
      component: "runtime-health",
      code: null,
      message: null,
      attrs: { ready: true }
    })).toString("utf8"), CORPUS.runtimeDiagnosticsV4.canonical);
  });
});
