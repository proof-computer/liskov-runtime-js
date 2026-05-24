import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { describe, it } from "node:test";

import {
  blackboxLogConfigFingerprint,
  blackboxLogHostnames,
  createBlackboxRemoteLogger,
  decryptProofLogRecord,
  generateProofLogEncryptionKey,
  readBlackboxLogConfig,
  type BlackboxLogBatch
} from "../src/index.js";

describe("Blackbox runtime logger", () => {
  it("parses compact config, signs writes, encrypts records, and keeps posted batches plaintext-free", async () => {
    const dek = generateProofLogEncryptionKey();
    const env = {
      BLACKBOX_LOG_CONFIG: Buffer.from(JSON.stringify({
        sid: "sink-1",
        jid: "job-1",
        url: "https://blackbox.test/v1/sinks/sink-1/events",
        k: dek,
        ctx: { applicationId: "generic-worker" }
      })).toString("base64url")
    };
    const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const signedMessages: string[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => env[name as keyof typeof env],
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: (message) => {
          signedMessages.push(Buffer.from(message).toString("utf8"));
          return "b".repeat(128);
        }
      },
      fetchImpl: (async (url, init) => {
        calls.push({
          url: String(url),
          headers: init?.headers as Record<string, string>,
          body: String(init?.body)
        });
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }) as typeof fetch,
      signedAt: () => "2026-05-24T12:00:00.000Z",
      nonce: () => "nonce-1",
      baseRecord: () => ({ deploymentId: "42" }),
      onError: (error) => assert.fail(String(error))
    });

    assert.equal(readBlackboxLogConfig((name) => env[name as keyof typeof env])?.sinkId, "sink-1");
    assert.deepEqual(blackboxLogHostnames((name) => env[name as keyof typeof env]), ["blackbox.test"]);
    assert.match(blackboxLogConfigFingerprint((name) => env[name as keyof typeof env]) ?? "", /^0x[0-9a-f]{64}$/u);

    await logger("validator-start", { poll: true });

    assert.equal(calls[0]?.url, "https://blackbox.test/v1/sinks/sink-1/events");
    assert.match(calls[0]?.headers.authorization ?? "", /^Ed25519 a{64}:/u);
    assert.match(signedMessages[0] ?? "", /^POST\n\/v1\/sinks\/sink-1\/events\n0x[0-9a-f]{64}\n2026-05-24T12:00:00\.000Z\nnonce-1$/u);
    assert.equal(calls[0]?.body.includes("validator-start"), false);
    assert.equal(calls[0]?.body.includes("poll"), false);

    const batch = JSON.parse(calls[0]!.body) as BlackboxLogBatch;
    const record = decryptProofLogRecord<Record<string, unknown>>(dek, batch.encrypted[0]!);
    assert.equal(record.event, "validator-start");
    assert.equal(record.deploymentId, "42");
    assert.deepEqual(record.details, { poll: true });
  });

  it("keeps failed batches queued so sequence continuity is preserved", async () => {
    const dek = generateProofLogEncryptionKey();
    const env = {
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        sinkId: "sink-1",
        jobId: "job-1",
        writeUrl: "https://blackbox.test/v1/sinks/sink-1/events",
        dek
      })
    };
    const calls: BlackboxLogBatch[] = [];
    let attempt = 0;
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => env[name as keyof typeof env],
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "c".repeat(64),
        sign: () => "d".repeat(128)
      },
      fetchImpl: (async (_url, init) => {
        attempt += 1;
        calls.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return attempt === 1
          ? new Response("temporary failure", { status: 503 })
          : new Response(JSON.stringify({ ok: true }), { status: 200 });
      }) as typeof fetch
    });

    await logger("first");
    await logger("second");

    assert.equal(calls.length, 3);
    assert.equal(calls[1]?.batchId, calls[0]?.batchId);
    assert.equal(calls[2]?.sequenceStart, 2);
    assert.equal(calls[2]?.previousHash, calls[1]?.batchId);
  });
});
