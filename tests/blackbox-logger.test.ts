import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
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
import {
  installDiskSpoolModulesForTest,
  type DiskSpoolModules
} from "../src/blackbox-spool-internal.js";

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
      spoolMode: "memory",
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: (message) => {
          signedMessages.push(Buffer.from(message).toString("utf8"));
          return "b".repeat(128);
        }
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/resume")) {
          return resumeResponse("sink-1", { nextSequence: 1, previousHash: null });
        }
        calls.push({
          url: String(url),
          headers: init?.headers as Record<string, string>,
          body: String(init?.body)
        });
        return acceptedBatchResponse(init, 200);
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
    assert.match(signedMessages[0] ?? "", /^POST\n\/v1\/sinks\/sink-1\/resume\n0x[0-9a-f]{64}\n2026-05-24T12:00:00\.000Z\nnonce-1$/u);
    assert.match(signedMessages[1] ?? "", /^POST\n\/v1\/sinks\/sink-1\/events\n0x[0-9a-f]{64}\n2026-05-24T12:00:00\.000Z\nnonce-1$/u);
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
      spoolMode: "memory",
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "c".repeat(64),
        sign: () => "d".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/resume")) {
          return resumeResponse("sink-1", { nextSequence: 1, previousHash: null });
        }
        attempt += 1;
        calls.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return attempt === 1
          ? new Response("temporary failure", { status: 503 })
          : acceptedBatchResponse(init, 200);
      }) as typeof fetch
    });

    await logger("first");
    await logger("second");

    assert.equal(calls.length, 3);
    assert.equal(calls[1]?.batchId, calls[0]?.batchId);
    assert.equal(calls[2]?.sequenceStart, 2);
    assert.equal(calls[2]?.previousHash, calls[1]?.batchId);
  });

  it("parses the factory-token config variant with short and long field names", () => {
    const dek = generateProofLogEncryptionKey();
    const fromShort = readBlackboxLogConfig((name) =>
      name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            ft: "bbx_sf_fac-1_secret",
            base: "https://blackbox.test",
            spool: "/data/spool",
            k: dek,
            ctx: "deck"
          })
        : undefined
    );
    assert.equal(fromShort?.factoryToken, "bbx_sf_fac-1_secret");
    assert.equal(fromShort?.factoryId, "fac-1");
    assert.equal(fromShort?.baseUrl, "https://blackbox.test");
    assert.equal(fromShort?.spoolDir, "/data/spool");
    assert.equal(fromShort?.sinkId, undefined);

    const explicitEnv: Record<string, string | undefined> = {
      BLACKBOX_FACTORY_TOKEN: "bbx_sf_fac-2_secret",
      BLACKBOX_BASE_URL: "https://blackbox.test",
      BLACKBOX_LOG_DEK: dek
    };
    const fromExplicitEnv = readBlackboxLogConfig((name) => explicitEnv[name]);
    assert.equal(fromExplicitEnv?.factoryId, "fac-2");

    const getFactoryConfig = (name: string) =>
      name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({ factoryToken: "bbx_sf_fac-1_secret", baseUrl: "https://blackbox.test", dek })
        : undefined;
    assert.deepEqual(blackboxLogHostnames(getFactoryConfig), ["blackbox.test"]);
    assert.match(blackboxLogConfigFingerprint(getFactoryConfig) ?? "", /^0x[0-9a-f]{64}$/u);
  });

  it("self-registers a job-bound sink from a factory token, then writes to the derived sink URL", async () => {
    const dek = generateProofLogEncryptionKey();
    const env = {
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken: "bbx_sf_fac-1_secret",
        baseUrl: "https://blackbox.test",
        applicationId: "switchboard-validator",
        dek
      })
    };
    const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => env[name as keyof typeof env],
      spoolMode: "memory",
      std: { job: { getId: () => 76976 } },
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        calls.push({
          url: String(url),
          headers: init?.headers as Record<string, string>,
          body: String(init?.body)
        });
        return String(url).endsWith("/job-sinks")
          ? new Response(JSON.stringify({
              sink: {
                sinkId: "sink-job-76976",
                writeUrl: "https://blackbox.test/v1/sinks/sink-job-76976/events",
                resumeUrl: "https://blackbox.test/v1/sinks/sink-job-76976/resume"
              },
              chain: { nextSequence: 1, previousHash: null }
            }), { status: 201 })
          : acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => assert.fail(String(error))
    });

    await logger("validator-start", { boot: 1 });
    await logger("validator-poll-start");

    assert.equal(calls[0]?.url, "https://blackbox.test/v1/sink-factories/fac-1/job-sinks");
    assert.equal(calls[0]?.headers["x-blackbox-sink-factory-token"], "bbx_sf_fac-1_secret");
    assert.match(calls[0]?.headers.authorization ?? "", /^Ed25519 a{64}:/u);
    assert.deepEqual(JSON.parse(calls[0]!.body), { applicationId: "switchboard-validator", jobId: "76976" });

    assert.equal(calls[1]?.url, "https://blackbox.test/v1/sinks/sink-job-76976/events");
    const first = JSON.parse(calls[1]!.body) as BlackboxLogBatch;
    assert.equal(first.sinkId, "sink-job-76976");
    assert.equal(first.jobId, "76976");
    assert.equal(first.sequenceStart, 1);

    // The second write reuses the cached sink (exactly one self-register call).
    assert.equal(calls.length, 3);
    assert.equal(calls[2]?.url, "https://blackbox.test/v1/sinks/sink-job-76976/events");
    assert.equal((JSON.parse(calls[2]!.body) as BlackboxLogBatch).sequenceStart, 2);
  });

  it("resumes a fresh in-memory invocation from the factory's canonical chain head", async () => {
    const dek = generateProofLogEncryptionKey();
    const batches: BlackboxLogBatch[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            factoryToken: "bbx_sf_fac-1_secret",
            baseUrl: "https://blackbox.test",
            dek
          })
        : undefined,
      spoolMode: "memory",
      std: { job: { getId: () => "job-ephemeral" } },
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/job-sinks")) {
          return Response.json({
            sinkId: "sink-ephemeral",
            chain: { nextSequence: 41, previousHash: chainHash("1") }
          });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => assert.fail(String(error))
    });

    await logger("after-ephemeral-restart");

    assert.equal(batches.length, 1);
    assert.equal(batches[0]?.sequenceStart, 41);
    assert.equal(batches[0]?.sequenceEnd, 41);
    assert.equal(batches[0]?.previousHash, chainHash("1"));
  });

  it("resumes a fresh pre-bound invocation before constructing its first batch", async () => {
    const dek = generateProofLogEncryptionKey();
    const urls: string[] = [];
    const batches: BlackboxLogBatch[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            sinkId: "sink-prebound",
            jobId: "job-prebound",
            writeUrl: "https://blackbox.test/v1/sinks/sink-prebound/events",
            resumeUrl: "https://blackbox.test/v1/sinks/sink-prebound/resume",
            dek
          })
        : undefined,
      spoolMode: "memory",
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        urls.push(String(url));
        if (String(url).endsWith("/resume")) {
          assert.deepEqual(JSON.parse(String(init?.body)), {
            jobId: "job-prebound",
            writerPublicKey: "a".repeat(64)
          });
          return resumeResponse("sink-prebound", { nextSequence: 11, previousHash: chainHash("2") });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => assert.fail(String(error))
    });

    await logger("prebound-restart");

    assert.deepEqual(urls, [
      "https://blackbox.test/v1/sinks/sink-prebound/resume",
      "https://blackbox.test/v1/sinks/sink-prebound/events"
    ]);
    assert.equal(batches[0]?.sequenceStart, 11);
    assert.equal(batches[0]?.previousHash, chainHash("2"));
  });

  it("consumes a conflict head and retries a racing sequence conflict", async () => {
    const dek = generateProofLogEncryptionKey();
    let registrations = 0;
    const batches: BlackboxLogBatch[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            factoryToken: "bbx_sf_fac-1_secret",
            baseUrl: "https://blackbox.test",
            dek
          })
        : undefined,
      spoolMode: "memory",
      std: { job: { getId: () => "job-race" } },
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/job-sinks")) {
          registrations += 1;
          return Response.json({
            sinkId: "sink-race",
            chain: { nextSequence: 1, previousHash: null }
          });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return batches.length === 1
          ? new Response(JSON.stringify({
              ok: false,
              error: "sequence_conflict",
              reason: "sequence already exists with a different hash",
              chain: { nextSequence: 2, previousHash: chainHash("3") },
              auditEventId: "17"
            }), { status: 409 })
          : acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => assert.fail(String(error))
    });

    await logger("racing-event");

    assert.equal(registrations, 1);
    assert.equal(batches.length, 2);
    assert.equal(batches[0]?.sequenceStart, 1);
    assert.equal(batches[1]?.sequenceStart, 2);
    assert.equal(batches[1]?.previousHash, chainHash("3"));
    assert.notEqual(batches[1]?.batchId, batches[0]?.batchId);
    assert.deepEqual(batches[1]?.encrypted, batches[0]?.encrypted);
  });

  it("rebases when the next sequence is unchanged but the canonical hash changed", async () => {
    const dek = generateProofLogEncryptionKey();
    const batches: BlackboxLogBatch[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            sinkId: "sink-same-sequence",
            jobId: "job-same-sequence",
            writeUrl: "https://blackbox.test/v1/sinks/sink-same-sequence/events",
            dek
          })
        : undefined,
      spoolMode: "memory",
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/resume")) {
          return resumeResponse("sink-same-sequence", {
            nextSequence: 7,
            previousHash: chainHash("4")
          });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return batches.length === 1
          ? new Response(JSON.stringify({
              ok: false,
              error: "sequence_conflict",
              chain: { nextSequence: 7, previousHash: chainHash("5") },
              auditEventId: "18"
            }), { status: 409 })
          : acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => assert.fail(String(error))
    });

    await logger("same-sequence-race");

    assert.equal(batches.length, 2);
    assert.equal(batches[0]?.sequenceStart, 7);
    assert.equal(batches[1]?.sequenceStart, 7);
    assert.equal(batches[1]?.previousHash, chainHash("5"));
    assert.equal(batches[1]?.createdAt, batches[0]?.createdAt);
    assert.deepEqual(batches[1]?.encrypted, batches[0]?.encrypted);
    assert.notEqual(batches[1]?.batchId, batches[0]?.batchId);
  });

  it("replays an accepted pending batch in its original form after the response is lost", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-lost-response-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const dek = generateProofLogEncryptionKey();
    let accepted: BlackboxLogBatch | undefined;
    const firstErrors: string[] = [];
    const makeLogger = (lostResponse: boolean, errors: string[]) => createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            sinkId: "sink-lost-response",
            jobId: "job-lost-response",
            writeUrl: "https://blackbox.test/v1/sinks/sink-lost-response/events",
            spoolDir,
            dek
          })
        : undefined,
      spoolMode: "disk",
      spoolDir,
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/resume")) {
          return resumeResponse("sink-lost-response", accepted
            ? { nextSequence: accepted.sequenceEnd + 1, previousHash: accepted.batchId ?? null }
            : { nextSequence: 1, previousHash: null });
        }
        const replay = JSON.parse(String(init?.body)) as BlackboxLogBatch;
        if (!accepted) accepted = replay;
        else if (replay.batchId === accepted.batchId) assert.deepEqual(replay, accepted);
        if (lostResponse) throw new Error("response lost after accept");
        return acceptedBatchResponse(init, 200);
      }) as typeof fetch,
      onError: (error) => errors.push(String(error))
    });

    await makeLogger(true, firstErrors)("accepted-before-disconnect");
    assert.equal(firstErrors.length, 1);
    assert.equal((await fs.readdir(path.join(spoolDir, "batches"))).length, 1);

    const replayErrors: string[] = [];
    await makeLogger(false, replayErrors)("after-restart");
    assert.deepEqual(replayErrors, []);
    assert.equal((await fs.readdir(path.join(spoolDir, "batches"))).length, 0);
  });

  it("keeps the durable spool intact and reports once when resume data is malformed", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-malformed-resume-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const errors: string[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            sinkId: "sink-malformed",
            jobId: "job-malformed",
            writeUrl: "https://blackbox.test/v1/sinks/sink-malformed/events",
            spoolDir,
            dek: generateProofLogEncryptionKey()
          })
        : undefined,
      spoolMode: "disk",
      spoolDir,
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async () => Response.json({
        ok: true,
        sinkId: "sink-malformed",
        chain: { nextSequence: 2, previousHash: "not-a-chain-hash" }
      })) as typeof fetch,
      onError: (error) => errors.push(String(error))
    });

    await logger("remains-spooled");

    assert.equal(errors.length, 1);
    assert.match(errors[0] ?? "", /32-byte 0x-prefixed hash/u);
    assert.equal((await fs.readdir(path.join(spoolDir, "records"))).length, 1);
    assert.equal((await fs.readdir(path.join(spoolDir, "batches"))).length, 0);
  });

  it("stops after three conflict rebases and emits one redacted failure", async () => {
    const errors: string[] = [];
    const batches: BlackboxLogBatch[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            factoryToken: "bbx_sf_exhausted_secret",
            baseUrl: "https://blackbox.test",
            dek: generateProofLogEncryptionKey()
          })
        : undefined,
      spoolMode: "memory",
      std: { job: { getId: () => "job-exhausted" } },
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/job-sinks")) {
          return Response.json({
            sinkId: "sink-exhausted",
            chain: { nextSequence: 1, previousHash: null }
          });
        }
        const batch = JSON.parse(String(init?.body)) as BlackboxLogBatch;
        batches.push(batch);
        return new Response(JSON.stringify({
          ok: false,
          error: "sequence_conflict",
          reason: "conflict",
          chain: {
            nextSequence: batch.sequenceStart + 1,
            previousHash: chainHash(String(batches.length % 10))
          },
          auditEventId: String(100 + batches.length)
        }), { status: 409 });
      }) as typeof fetch,
      onError: (error) => errors.push(String(error))
    });

    await logger("retry-exhaustion", { secret: "must-not-appear" });

    assert.equal(batches.length, 4);
    assert.deepEqual(batches.map((batch) => batch.sequenceStart), [1, 2, 3, 4]);
    assert.equal(errors.length, 1);
    assert.match(errors[0] ?? "", /Blackbox log write failed: 409/u);
    assert.equal(errors[0]?.includes("must-not-appear"), false);
  });

  it("spools records while self-registration fails and flushes them all once the sink exists", async () => {
    const dek = generateProofLogEncryptionKey();
    const env = {
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken: "bbx_sf_fac-1_secret",
        baseUrl: "https://blackbox.test",
        dek
      })
    };
    const errors: string[] = [];
    let registerAttempts = 0;
    const batches: BlackboxLogBatch[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) => env[name as keyof typeof env],
      spoolMode: "memory",
      std: { job: { getId: () => "job-9" } },
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/job-sinks")) {
          registerAttempts += 1;
          return registerAttempts === 1
            ? new Response("unreachable", { status: 503 })
            : new Response(JSON.stringify({
                sinkId: "sink-9",
                chain: { nextSequence: 1, previousHash: null }
              }), { status: 201 });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => errors.push(String(error))
    });

    await logger("prepare-start");
    assert.equal(errors.length, 1);
    assert.match(errors[0] ?? "", /self-register failed: 503/u);
    assert.equal(batches.length, 0);

    await logger("prepare-done");
    assert.equal(registerAttempts, 2);
    assert.equal(batches.length, 1);
    // Both spooled records flush in one in-order batch once the sink exists.
    assert.equal(batches[0]?.sequenceStart, 1);
    assert.equal(batches[0]?.sequenceEnd, 2);
    const events = batches[0]!.encrypted.map(
      (record) => decryptProofLogRecord<Record<string, unknown>>(dek, record).event
    );
    assert.deepEqual(events, ["prepare-start", "prepare-done"]);
  });

  it("persists spool state on disk so a restarted writer keeps its sink and sequence", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-spool-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));

    const dek = generateProofLogEncryptionKey();
    const env = {
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken: "bbx_sf_fac-1_secret",
        baseUrl: "https://blackbox.test",
        spoolDir,
        dek
      })
    };
    let registerAttempts = 0;
    const batches: BlackboxLogBatch[] = [];
    const makeLogger = () =>
      createBlackboxRemoteLogger({
        getConfigValue: (name) => env[name as keyof typeof env],
        std: { job: { getId: () => "job-9" } },
        signer: {
          scheme: "Ed25519",
          publicKeyHex: "a".repeat(64),
          sign: () => "b".repeat(128)
        },
        fetchImpl: (async (url, init) => {
          if (String(url).endsWith("/job-sinks")) {
            registerAttempts += 1;
            return new Response(JSON.stringify({
              sinkId: "sink-9",
              chain: { nextSequence: 1, previousHash: null }
            }), { status: 201 });
          }
          if (String(url).endsWith("/resume")) {
            const last = batches.at(-1);
            return resumeResponse("sink-9", last
              ? { nextSequence: last.sequenceEnd + 1, previousHash: last.batchId ?? null }
              : { nextSequence: 1, previousHash: null });
          }
          batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
          return acceptedBatchResponse(init);
        }) as typeof fetch,
        onError: (error) => assert.fail(String(error))
      });

    await makeLogger()("first-boot");
    await makeLogger()("after-restart");

    // The restarted writer reuses the persisted sink (no second self-register)
    // and continues the persisted chain instead of restarting at sequence 1.
    assert.equal(registerAttempts, 1);
    assert.equal(batches.length, 2);
    assert.equal(batches[1]?.sinkId, "sink-9");
    assert.equal(batches[1]?.sequenceStart, 2);
    assert.equal(batches[1]?.previousHash, batches[0]?.batchId);
  });

  it("resets persisted sink and chain identity when the runtime job changes", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-job-reset-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const dek = generateProofLogEncryptionKey();
    const registrations: string[] = [];
    const batches: BlackboxLogBatch[] = [];
    const makeLogger = (jobId: string) => createBlackboxRemoteLogger({
      getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
        ? JSON.stringify({
            factoryToken: "bbx_sf_reset_secret",
            baseUrl: "https://blackbox.test",
            spoolDir,
            dek
          })
        : undefined,
      spoolMode: "disk",
      spoolDir,
      std: { job: { getId: () => jobId } },
      signer: {
        scheme: "Ed25519",
        publicKeyHex: "a".repeat(64),
        sign: () => "b".repeat(128)
      },
      fetchImpl: (async (url, init) => {
        if (String(url).endsWith("/job-sinks")) {
          const body = JSON.parse(String(init?.body)) as { jobId: string };
          registrations.push(body.jobId);
          return Response.json({
            sinkId: `sink-${body.jobId}`,
            chain: { nextSequence: 1, previousHash: null }
          });
        }
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return acceptedBatchResponse(init);
      }) as typeof fetch,
      onError: (error) => assert.fail(String(error))
    });

    await makeLogger("job-one")("first-job");
    await makeLogger("job-two")("second-job");

    assert.deepEqual(registrations, ["job-one", "job-two"]);
    assert.deepEqual(batches.map((batch) => [batch.sinkId, batch.jobId, batch.sequenceStart]), [
      ["sink-job-one", "job-one", 1],
      ["sink-job-two", "job-two", 1]
    ]);
  });

  it("fails loudly on an unrecognized config shape instead of degrading to a silent no-op", async () => {
    const errors: string[] = [];
    const logger = createBlackboxRemoteLogger({
      getConfigValue: (name) =>
        name === "BLACKBOX_LOG_CONFIG" ? JSON.stringify({ mystery: true }) : undefined,
      onError: (error) => errors.push(String(error))
    });
    await logger("boot");
    assert.equal(errors.length, 1);
    assert.match(errors[0] ?? "", /requires dek/u);

    const missingBase = createBlackboxRemoteLogger({
      getConfigValue: (name) =>
        name === "BLACKBOX_LOG_CONFIG"
          ? JSON.stringify({ factoryToken: "bbx_sf_fac-1_secret", dek: generateProofLogEncryptionKey() })
          : undefined,
      onError: (error) => errors.push(String(error))
    });
    await missingBase("boot");
    assert.equal(errors.length, 2);
    assert.match(errors[1] ?? "", /requires baseUrl/u);
  });

  it("serializes concurrent disk admissions while a sink request is blocked and flushes every event exactly once", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-concurrent-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const dek = generateProofLogEncryptionKey();
    const errors: string[] = [];
    const batches: BlackboxLogBatch[] = [];
    let releaseFirst!: () => void;
    const firstReleased = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let firstRequestStarted!: () => void;
    const firstRequest = new Promise<void>((resolve) => { firstRequestStarted = resolve; });
    let requests = 0;
    const logger = diskLogger({
      spoolDir,
      dek,
      onError: (error) => errors.push(String(error)),
      fetchImpl: (async (_url, init) => {
        requests += 1;
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        if (requests === 1) {
          firstRequestStarted();
          await firstReleased;
        }
        return acceptedBatchResponse(init);
      }) as typeof fetch
    });

    const writes = [logger("event-000")];
    await firstRequest;
    for (let index = 1; index < 126; index += 1) {
      writes.push(logger(`event-${String(index).padStart(3, "0")}`));
    }
    await waitFor(async () => (await durableJsonSize(spoolDir)) > 0);
    releaseFirst();
    await Promise.all(writes);

    assert.deepEqual(errors, []);
    assert.ok(batches.length >= 4);
    assert.ok(batches.every((batch) => batch.encrypted.length <= 50));
    let nextSequence = 1;
    const events: string[] = [];
    for (const batch of batches) {
      assert.equal(batch.sequenceStart, nextSequence);
      assert.equal(batch.sequenceEnd, batch.sequenceStart + batch.encrypted.length - 1);
      nextSequence = batch.sequenceEnd + 1;
      for (const encrypted of batch.encrypted) {
        events.push(decryptProofLogRecord<{ event: string }>(dek, encrypted).event);
      }
    }
    assert.equal(events.length, 126);
    assert.equal(new Set(events).size, 126);
    assert.deepEqual([...events].sort(), Array.from({ length: 126 }, (_, index) => `event-${String(index).padStart(3, "0")}`));
  });

  it("wakes the active flush for a record admitted during its completion window", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-late-flush-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const recordsDir = path.join(spoolDir, "records");
    let recordListings = 0;
    let releaseEmptyListing!: () => void;
    const emptyListingReleased = new Promise<void>((resolve) => { releaseEmptyListing = resolve; });
    let emptyListingReached!: () => void;
    const emptyListing = new Promise<void>((resolve) => { emptyListingReached = resolve; });
    const proxyFs = new Proxy(fs, {
      get(target, property, receiver) {
        if (property !== "readdir") return Reflect.get(target, property, receiver);
        return async (directory: Parameters<typeof fs.readdir>[0], ...args: unknown[]) => {
          const result = await fs.readdir(directory as string, ...(args as []));
          if (path.resolve(String(directory)) === path.resolve(recordsDir)) {
            recordListings += 1;
            if (recordListings === 3) {
              emptyListingReached();
              await emptyListingReleased;
            }
          }
          return result;
        };
      }
    }) as typeof fs;
    const restore = installDiskSpoolModulesForTest({ fs: proxyFs, path: path as DiskSpoolModules["path"] });
    t.after(restore);
    const batches: BlackboxLogBatch[] = [];
    const logger = diskLogger({
      spoolDir,
      fetchImpl: (async (_url, init) => {
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return acceptedBatchResponse(init);
      }) as typeof fetch
    });

    const first = logger("first");
    await emptyListing;
    const late = logger("late");
    await waitFor(async () => (await fs.readdir(recordsDir)).some((file) => file.endsWith(".json")));
    releaseEmptyListing();
    await Promise.all([first, late]);

    assert.equal(batches.length, 2);
    assert.deepEqual(batches.map((batch) => batch.sequenceStart), [1, 2]);
  });

  it("ignores orphan temporary files for quota and tolerates a listed JSON file disappearing before stat", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-size-race-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const recordsDir = path.join(spoolDir, "records");
    await fs.mkdir(recordsDir, { recursive: true });
    await fs.mkdir(path.join(spoolDir, "batches"), { recursive: true });
    await fs.writeFile(path.join(recordsDir, "orphan.json.deadbeef.tmp"), Buffer.alloc(11 * 1024 * 1024));
    const disappearing = path.join(recordsDir, "disappearing.json");
    await fs.writeFile(disappearing, "{}\n");
    let removed = false;
    const proxyFs = new Proxy(fs, {
      get(target, property, receiver) {
        if (property !== "stat") return Reflect.get(target, property, receiver);
        return async (file: Parameters<typeof fs.stat>[0], ...args: unknown[]) => {
          if (!removed && path.resolve(String(file)) === path.resolve(disappearing)) {
            removed = true;
            await fs.rm(disappearing);
          }
          return fs.stat(file, ...(args as []));
        };
      }
    }) as typeof fs;
    const restore = installDiskSpoolModulesForTest({ fs: proxyFs, path: path as DiskSpoolModules["path"] });
    t.after(restore);
    const errors: string[] = [];
    const batches: BlackboxLogBatch[] = [];
    const logger = diskLogger({
      spoolDir,
      onError: (error) => errors.push(String(error)),
      fetchImpl: (async (_url, init) => {
        batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
        return acceptedBatchResponse(init);
      }) as typeof fetch
    });

    await logger("survives-size-race");
    assert.equal(removed, true);
    assert.deepEqual(errors, []);
    assert.equal(batches.length, 1);
  });

  it("removes an atomic-write temporary file after rename failure and preserves the original error", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-rename-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const original = Object.assign(new Error("original rename failure"), { code: "EIO" });
    const proxyFs = new Proxy(fs, {
      get(target, property, receiver) {
        if (property === "rename") return async () => { throw original; };
        return Reflect.get(target, property, receiver);
      }
    }) as typeof fs;
    const restore = installDiskSpoolModulesForTest({ fs: proxyFs, path: path as DiskSpoolModules["path"] });
    t.after(restore);
    const errors: unknown[] = [];
    const logger = diskLogger({ spoolDir, onError: (error) => errors.push(error) });

    await logger("rename-fails");

    assert.equal(errors[0], original);
    const files = await fs.readdir(path.join(spoolDir, "records"));
    assert.deepEqual(files.filter((file) => file.endsWith(".tmp")), []);
  });

  it("never admits concurrent durable JSON beyond the ten MiB spool limit", async (t) => {
    const spoolDir = await fs.mkdtemp(path.join(tmpdir(), "blackbox-quota-test-"));
    t.after(async () => fs.rm(spoolDir, { recursive: true, force: true }));
    const recordsDir = path.join(spoolDir, "records");
    await fs.mkdir(recordsDir, { recursive: true });
    await fs.mkdir(path.join(spoolDir, "batches"), { recursive: true });
    const limit = 10 * 1024 * 1024;
    const prefix = '{"format":"filler"}';
    await fs.writeFile(path.join(recordsDir, "0000000000000-filler.json"), prefix + " ".repeat(limit - 90_000 - prefix.length));
    let releaseSink!: () => void;
    const sinkReleased = new Promise<void>((resolve) => { releaseSink = resolve; });
    let sinkStarted!: () => void;
    const firstSink = new Promise<void>((resolve) => { sinkStarted = resolve; });
    let requestCount = 0;
    const errors: string[] = [];
    const logger = diskLogger({
      spoolDir,
      onError: (error) => errors.push(String(error)),
      fetchImpl: (async (_url, init) => {
        requestCount += 1;
        if (requestCount === 1) {
          sinkStarted();
          await sinkReleased;
        }
        return acceptedBatchResponse(init);
      }) as typeof fetch
    });
    const writes = [logger("quota-0", { payload: "x".repeat(40_000) })];
    await firstSink;
    for (let index = 1; index < 20; index += 1) {
      writes.push(logger(`quota-${index}`, { payload: "x".repeat(40_000) }));
    }
    await waitFor(() => Promise.resolve(errors.some((error) => error.includes("spool_full"))));

    assert.ok(await durableJsonSize(spoolDir) <= limit);
    releaseSink();
    await Promise.all(writes);
    assert.ok(errors.some((error) => error.includes("spool_full")));
  });
});

function diskLogger(options: {
  spoolDir: string;
  dek?: string;
  fetchImpl?: typeof fetch;
  onError?: (error: unknown, event: string) => void;
}) {
  const dek = options.dek ?? generateProofLogEncryptionKey();
  const write = options.fetchImpl ?? (async (_url, init) => acceptedBatchResponse(init)) as typeof fetch;
  return createBlackboxRemoteLogger({
    getConfigValue: (name) => name === "BLACKBOX_LOG_CONFIG"
      ? JSON.stringify({
          sinkId: "sink-disk",
          jobId: "job-disk",
          writeUrl: "https://blackbox.test/v1/sinks/sink-disk/events",
          spoolDir: options.spoolDir,
          dek
        })
      : undefined,
    spoolMode: "disk",
    spoolDir: options.spoolDir,
    signer: {
      scheme: "Ed25519",
      publicKeyHex: "a".repeat(64),
      sign: () => "b".repeat(128)
    },
    fetchImpl: (async (url, init) => String(url).endsWith("/resume")
      ? resumeResponse("sink-disk", { nextSequence: 1, previousHash: null })
      : write(url, init)) as typeof fetch,
    onError: options.onError
  });
}

function acceptedBatchResponse(init: RequestInit | undefined, status = 201): Response {
  const batch = JSON.parse(String(init?.body)) as BlackboxLogBatch;
  return new Response(JSON.stringify({
    ok: true,
    chain: {
      nextSequence: batch.sequenceEnd + 1,
      previousHash: batch.batchId
    }
  }), { status });
}

function resumeResponse(
  sinkId: string,
  chain: { nextSequence: number; previousHash: string | null },
  status = 200
): Response {
  return new Response(JSON.stringify({ ok: true, sinkId, chain }), { status });
}

function chainHash(nibble: string): string {
  return `0x${nibble.repeat(64)}`;
}

async function durableJsonSize(spoolDir: string): Promise<number> {
  let total = 0;
  for (const subdir of ["records", "batches"]) {
    const dir = path.join(spoolDir, subdir);
    for (const file of await fs.readdir(dir).catch(() => [])) {
      if (!file.endsWith(".json")) continue;
      total += (await fs.stat(path.join(dir, file))).size;
    }
  }
  return total;
}

async function waitFor(predicate: () => Promise<boolean>, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for test condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
