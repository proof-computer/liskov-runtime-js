import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createAcurastRuntimeAdapter,
  createAcurastHttpPostFetch,
  getRuntimeEnvValue,
  resolveAcurastRuntimeIdentity,
  type AcurastRuntimeStd
} from "../src/index.js";

describe("runtime env lookup and Acurast adapter", () => {
  it("uses process env first, then _STD_.env, then global environment(name)", () => {
    const std: AcurastRuntimeStd = {
      env: {
        FROM_STD: "std",
        SHARED: "std-shared"
      }
    };
    const environment = (name: string) => name === "FROM_ENVIRONMENT" || name === "SHARED" ? `environment-${name}` : undefined;
    assert.equal(getRuntimeEnvValue("SHARED", { env: { SHARED: "process-shared" }, std, environment }), "process-shared");
    assert.equal(getRuntimeEnvValue("FROM_STD", { env: {}, std, environment }), "std");
    assert.equal(getRuntimeEnvValue("FROM_ENVIRONMENT", { env: {}, std, environment }), "environment-FROM_ENVIRONMENT");
  });

  it("resolves identity, signer, and decryptor from injected Acurast std", async () => {
    const signedPayloads: string[] = [];
    const std: AcurastRuntimeStd = {
      job: {
        getId: () => "job-1",
        getEncryptionKeys: () => ({ secp256r1Encryption: new Uint8Array([1, 2, 3]) })
      },
      device: {
        getAddress: () => "processor-1"
      },
      signers: {
        ed25519: {
          sign: (payloadHex) => {
            signedPayloads.push(payloadHex);
            return "0x" + "11".repeat(64);
          }
        },
        secp256r1: {
          decrypt: () => "0x" + Buffer.from("plaintext", "utf8").toString("hex")
        }
      }
    };
    const adapter = createAcurastRuntimeAdapter({ env: {}, std });
    assert.deepEqual(await adapter.resolveIdentity({ requireEncryptionKey: true }), {
      jobId: "job-1",
      processorId: "processor-1",
      responseEncryptionKey: "010203"
    });
    assert.equal(await adapter.sign(Buffer.from("message")), "0x" + "11".repeat(64));
    assert.deepEqual(signedPayloads, [Buffer.from("message").toString("hex")]);
    assert.equal(Buffer.from(await adapter.decryptGrantPayload({
      senderPublicKey: "00",
      saltHex: "00",
      ciphertextHex: "00"
    })).toString("utf8"), "plaintext");
  });

  it("primes lazy Acurast encryption keys before resolving Lockbox identity", async () => {
    let primed = false;
    const std: AcurastRuntimeStd = {
      job: {
        getId: () => "job-1",
        getEncryptionKeys: () => primed ? { p256: "0x" + "02".repeat(33) } : {} as Record<string, string>
      },
      device: {
        getAddress: () => "processor-1"
      },
      signers: {
        secp256r1: {
          encrypt: () => {
            primed = true;
            return "0x00";
          }
        }
      }
    };
    const adapter = createAcurastRuntimeAdapter({ env: {}, std });

    assert.deepEqual(await adapter.resolveIdentity({ requireEncryptionKey: true }), {
      jobId: "job-1",
      processorId: "processor-1",
      responseEncryptionKey: "02".repeat(33)
    });
  });

  it("resolves a secp256k1 response key when the processor exposes no p256 key", async () => {
    const encryptCalls: string[] = [];
    let k1Primed = false;
    const std: AcurastRuntimeStd = {
      job: {
        getId: () => "job-1",
        getEncryptionKeys: () => k1Primed ? { secp256k1: "0x" + "03".repeat(33) } : {} as Record<string, string>
      },
      device: {
        getAddress: () => "processor-1"
      },
      signers: {
        secp256k1: {
          encrypt: (publicKey) => {
            encryptCalls.push(publicKey);
            k1Primed = true;
            return "0x00";
          },
          decrypt: () => "0x00"
        }
      }
    };
    const adapter = createAcurastRuntimeAdapter({ env: {}, std });

    assert.deepEqual(await adapter.resolveIdentity({ requireEncryptionKey: true }), {
      jobId: "job-1",
      processorId: "processor-1",
      responseEncryptionKey: "03".repeat(33)
    });
    assert.equal(encryptCalls.length, 1);
    assert.match(encryptCalls[0], /^02/u);
    assert.equal(resolveAcurastRuntimeIdentity({ env: {}, std }, { requireEncryptionKey: true }).responseEncryptionKey, "03".repeat(33));
  });

  it("resolves the p256 key and never primes secp256k1 when both are exposed", async () => {
    const k1EncryptCalls: string[] = [];
    const std: AcurastRuntimeStd = {
      job: {
        getId: () => "job-1",
        getEncryptionKeys: () => ({ secp256k1: "03".repeat(33), p256: "02".repeat(33) })
      },
      device: {
        getAddress: () => "processor-1"
      },
      signers: {
        secp256r1: {
          encrypt: () => "0x00"
        },
        secp256k1: {
          encrypt: (publicKey) => {
            k1EncryptCalls.push(publicKey);
            return "0x00";
          }
        }
      }
    };
    const adapter = createAcurastRuntimeAdapter({ env: {}, std });

    assert.equal((await adapter.resolveIdentity({ requireEncryptionKey: true })).responseEncryptionKey, "02".repeat(33));
    assert.equal(resolveAcurastRuntimeIdentity({ env: {}, std }, { requireEncryptionKey: true }).responseEncryptionKey, "02".repeat(33));
    assert.deepEqual(k1EncryptCalls, []);
  });

  it("still requires a response key when neither a p256 nor a secp256k1 key is exposed", async () => {
    const std: AcurastRuntimeStd = {
      job: {
        getId: () => "job-1",
        getEncryptionKeys: () => ({ ed25519: "04".repeat(32) })
      },
      device: {
        getAddress: () => "processor-1"
      },
      signers: {
        secp256r1: { encrypt: () => "0x00" },
        secp256k1: { encrypt: () => "0x00" }
      }
    };
    const adapter = createAcurastRuntimeAdapter({ env: {}, std });

    await assert.rejects(
      () => adapter.resolveIdentity({ requireEncryptionKey: true }),
      /^Error: Acurast response encryption key is required for Lockbox bootstrap$/u
    );
  });

  it("decrypts each envelope through the signer of its curve", async () => {
    const calls: Array<{ curve: string; args: string[] }> = [];
    const signer = (curve: string, plaintext: string) => ({
      decrypt: (publicKey: string, salt: string, ciphertext: string) => {
        calls.push({ curve, args: [publicKey, salt, ciphertext] });
        return "0x" + Buffer.from(plaintext, "utf8").toString("hex");
      }
    });
    const adapter = createAcurastRuntimeAdapter({
      env: {},
      std: {
        signers: {
          secp256r1: signer("secp256r1", "p256-plaintext"),
          secp256k1: signer("secp256k1", "k1-plaintext")
        }
      }
    });

    const k1 = await adapter.decryptGrantPayload({
      curveName: "secp256k1",
      senderPublicKey: "0x02" + "aa".repeat(32),
      saltHex: "0x" + "bb".repeat(16),
      ciphertextHex: "0x" + "cc".repeat(40)
    });
    const p256 = await adapter.decryptGrantPayload({
      curveName: "secp256r1",
      senderPublicKey: "0x03" + "dd".repeat(32),
      saltHex: "0x" + "ee".repeat(16),
      ciphertextHex: "0x" + "ff".repeat(40)
    });

    assert.equal(Buffer.from(k1).toString("utf8"), "k1-plaintext");
    assert.equal(Buffer.from(p256).toString("utf8"), "p256-plaintext");
    assert.deepEqual(calls, [
      { curve: "secp256k1", args: ["0x02" + "aa".repeat(32), "0x" + "bb".repeat(16), "0x" + "cc".repeat(40)] },
      { curve: "secp256r1", args: ["0x03" + "dd".repeat(32), "0x" + "ee".repeat(16), "0x" + "ff".repeat(40)] }
    ]);
    await assert.rejects(() => adapter.decryptGrantPayload({
      curveName: "ed25519",
      senderPublicKey: "00",
      saltHex: "00",
      ciphertextHex: "00"
    }), /unsupported curve/u);
    await assert.rejects(() => createAcurastRuntimeAdapter({
      env: {},
      std: { signers: { secp256r1: signer("secp256r1", "p256-plaintext") } }
    }).decryptGrantPayload({
      curveName: "secp256k1",
      senderPublicKey: "00",
      saltHex: "00",
      ciphertextHex: "00"
    }), /secp256k1 decrypt/u);
  });

  it("adapts Acurast httpPOST to the fetch surface used by runtime bootstrap", async () => {
    const calls: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
    const fetchImpl = createAcurastHttpPostFetch({
      httpPOST(url, body, headers, onSuccess) {
        calls.push({ url, body, headers });
        onSuccess(JSON.stringify({ ok: true }), "certificate");
      }
    });
    assert.equal(typeof fetchImpl, "function");

    const response = await fetchImpl!("https://liskov.test/api/jobs/runtime-env", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request: true })
    });

    assert.equal(response.ok, true);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true });
    assert.deepEqual(calls, [{
      url: "https://liskov.test/api/jobs/runtime-env",
      body: JSON.stringify({ request: true }),
      headers: {
        "Content-Type": "application/json",
        "X-Liskov-Acurast-Response-Tunnel": "v1"
      }
    }]);
  });

  it("serializes object-shaped Acurast httpPOST success responses", async () => {
    const fetchImpl = createAcurastHttpPostFetch({
      httpPOST(_url, _body, _headers, onSuccess) {
        onSuccess({
          batch: { batchId: "batch-1" },
          chain: { nextSequence: 2, previousHash: "0x" + "ab".repeat(32) }
        }, "certificate");
      }
    });

    const response = await fetchImpl!("https://logging.test/v1/sinks/sink-1/events", {
      method: "POST",
      body: "{}"
    });

    assert.equal(response.ok, true);
    assert.deepEqual(await response.json(), {
      batch: { batchId: "batch-1" },
      chain: { nextSequence: 2, previousHash: "0x" + "ab".repeat(32) }
    });
  });

  it("canonicalizes fetch header casing before calling Acurast httpPOST", async () => {
    const calls: Array<{ headers: Record<string, string> }> = [];
    const fetchImpl = createAcurastHttpPostFetch({
      httpPOST(_url, _body, headers, onSuccess) {
        calls.push({ headers });
        onSuccess(JSON.stringify({ ok: true }), "certificate");
      }
    });

    const response = await fetchImpl!("https://liskov.test/api/jobs/runtime-diagnostics", {
      method: "POST",
      headers: new Headers({
        accept: "application/json",
        authorization: "Bearer token",
        "content-type": "application/json",
        "x-publickey": "public-key",
        "x-signature": "signature",
        "x-timestamp": "timestamp"
      }),
      body: "{}"
    });

    assert.equal(response.ok, true);
    assert.deepEqual(calls, [{
      headers: {
        Accept: "application/json",
        Authorization: "Bearer token",
        "Content-Type": "application/json",
        "X-Liskov-Acurast-Response-Tunnel": "v1",
        "X-PublicKey": "public-key",
        "X-Signature": "signature",
        "X-Timestamp": "timestamp"
      }
    }]);
  });

  it("recovers the real HTTP status and JSON body from an Acurast httpPOST error", async () => {
    const fetchImpl = createAcurastHttpPostFetch({
      httpPOST(_url, _body, _headers, _onSuccess, onError) {
        onError(
          'HTTP Post failed with {"ok":false,"error":"runtime_bootstrap_job_not_found","reason":"no match"} (404)'
        );
      }
    });

    const response = await fetchImpl!("https://liskov.test/api/jobs/runtime-bootstrap", {
      method: "POST",
      body: "{}"
    });

    assert.equal(response.ok, false);
    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), {
      ok: false,
      error: "runtime_bootstrap_job_not_found",
      reason: "no match"
    });
  });

  it("unwraps an opted-in success body carried through the Acurast error callback", async () => {
    const calls: Array<{ headers: Record<string, string> }> = [];
    const fetchImpl = createAcurastHttpPostFetch({
      httpPOST(_url, _body, headers, _onSuccess, onError) {
        calls.push({ headers });
        onError(
          'HTTP Post failed with {"domain":"proof.liskov.acurast-response-tunnel.v1","status":201,"body":"{\\"ok\\":true,\\"sinkId\\":\\"sink-1\\"}"} (418)'
        );
      }
    });

    const response = await fetchImpl!("https://logging.test/v1/sink-factories/factory-1/job-sinks", {
      method: "POST",
      body: "{}"
    });

    assert.equal(response.ok, true);
    assert.equal(response.status, 201);
    assert.deepEqual(await response.json(), { ok: true, sinkId: "sink-1" });
    assert.deepEqual(calls, [{
      headers: { "X-Liskov-Acurast-Response-Tunnel": "v1" }
    }]);
  });

  it("falls back to 599 when an Acurast httpPOST error has no recoverable status", async () => {
    const fetchImpl = createAcurastHttpPostFetch({
      httpPOST(_url, _body, _headers, _onSuccess, onError) {
        onError("network unreachable");
      }
    });

    const response = await fetchImpl!("https://liskov.test/api/jobs/runtime-bootstrap", {
      method: "POST",
      body: "{}"
    });

    assert.equal(response.status, 599);
    assert.equal(await response.text(), "network unreachable");
  });

  it("returns undefined when Acurast httpPOST is unavailable", () => {
    assert.equal(createAcurastHttpPostFetch(), undefined);
  });

  it("ignores legacy JOB_ID and serializes object-shaped Acurast job ids", async () => {
    const runtimeJobId = [{ acurast: "5GQijf2Pw2jiGhhqXenc7VoYFqmE5RVRk5A3ZKaRviF6HFgd" }, 66121];
    const std: AcurastRuntimeStd = {
      job: {
        getId: () => runtimeJobId,
        getEncryptionKeys: () => JSON.stringify({ p256: [1, 2, 3] })
      },
      device: {
        getAddress: () => ({ processor: "processor-1" })
      }
    };
    const adapter = createAcurastRuntimeAdapter({
      env: {
        JOB_ID: "[object Object]"
      },
      std
    });

    assert.deepEqual(await adapter.resolveIdentity({ requireEncryptionKey: true }), {
      jobId: JSON.stringify(runtimeJobId),
      processorId: JSON.stringify({ processor: "processor-1" }),
      responseEncryptionKey: "010203"
    });
  });

  it("fails closed when runtime signer, decryptor, or encryption key is missing", async () => {
    const adapter = createAcurastRuntimeAdapter({
      env: {
        ACURAST_JOB_ID: "job-1",
        ACURAST_PROCESSOR_ID: "processor-1"
      },
      std: {}
    });
    await assert.rejects(() => adapter.sign(Buffer.from("message")), /Ed25519 signer/u);
    await assert.rejects(() => adapter.decryptGrantPayload({
      senderPublicKey: "00",
      saltHex: "00",
      ciphertextHex: "00"
    }), /secp256r1 decrypt/u);
    await assert.rejects(() => adapter.resolveIdentity({ requireEncryptionKey: true }), /response encryption key/u);
  });
});
