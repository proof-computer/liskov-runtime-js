import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createAcurastRuntimeAdapter,
  createAcurastHttpPostFetch,
  getRuntimeEnvValue,
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
      headers: { "Content-Type": "application/json" }
    }]);
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
        "X-PublicKey": "public-key",
        "X-Signature": "signature",
        "X-Timestamp": "timestamp"
      }
    }]);
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
