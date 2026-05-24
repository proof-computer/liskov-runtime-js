import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createAcurastRuntimeAdapter,
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
