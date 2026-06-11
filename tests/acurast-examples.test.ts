import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import {
  bootstrapSlipwayRuntime,
  decryptProofLogRecord,
  generateProofLogEncryptionKey,
  type BlackboxLogBatch,
  type RuntimeIdentityProvider
} from "../src/index.js";
import { runAcurastEnvVarsExample } from "../examples/acurast-env-vars/src/index.js";
import { runAcurastFetchExample } from "../examples/acurast-fetch/src/index.js";
import { runAcurastWebserverExample } from "../../../public_repos/slipway-switchboard-js/examples/acurast-webserver/src/index.js";
import { attachSlipwaySwitchboard } from "../../../public_repos/slipway-switchboard-js/src/index.js";

const JOB_SIGNER_PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000009";
const REGISTRY_ADDRESS = "0x65d6B76BeC50F46D198fFa3598E381a298025Da0";

describe("Slipway-backed Acurast examples", () => {
  it("runs the env-vars example through runtime-env, redaction, allowlisting, and Slipway logging", async () => {
    const secretValue = "super-secret-env-value";
    const factoryToken = "bbx_sf_env_secret";
    const dek = generateProofLogEncryptionKey();
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: slipwayBootstrap(),
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken,
        baseUrl: "https://logging.slipway.proof.computer",
        dek
      })
    };
    const output: string[] = [];
    const allowed: string[][] = [];
    const batches: BlackboxLogBatch[] = [];
    const webhookBodies: Array<Record<string, unknown>> = [];
    const fetchImpl = exampleFetch({
      runtimeEnvValues: {
        WEBHOOK_URL: "https://webhook.example.test/env-vars",
        MY_SECRET_ENV_VAR: secretValue
      },
      batches,
      webhookBodies
    });

    const result = await runAcurastEnvVarsExample({
      bootstrapSlipwayRuntime,
      runtimeOptions: {
        env,
        std: fakeStd(allowed),
        identityProvider: fakeIdentityProvider(),
        logging: { mode: "background", spoolMode: "memory" },
        nowMs: () => 1_000
      },
      fetchImpl,
      nowMs: () => 2_000,
      stdout: (line) => output.push(line)
    });

    const expectedDigest = `sha256:${createHash("sha256").update(secretValue).digest("hex")}`;
    assert.equal(result.webhookStatus, 202);
    assert.deepEqual(result.env, {
      name: "MY_SECRET_ENV_VAR",
      present: true,
      digest: expectedDigest
    });
    assert.equal(webhookBodies.length, 1);
    assert.equal((webhookBodies[0]?.env as { digest?: string } | undefined)?.digest, expectedDigest);
    assert.equal(JSON.stringify(output).includes(secretValue), false);
    assert.equal(JSON.stringify(webhookBodies).includes(secretValue), false);
    assert.equal(JSON.stringify(output).includes(factoryToken), false);
    assert.equal(allowed.some((hostnames) => hostnames.includes("webhook.example.test")), true);
    assert.equal(decryptedEvents(batches, dek).includes("example.env-vars.posted"), true);
  });

  it("runs the fetch example with fake external hosts and runtime log forwarding", async () => {
    const factoryToken = "bbx_sf_fetch_secret";
    const dek = generateProofLogEncryptionKey();
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: slipwayBootstrap(),
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken,
        baseUrl: "https://logging.slipway.proof.computer",
        dek
      })
    };
    const output: string[] = [];
    const allowed: string[][] = [];
    const batches: BlackboxLogBatch[] = [];
    const webhookBodies: Array<Record<string, unknown>> = [];
    const fetchImpl = exampleFetch({
      runtimeEnvValues: {
        WEBHOOK_URL: "https://webhook.example.test/fetch",
        PRICE_BASE_URL: "https://prices.example.test",
        PRICE_SYMBOL: "ETH",
        PRICE_TARGET_CURRENCY: "USD"
      },
      batches,
      webhookBodies
    });

    const result = await runAcurastFetchExample({
      bootstrapSlipwayRuntime,
      runtimeOptions: {
        env,
        std: fakeStd(allowed),
        identityProvider: fakeIdentityProvider(),
        logging: { mode: "background", spoolMode: "memory" },
        nowMs: () => 1_000
      },
      fetchImpl,
      nowMs: () => 2_000,
      stdout: (line) => output.push(line)
    });

    assert.equal(result.webhookStatus, 202);
    assert.equal(result.symbol, "ETH");
    assert.equal(result.targetCurrency, "USD");
    assert.equal(result.price, 3210.5);
    assert.equal(webhookBodies.length, 1);
    assert.equal(((webhookBodies[0]?.price as Record<string, unknown> | undefined)?.value), 3210.5);
    assert.equal(allowed.some((hostnames) => hostnames.includes("prices.example.test")), true);
    assert.equal(allowed.some((hostnames) => hostnames.includes("webhook.example.test")), true);
    assert.equal(JSON.stringify(output).includes(factoryToken), false);
    assert.equal(decryptedEvents(batches, dek).includes("example.fetch.posted"), true);
  });

  it("runs the webserver example with real Slipway runtime, adapter prepare, and ready-after-listen ordering", async () => {
    const factoryToken = "bbx_sf_webserver_secret";
    const dek = generateProofLogEncryptionKey();
    const env: Record<string, string | undefined> = {
      PROOF_SLIPWAY_BOOTSTRAP: slipwayBootstrap(),
      BLACKBOX_LOG_CONFIG: JSON.stringify({
        factoryToken,
        baseUrl: "https://logging.slipway.proof.computer",
        dek
      })
    };
    const output: string[] = [];
    const allowed: string[][] = [];
    const batches: BlackboxLogBatch[] = [];
    const relayCalls: Array<{ label: string; body?: Record<string, unknown> }> = [];
    const fetchImpl = exampleFetch({
      runtimeEnvValues: {
        PORT: "0",
        HOST: "127.0.0.1",
        PROOF_INGRESS_RELAY_URL: "https://relay.example.test",
        PROOF_INGRESS_INTENT_ID: "di_example",
        PROOF_INGRESS_INTENT_TOKEN: "intent-token",
        JOB_SIGNER_PRIVATE_KEY,
        SWITCHBOARD_INTENT_MAX_ATTEMPTS: "1",
        SWITCHBOARD_CERTIFICATE_MODE: "manual"
      },
      batches,
      relayCalls
    });

    const handle = await runAcurastWebserverExample({
      bootstrapSlipwayRuntime,
      attachSlipwaySwitchboard,
      runtimeOptions: {
        env,
        std: fakeStd(allowed),
        identityProvider: fakeIdentityProvider(),
        logging: { mode: "background", spoolMode: "memory" },
        nowMs: () => 1_000
      },
      switchboardOptions: {
        baseEnv: {}
      },
      fetchImpl,
      host: "127.0.0.1",
      stdout: (line) => output.push(line)
    });

    try {
      const response = await fetch(`http://127.0.0.1:${handle.port}/`);
      assert.equal(response.status, 200);
      assert.match(await response.text(), /Hello from Acurast via Slipway and Switchboard/u);

      const labels = relayCalls.map((call) => call.label);
      assert.ok(labels.indexOf("relay:runtime-config") > labels.indexOf("relay:claim"));
      assert.ok(labels.indexOf("relay:ingress-registration") > labels.indexOf("relay:runtime-config"));
      assert.ok(labels.indexOf("relay:upstream-admission-request") > labels.indexOf("relay:ingress-registration"));
      assert.ok(labels.indexOf("relay:health:ready") > labels.indexOf("relay:upstream-admission-request"));
      const admission = relayCalls.find((call) => call.label === "relay:upstream-admission-request")?.body;
      assert.equal((admission?.request as Record<string, unknown> | undefined)?.upstreamPort, handle.port);
      const ready = relayCalls.find((call) => call.label === "relay:health:ready")?.body;
      assert.equal((ready?.details as Record<string, unknown> | undefined)?.port, handle.port);
      assert.equal(allowed.some((hostnames) => hostnames.includes("relay.example.test")), true);
      const events = decryptedEvents(batches, dek);
      assert.equal(events.includes("switchboard.process-start"), true);
      assert.equal(events.includes("example.webserver.listening"), true);
      assert.equal(JSON.stringify(output).includes(factoryToken), false);
    } finally {
      await handle.stop();
    }
  });
});

function exampleFetch(input: {
  runtimeEnvValues: Record<string, string>;
  batches: BlackboxLogBatch[];
  webhookBodies?: Array<Record<string, unknown>>;
  relayCalls?: Array<{ label: string; body?: Record<string, unknown> }>;
}): typeof fetch {
  return (async (url, init) => {
    const parsed = new URL(String(url));
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined;
    if (parsed.hostname === "slipway.test" && parsed.pathname === "/api/jobs/runtime-env") {
      return jsonResponse(runtimeEnvResponse(input.runtimeEnvValues));
    }
    if (parsed.hostname === "logging.slipway.proof.computer" && parsed.pathname.endsWith("/job-sinks")) {
      return jsonResponse({ sinkId: "sink-example" });
    }
    if (parsed.hostname === "logging.slipway.proof.computer" && parsed.pathname.endsWith("/events")) {
      input.batches.push(JSON.parse(String(init?.body)) as BlackboxLogBatch);
      return jsonResponse({ ok: true });
    }
    if (parsed.hostname === "webhook.example.test") {
      input.webhookBodies?.push(body ?? {});
      return jsonResponse({ ok: true }, 202);
    }
    if (parsed.hostname === "prices.example.test") {
      return jsonResponse({ USD: 3210.5 });
    }
    if (parsed.hostname === "relay.example.test") {
      return relayResponse(parsed, body, input.relayCalls ?? []);
    }
    throw new Error(`Unexpected fetch ${parsed.toString()}`);
  }) as typeof fetch;
}

function relayResponse(
  parsed: URL,
  body: Record<string, unknown> | undefined,
  calls: Array<{ label: string; body?: Record<string, unknown> }>
): Response {
  if (parsed.pathname.endsWith("/claim")) {
    calls.push({ label: "relay:claim", body });
    return jsonResponse({ ok: true });
  }
  if (parsed.pathname.endsWith("/runtime-config")) {
    calls.push({ label: "relay:runtime-config", body });
    return jsonResponse({
      ok: true,
      config: {
        relayUrl: "https://relay.example.test",
        chainId: "420420419",
        registryAddress: REGISTRY_ADDRESS,
        sessionId: hex32("01"),
        jobId: hex32("02"),
        operatorId: hex32("03"),
        processorId: hex32("04"),
        gatewayId: "gateway-example",
        gatewayUpstreamAdmissionMode: "relay-pull",
        endpointHostname: "demo.example.test",
        certificateMode: "manual"
      }
    });
  }
  if (parsed.pathname.endsWith("/health")) {
    const state = typeof body?.state === "string" ? body.state : "unknown";
    calls.push({ label: `relay:health:${state}`, body });
    return jsonResponse({ ok: true });
  }
  if (parsed.pathname === "/v1/ingress-registrations") {
    calls.push({ label: "relay:ingress-registration", body });
    return jsonResponse({ ok: true });
  }
  if (parsed.pathname.endsWith("/upstream-admission-requests")) {
    calls.push({ label: "relay:upstream-admission-request", body });
    return jsonResponse({ ok: true, candidateUpstreamIps: body?.candidateUpstreamIps });
  }
  throw new Error(`Unexpected relay fetch ${parsed.toString()}`);
}

function decryptedEvents(batches: BlackboxLogBatch[], dek: string): string[] {
  return batches.flatMap((batch) =>
    batch.encrypted.map((record) => String(decryptProofLogRecord<Record<string, unknown>>(dek, record).event))
  );
}

function slipwayBootstrap(): string {
  return JSON.stringify({
    v: 1,
    u: "https://slipway.test",
    a: "acurast-example",
    p: "1".repeat(64),
    d: "42"
  });
}

function runtimeEnvResponse(values: Record<string, string>): Record<string, unknown> {
  return {
    ok: true,
    domain: "proof.slipway.runtime-env-response.v1",
    requestId: "runtime-env-request-example",
    applicationId: "acurast-example",
    policyDigest: "1".repeat(64),
    jobId: "job-example",
    deploymentId: "42",
    processorId: "processor-example",
    revision: "examples-revision-1",
    issuedAtMs: 1_000,
    expiresAtMs: 61_000,
    refreshAfterMs: 30_000,
    values
  };
}

function fakeStd(allowed: string[][]) {
  return {
    job: {
      getId: () => "42",
      getPublicKeys: () => ({ ed25519: "a".repeat(64) })
    },
    signers: {
      ed25519: {
        sign: () => "b".repeat(128)
      }
    },
    net: {
      addAllowedHostnames: (hostnames: string[]) => {
        allowed.push(hostnames);
      }
    }
  };
}

function fakeIdentityProvider(): RuntimeIdentityProvider {
  return {
    async resolveIdentity() {
      return { jobId: "job-example", processorId: "processor-example", responseEncryptionKey: "ab".repeat(33) };
    },
    async sign() {
      return "0x" + "11".repeat(64);
    },
    async decryptGrantPayload() {
      return Buffer.from("{}", "utf8");
    }
  };
}

function hex32(byte: string): string {
  return `0x${byte.repeat(32)}`;
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" }
  });
}
