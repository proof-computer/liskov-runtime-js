import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
  buildRuntimeContextRequest,
  LISKOV_RUNTIME_CONTEXT_REQUEST_DOMAIN,
  LISKOV_RUNTIME_CONTEXT_RESPONSE_DOMAIN,
  LiskovRuntimeContextRefusedError,
  parseLiskovRuntimeBootstrapResponse,
  parseLiskovRuntimeContext,
  refreshLiskovRuntimeContext,
  runtimeContextRequestMessage,
  type RuntimeIdentityProvider
} from "../src/index.js";

const bootstrap = JSON.parse(readFileSync(new URL("./fixtures/runtime-bootstrap-context.json", import.meta.url), "utf8"));
const fixture = bootstrap.context;

function provider(messages: string[] = []): RuntimeIdentityProvider {
  return {
    async resolveIdentity() { return { jobId: "job-1", processorId: "processor-1" }; },
    async sign(message) { messages.push(Buffer.from(message).toString("utf8")); return "0x" + "11".repeat(64); },
    async decryptGrantPayload() { throw new Error("Not used"); }
  };
}

function response(request: Record<string, unknown>) {
  return { ok: true, domain: LISKOV_RUNTIME_CONTEXT_RESPONSE_DOMAIN, requestNonce: request.nonce,
    jobId: request.jobId, processorId: request.processorId, applicationUid: fixture.application.uid, context: fixture };
}

const input = { coreUrl: "https://core.test/base", jobId: "job-1", processorId: "processor-1",
  nowMs: () => 1000, randomBytes: (size: number) => new Uint8Array(size).fill(7) };

describe("runtime context wire parser", () => {
  it("pins the owner schema bytes and validates the bootstrap fixture structurally", () => {
    // Verbatim at liskov-rs mpe1 merge d31310267a513f6526a5682fdab19dc750fc7bce.
    // No schema-validator dependency: check the schema's refs, types, enums,
    // required fields and additionalProperties used by this contract below.
    const bytes = readFileSync(new URL("./fixtures/runtime-context.schema.json", import.meta.url));
    assert.equal(createHash("sha256").update(bytes).digest("hex"),
      "006df5281972874dab8a6ebe34517d235af3c2e66baaecc4b7ba79b4a309f97a");
    const schema = JSON.parse(bytes.toString("utf8"));
    checkSchema(fixture, schema, schema);
    checkSchema(parseLiskovRuntimeBootstrapResponse(bootstrap).context, schema, schema);
    assert.throws(() => checkSchema({ ...fixture, application: { uid: 0 } }, schema, schema));
    assert.deepEqual(parseLiskovRuntimeContext(fixture), fixture);
  });

  it("preserves null, zero and empty strings, drops unknown fields and freezes the snapshot", () => {
    const value = structuredClone(fixture);
    value.future = "ignored";
    value.application.future = "ignored";
    value.application.displayName = "";
    value.serverTimeMs = 0;
    value.job.scheduleEndsAtMs = 0;
    value.network.observedAtMs = 0;
    value.network.geolocation.asOfMs = 0;
    const parsed = parseLiskovRuntimeContext(value);
    assert.equal(parsed.application.displayName, "");
    assert.equal(parsed.serverTimeMs, 0);
    assert.equal(parsed.job.scheduleEndsAtMs, 0);
    assert.equal(parsed.network.observedAtMs, 0);
    assert.equal(parsed.network.geolocation.asOfMs, 0);
    assert.equal(parsed.artifact.cid, null);
    assert.equal("future" in parsed, false);
    assert.equal("future" in parsed.application, false);
    assert.ok(Object.isFrozen(parsed.network.geolocation));
    value.application.uid = "changed";
    assert.equal(parsed.application.uid, fixture.application.uid);
  });

  it("requires every nullable field and rejects wrong types, schema, status and accuracy", () => {
    function missingFields(value: Record<string, unknown>, path: string[] = []): void {
      for (const [key, child] of Object.entries(value)) {
        const copy = structuredClone(fixture);
        let parent = copy;
        for (const part of path) parent = parent[part];
        delete parent[key];
        assert.throws(() => parseLiskovRuntimeContext(copy), `missing ${[...path, key].join(".")}`);
        if (child !== null && typeof child === "object") missingFields(child as Record<string, unknown>, [...path, key]);
      }
    }
    missingFields(fixture);
    for (const value of [null, [], { ...fixture, schema: "future" }, { ...fixture, serverTimeMs: 1.5 },
      { ...fixture, serverTimeMs: Number.MAX_SAFE_INTEGER + 1 },
      { ...fixture, capabilities: { ...fixture.capabilities, secrets: 0 } },
      { ...fixture, network: { ...fixture.network, geolocation: { ...fixture.network.geolocation, status: "unknown" } } },
      { ...fixture, network: { ...fixture.network, geolocation: { ...fixture.network.geolocation, accuracy: "gps" } } }]) {
      assert.throws(() => parseLiskovRuntimeContext(value));
    }
    for (const status of ["ready", "pending", "stale", "disabled", "unavailable", "not_observed"]) {
      assert.equal(parseLiskovRuntimeContext({ ...fixture,
        network: { ...fixture.network, geolocation: { ...fixture.network.geolocation, status } } }).network.geolocation.status, status);
    }
  });
});

describe("explicit runtime context refresh", () => {
  it("signs exact sorted-key JSON and posts the exact body once with a 30-second TTL", async () => {
    const messages: string[] = [];
    const unsigned = buildRuntimeContextRequest({ jobId: "job-1", processorId: "processor-1", nonce: "07".repeat(16),
      issuedAtMs: 1000, expiresAtMs: 31000 });
    const expected = '{"domain":"proof.liskov.runtime-context-request.v1","expiresAtMs":31000,"issuedAtMs":1000,"jobId":"job-1","nonce":"07070707070707070707070707070707","processorId":"processor-1"}';
    assert.equal(Buffer.from(runtimeContextRequestMessage(unsigned)).toString("utf8"), expected);
    let calls = 0;
    const parsed = await refreshLiskovRuntimeContext({ ...input, identityProvider: provider(messages),
      fetchImpl: (async (url, init) => {
        calls++;
        assert.equal(String(url), "https://core.test/api/jobs/runtime-context");
        assert.equal(init?.method, "POST");
        assert.equal(new Headers(init?.headers).get("content-type"), "application/json");
        const body = JSON.parse(String(init?.body));
        assert.deepEqual(body, { ...unsigned, signature: "0x" + "11".repeat(64) });
        return Response.json(response(body));
      }) as typeof fetch });
    assert.deepEqual(messages, [expected]);
    assert.deepEqual(parsed, fixture);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(calls, 1);
  });

  for (const field of ["requestNonce", "jobId", "processorId", "domain", "applicationUid", "ok"]) {
    it(`refuses a mismatched ${field}`, async () => {
      await assert.rejects(refreshLiskovRuntimeContext({ ...input, identityProvider: provider(),
        fetchImpl: (async (_url, init) => Response.json({ ...response(JSON.parse(String(init?.body))),
          [field]: field === "ok" ? false : "mismatch" })) as typeof fetch }), /binding mismatch/u);
    });
  }

  it("refuses mismatched embedded identities and the bootstrap's application UID", async () => {
    for (const context of [
      { ...fixture, job: { ...fixture.job, id: "other-job" } },
      { ...fixture, processor: { id: "other-processor" } },
      { ...fixture, application: { ...fixture.application, uid: "other-app" } }
    ]) {
      await assert.rejects(refreshLiskovRuntimeContext({ ...input, identityProvider: provider(),
        fetchImpl: (async (_url, init) => Response.json({ ...response(JSON.parse(String(init?.body))), context })) as typeof fetch }),
      /binding mismatch/u);
    }
    await assert.rejects(refreshLiskovRuntimeContext({ ...input, identityProvider: provider(), applicationUid: "other-app",
      fetchImpl: (async (_url, init) => Response.json(response(JSON.parse(String(init?.body))))) as typeof fetch }), /binding mismatch/u);
  });

  for (const [status, code, retryable] of [
    [400, "runtime_context_expiry_invalid", false], [403, "runtime_context_request_stale", false],
    [403, "runtime_context_signature_invalid", false], [409, "runtime_context_nonce_replayed", false],
    [429, "runtime_context_rate_limited", true], [503, "runtime_context_store_unavailable", true]
  ] as const) {
    it(`surfaces ${status} ${code} without retrying`, async () => {
      let calls = 0;
      await assert.rejects(refreshLiskovRuntimeContext({ ...input, identityProvider: provider(),
        fetchImpl: (async () => { calls++; return Response.json({ ok: false, error: code }, { status }); }) as typeof fetch }),
      (error: unknown) => {
        assert.ok(error instanceof LiskovRuntimeContextRefusedError);
        assert.equal(error.code, code);
        assert.equal(error.status, status);
        assert.equal(error.retryable, retryable);
        return true;
      });
      assert.equal(calls, 1);
    });
  }

  it("uses fresh nonces on two calls and honors an explicit TTL", async () => {
    const nonces: string[] = [];
    let byte = 0;
    const options = { ...input, identityProvider: provider(), ttlMs: 5000,
      randomBytes: (size: number) => new Uint8Array(size).fill(++byte),
      fetchImpl: (async (_url: unknown, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body));
        assert.equal(body.domain, LISKOV_RUNTIME_CONTEXT_REQUEST_DOMAIN);
        assert.equal(body.expiresAtMs, 6000);
        nonces.push(body.nonce);
        return Response.json(response(body));
      }) as typeof fetch };
    await refreshLiskovRuntimeContext(options);
    await refreshLiskovRuntimeContext(options);
    assert.equal(new Set(nonces).size, 2);
  });

  it("rejects unsafe transport and invalid request windows before signing or sending", async () => {
    const messages: string[] = [];
    let calls = 0;
    const options = { ...input, identityProvider: provider(messages),
      fetchImpl: (async () => { calls++; throw new Error("Unexpected call"); }) as typeof fetch };
    await assert.rejects(refreshLiskovRuntimeContext({ ...options, coreUrl: "http://core.test" }), /HTTPS/u);
    for (const ttlMs of [0, -1, 60001, 0.5, Infinity]) {
      await assert.rejects(refreshLiskovRuntimeContext({ ...options, ttlMs }));
    }
    assert.equal(calls, 0);
    assert.equal(messages.length, 0);
  });

  it("omits malformed response contents from errors", async () => {
    for (const status of [200, 503]) {
      await assert.rejects(refreshLiskovRuntimeContext({ ...input, identityProvider: provider(),
        fetchImpl: (async () => new Response('invalid ' + fixture.network.observedWanIp, { status })) as typeof fetch }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message.includes(fixture.network.observedWanIp), false);
        return true;
      });
    }
  });
});

// A minimal structural validator for the features the copied owner schema uses.
function checkSchema(value: unknown, schema: any, root: any): void {
  if (schema.$ref) {
    assert.match(schema.$ref, /^#\/\$defs\//u);
    return checkSchema(value, root.$defs[schema.$ref.slice("#/$defs/".length)], root);
  }
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  const matches = types.some((type: string) => type === "null" ? value === null :
    type === "integer" ? Number.isSafeInteger(value) :
    type === "object" ? value !== null && typeof value === "object" && !Array.isArray(value) : typeof value === type);
  assert.ok(matches, `Expected ${types.join(" | ")}`);
  if (schema.enum) assert.ok(schema.enum.includes(value));
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    for (const key of schema.required ?? []) assert.ok(Object.hasOwn(record, key), `Missing ${key}`);
    for (const [key, child] of Object.entries(record)) {
      if (schema.additionalProperties === false) assert.ok(Object.hasOwn(schema.properties, key), `Unexpected ${key}`);
      if (schema.properties[key]) checkSchema(child, schema.properties[key], root);
    }
  }
}
