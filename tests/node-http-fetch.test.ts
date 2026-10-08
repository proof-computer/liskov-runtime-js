import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import {
  createAcurastRuntimeFetch,
  createNodeHttpFetch,
  defaultRuntimeFetch,
  isAcurastIosRuntime,
  type AcurastHttpPost
} from "../src/index.js";

let server: Server;
let base = "";
const seen: { method?: string; url?: string; headers: Record<string, unknown>; body: string }[] = [];

before(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      if (req.url === "/echo") {
        res.writeHead(201, { "content-type": "application/json", "x-echo": "yes" });
        res.end(JSON.stringify({ method: req.method, body: Buffer.concat(chunks).toString("utf8") }));
      } else if (req.url === "/bytes") {
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from([1, 2, 3, 4]));
      } else if (req.url === "/empty") {
        res.writeHead(204);
        res.end();
      } else if (req.url === "/redirect") {
        res.writeHead(302, { location: "/echo" });
        res.end();
      } else if (req.url === "/slow") {
        setTimeout(() => { res.writeHead(200); res.end("late"); }, 2_000);
      } else {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("missing");
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("Node http/https fetch adapter", () => {
  const nodeFetch = createNodeHttpFetch();

  it("posts a string body and returns the real status, headers and text", async () => {
    const response = await nodeFetch(`${base}/echo`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: 1 })
    });
    assert.equal(response.status, 201);
    assert.equal(response.ok, true);
    assert.equal(response.headers.get("x-echo"), "yes");
    assert.deepEqual(await response.json(), { method: "POST", body: "{\"a\":1}" });
    const request = seen.at(-1)!;
    assert.equal(request.headers["content-length"], String(Buffer.byteLength("{\"a\":1}")));
    assert.equal(request.headers["x-liskov-acurast-response-tunnel"], undefined);
  });

  it("reads a GET body as bytes", async () => {
    const response = await nodeFetch(new URL(`${base}/bytes`));
    assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], [1, 2, 3, 4]);
  });

  it("sends Uint8Array and URLSearchParams bodies", async () => {
    await nodeFetch(`${base}/echo`, { method: "POST", body: new Uint8Array([104, 105]) });
    assert.equal(seen.at(-1)!.body, "hi");
    await nodeFetch(`${base}/echo`, { method: "POST", body: new URLSearchParams({ q: "1" }) });
    assert.equal(seen.at(-1)!.body, "q=1");
  });

  it("resolves an error status instead of rejecting", async () => {
    const response = await nodeFetch(`${base}/nowhere`);
    assert.equal(response.status, 404);
    assert.equal(await response.text(), "missing");
  });

  it("gives a 204 a null body", async () => {
    const response = await nodeFetch(`${base}/empty`);
    assert.equal(response.status, 204);
    assert.equal(response.body, null);
  });

  it("returns a redirect unfollowed", async () => {
    const response = await nodeFetch(`${base}/redirect`);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "/echo");
  });

  it("rejects with an AbortError when the signal aborts", async () => {
    const controller = new AbortController();
    const pending = nodeFetch(`${base}/slow`, { signal: controller.signal });
    setTimeout(() => controller.abort(), 50);
    await assert.rejects(pending, (error: Error) => error.name === "AbortError");
    await assert.rejects(nodeFetch(`${base}/echo`, { signal: AbortSignal.abort() }), (error: Error) => error.name === "AbortError");
  });

  it("refuses a non-HTTP URL and an unsupported body", async () => {
    await assert.rejects(nodeFetch("ftp://example.invalid/x"), /does not support ftp:/);
    await assert.rejects(nodeFetch(`${base}/echo`, { method: "POST", body: new Blob(["x"]) }), /only supports/);
  });
});

describe("runtime transport selection", () => {
  const httpPOST: AcurastHttpPost = (_url, _body, _headers, onSuccess) => onSuccess("ok", "");

  it("detects the iOS processor by platform", () => {
    assert.equal(isAcurastIosRuntime("ios"), true);
    assert.equal(isAcurastIosRuntime("android"), false);
    assert.equal(isAcurastIosRuntime("linux"), false);
  });

  it("uses Node http on iOS, never httpPOST", async () => {
    let httpPostCalls = 0;
    const counting: AcurastHttpPost = (...args) => { httpPostCalls++; httpPOST(...args); };
    const selected = createAcurastRuntimeFetch({ platform: "ios", httpPOST: counting });
    assert.equal(typeof selected, "function");
    const response = await selected!(`${base}/echo`, { method: "POST", body: "x" });
    assert.equal(response.status, 201);
    assert.equal(httpPostCalls, 0);
  });

  it("keeps the httpPOST adapter everywhere else", async () => {
    let httpPostCalls = 0;
    const counting: AcurastHttpPost = (...args) => { httpPostCalls++; httpPOST(...args); };
    const selected = createAcurastRuntimeFetch({ platform: "android", httpPOST: counting });
    await selected!(`${base}/echo`, { method: "POST", body: "x" });
    assert.equal(httpPostCalls, 1);
  });

  it("falls back to global fetch off iOS when httpPOST is absent", () => {
    const previous = (globalThis as { httpPOST?: unknown }).httpPOST;
    delete (globalThis as { httpPOST?: unknown }).httpPOST;
    try {
      assert.equal(createAcurastRuntimeFetch({ platform: "android" }), globalThis.fetch);
    } finally {
      if (previous !== undefined) (globalThis as { httpPOST?: unknown }).httpPOST = previous;
    }
  });

  it("defaults the SDK's own requests to Node http on iOS and to global fetch elsewhere", async () => {
    assert.equal(defaultRuntimeFetch("android"), globalThis.fetch);
    assert.equal(defaultRuntimeFetch("linux"), globalThis.fetch);
    const ios = defaultRuntimeFetch("ios");
    assert.notEqual(ios, globalThis.fetch);
    assert.equal((await ios(`${base}/echo`, { method: "POST", body: "y" })).status, 201);
  });
});
