import assert from "node:assert/strict";
import * as https from "node:https";
import * as dns from "node:dns/promises";
import * as dgram from "node:dgram";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { after, before, it } from "node:test";
import { collectNetworkSample, networkSampleOutcomes, type NetworkTransport } from "../src/index.js";
import { createNodeNetworkTransport } from "../src/network-prober.js";
import { normalizeNetworkSample, type NetworkLeg, type NetworkLegId, type NetworkReceipt, type NetworkSampleV1 } from "../src/network-sample.js";

// Self-signed localhost fixture; never used by the production transport.
const key = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC+XS/uzWxqTBHR\nWY4oITFuHllWfiE5ijvWSls5VExyqiv7OXr9C/BlmpzHNw/noZmlWbqrJGwvGFsw\nHmEsXgyQ7kRp7QnubWdJBzm1UF9k/V6zLdXSehU7ilP1in2i8zLbWmbSw4c0RslH\nPzuHWMCtm1Ec6EkLj4SV2Q8XWlxdrlL0+o5pjk0rkiR0e5FWL7qA84eHQ/nFsbiO\nlNQj+sIX9VYsXkbjcSqwu7sR8d4NgSWrmWu4MMlaEBP0yzYT66vkfdRYQ8KXdkgc\nqOEGnLl8fcgqbF2o5LIuQcX7IZ+7HF/RmWakg3Bx27H5ivXOlbrD8hA9f9V5BPg2\nv2eJY4KBAgMBAAECggEAESQofQcT2FV9tD1taskkX49NiZeFa9456Z+b68Net+OB\nXteL7s28qZV8wQaBAOFBCc3U3HTE5g+6JFDT/LACTymZUPV2c7j3uDB1npE8acZT\n2OwLaS6ziz83NLCyA/KEtZJEGH3hRpCKLsdvl44jGW7XJLR44VjcvjaDoJ1zHD8+\ntxrMVbZijQzV4DnV1Ka65rTOglRehfz6YfEF5byXO0obGbZekXNtf6422XYQCmWs\ncz24aMthq/TMm2Npfuwv1Ltzj4ZrVNT/kuVglvmlXtomJkG6x40mwBcd3xn9Qz7u\nzOX41IIYvYadZ5sh4Q1q9N+Z/60FPqNHrw9ba1NzMQKBgQDg+wXAOWl2X0pc/PsO\nh0ZIqz1N9YDedrOko4KINLRU9D5DVKQmxL75gOF7Ihx6PDPxK8+64QO/VxUkL7T4\nKmQDmL0LYPZXSG9a616cOLNFYKbOX528pJhxit9itYP/IKNW8pAbB0WBdvEh/kFJ\n6tk0ZIwepDr8scU179TZH3s7SQKBgQDYnFRVDBL/iQNGBC0evZQlLFK2EN9od5uI\nj7oOeYeba8cFUNjb/NDi2P7JKfTiWY0GTW/uAa/rguDiP6h2GOpTln8a2RazYrUi\n7I48aqWUlEkF/Hu0jvTLfTnZqLmPPa8YhGyNG+fdy8zh2lw6aJ7BKZfFntIhUJHE\nUqYfzouVeQKBgBKIu32NfUGyMfcdJDWbMVAVQ1Sjz/0DvGLo0X0VEnIZOPPlCizj\ncnQtiOXS9pOfWAwbNt7HYL6nludHQtpa66hcMd65GzIvlnTgBQhLp4EkqDlCKUV8\nLc7UyPhhycD/2FT2YKbJX5F90fmh75D+Vux5CA4SK4Xbw0phOqC0djt5AoGAFERs\nT5jVnjs/pyl03091sRS4mHhzrt6iGuD306rjWVN4R7MM12iMUu1iyYe3dgZS/6f3\nNRnLUAnq6MB0Dri+FBwcwHJXgWlW8XGYzWZdH83QF1NMb9SAaxnIc+kpk5F99JlP\nXtShmUscXHWF86EeWYx+uurlVmCngusIyCkXPmECgYBxiX58lP+nOl7qQj4yWMWh\nbVVVfeehBb4ToGYlb453E32m3GmeALvo2Jf07pI1FFRpd5eIv0Y9ki5Dt2NLjLaW\nITRlGutLQbu3DfrUx+Fs2ALHnSZZqaPCsD6TY50BmqWfIJIFS+hynML6Kzys5gTF\nMFD7PxoWCGOTE5CzmnAyLQ==\n-----END PRIVATE KEY-----\n";
const cert = "-----BEGIN CERTIFICATE-----\nMIIDHzCCAgegAwIBAgIUPzhtviXaQ09Q8/lOJtM+h1WY4zAwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAwOTEyMDU1N1oXDTM2MTAw\nNjEyMDU1N1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAvl0v7s1sakwR0VmOKCExbh5ZVn4hOYo71kpbOVRMcqor\n+zl6/QvwZZqcxzcP56GZpVm6qyRsLxhbMB5hLF4MkO5Eae0J7m1nSQc5tVBfZP1e\nsy3V0noVO4pT9Yp9ovMy21pm0sOHNEbJRz87h1jArZtRHOhJC4+EldkPF1pcXa5S\n9PqOaY5NK5IkdHuRVi+6gPOHh0P5xbG4jpTUI/rCF/VWLF5G43EqsLu7EfHeDYEl\nq5lruDDJWhAT9Ms2E+ur5H3UWEPCl3ZIHKjhBpy5fH3IKmxdqOSyLkHF+yGfuxxf\n0ZlmpINwcdux+Yr1zpW6w/IQPX/VeQT4Nr9niWOCgQIDAQABo2kwZzAdBgNVHQ4E\nFgQUrrssTwwfhsUTbSVtFoI9e/wKGsYwHwYDVR0jBBgwFoAUrrssTwwfhsUTbSVt\nFoI9e/wKGsYwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3Qw\nDQYJKoZIhvcNAQELBQADggEBAKkHtQqGRy5inPgQdZFw6/2VQRbYDXvXf/WNXYjg\nO/b6VqT1idTm+7a+YSwCRgAVY3wAwxHjioYbp422DCGwATrZPB3qPh/oh+/3AWvD\nWZsiUTWTq5IgJUUBzELOfxNcC1eue1fiPwO2Cvf389YLh3eKeuL+Ap/vSsIoffC4\nD3oIi18UWaWjE7VDSd4kZUnTXrI2pG+RGzkuzd+yYCdewmNq1pjSKQAvjGd45/Wy\n/0ttsTEQz7tcOLcSq7Q5CCV6z2g8gPnibrA8Hbp7sSuvbs2WHA5FfgqWmIScC99n\nEa8z7hZ96TL4KO7nFfVg31yTHhU495/WrQbpLt2p6+V0EPM=\n-----END CERTIFICATE-----\n";
const token = `0x${"07".repeat(32)}`;
const startedAtMs = 1000;
const sizes = { download1m: 1_000_000, upload1m: 1_000_000, download10m: 10_000_000, upload10m: 10_000_000, download100m: 100_000_000 };
let server: https.Server;
let udp: dgram.Socket;
let httpPort = 0;
let udpPort = 0;
let fault = "";
let noEcho = false;
let extraEchoes = false;
let virtualMs = 0;
let delays: Record<string, number> = {};
let routes: string[] = [];
let packets: Buffer[] = [];
let receiptLegs: NetworkReceipt["legs"] = [];
let receiptEchoes = 0;
let peakBuffered = 0;
let downloadConcats = 0;
let sawDownload = false;
let badUploads = 0;
const now = () => performance.now() + virtualMs;

function reset() {
  fault = ""; noEcho = false; extraEchoes = false; virtualMs = 0; delays = {};
  routes = []; packets = []; receiptLegs = []; receiptEchoes = 0;
  peakBuffered = 0; downloadConcats = 0; badUploads = 0;
}
before(async () => {
  server = https.createServer({ key, cert }, (req, res) => {
    const url = new URL(req.url!, "https://localhost");
    routes.push(url.pathname);
    if (url.pathname === "/v1/healthz") { res.end(JSON.stringify({ ok: true, region: "lhr" })); return; }
    assert.equal(url.searchParams.get("t"), token);
    if (fault === "404" || fault === "429") { res.writeHead(Number(fault)); res.end(); return; }
    if (url.pathname.startsWith("/v1/blob/")) {
      const id = `download${url.pathname.split("/").at(-1)}` as NetworkLegId;
      const size = sizes[id];
      if (fault === "short-header") {
        res.writeHead(200, { "content-length": size - 1, "x-liskov-region": "lhr" }); res.end(); return;
      }
      res.writeHead(200, { "content-length": size, ...(fault === "region" ? {} : { "x-liskov-region": "lhr" }) });
      let offset = 0;
      const send = () => {
        while (offset < size && !res.destroyed) {
          const n = Math.min(16384, size - offset);
          const chunk = Buffer.alloc(n);
          for (let i = 0; i < n; i++) chunk[i] = (offset + i) % 251;
          if (fault === "wrong-byte" && offset === 0) chunk[0] = 255;
          offset += n;
          if (fault === "short-body" && offset > 32768) { setTimeout(() => res.destroy(), 10); return; }
          if (!res.write(chunk)) { res.once("drain", send); return; }
        }
        if (offset === size) {
          receiptLegs.push({ id, bytes: size, durationUs: 1, complete: true }); res.end();
        }
      };
      send(); return;
    }
    if (url.pathname === "/v1/upload") {
      const size = Number(req.headers["content-length"]);
      assert.ok(size === 1_000_000 || size === 10_000_000);
      assert.equal(req.headers["transfer-encoding"], undefined);
      let count = 0;
      req.on("data", (chunk: Buffer) => { count += chunk.length; if (chunk.some(b => b !== 0)) badUploads++; });
      req.on("end", () => {
        assert.equal(count, size);
        receiptLegs.push({ id: size === 1_000_000 ? "upload1m" : "upload10m", bytes: count, durationUs: 1, complete: true });
        res.end(JSON.stringify(fault === "upload-reply" ? { bytes: size - 1, region: "lhr" } : { bytes: size, region: "lhr" }));
      }); return;
    }
    if (url.pathname === "/v1/receipt") {
      const receipt: NetworkReceipt = { version: 1, challengeDigest: `sha256:${"a".repeat(64)}`, expiresAtSec: 1_800_000_000,
        region: "lhr", legs: receiptLegs, udpEchoes: receiptEchoes, mac: "b".repeat(64) };
      if (fault === "oversized-receipt") res.end(" ".repeat(4097));
      else res.end(JSON.stringify(fault === "bad-receipt" ? { ...receipt, legs: [] } : receipt));
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  httpPort = (server.address() as AddressInfo).port;
  udp = dgram.createSocket("udp4");
  udp.on("message", (packet, peer) => {
    packets.push(Buffer.from(packet));
    assert.equal(packet.length, 64);
    assert.equal(packet.subarray(0, 32).toString("hex"), token.slice(2));
    assert.equal(packet.readUInt16BE(32), packets.length - 1);
    assert.equal(packet.toString("ascii", 42, 46), "LNP1");
    assert.ok(packet.subarray(46).every(b => b === 0));
    if (noEcho) return;
    if (extraEchoes) {
      for (const offset of [0, 34, 42, 46]) {
        const invalid = Buffer.from(packet); invalid[offset] = invalid[offset]! ^ 255;
        udp.send(invalid, peer.port, peer.address);
      }
      udp.send(packet.subarray(0, 63), peer.port, peer.address);
      const future = Buffer.from(packet); future.writeUInt16BE(20, 32); udp.send(future, peer.port, peer.address);
      udp.send(packet, peer.port, peer.address);
    }
    udp.send(packet, peer.port, peer.address); receiptEchoes++;
  });
  await new Promise<void>(resolve => udp.bind(0, "127.0.0.1", resolve));
  udpPort = udp.address().port;
});
after(async () => {
  udp.close(); server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
});

// Only routing and trust are adapted: production request/stream/socket code runs unchanged.
function localTransport(unavailableUdp = false, socketFails = false) {
  const modules = {
    async https() {
      return { ...https, request(options: https.RequestOptions, callback: (res: import("node:http").IncomingMessage) => void) {
        assert.equal(options.hostname, "liskov-network-prober.fly.dev");
        assert.equal(options.port, 443);
        assert.equal(options.servername, "liskov-network-prober.fly.dev");
        return https.request({ ...options, hostname: "localhost", port: httpPort, servername: "localhost", ca: cert,
          lookup: (_hostname, _options, cb) => cb(null, "127.0.0.1", 4) }, res => {
          sawDownload = String(options.path).startsWith("/v1/blob/");
          res.on("data", (chunk: Buffer) => {
            peakBuffered = Math.max(peakBuffered, chunk.length + res.readableLength);
          });
          res.once("end", () => { virtualMs += delays[String(options.path).split("?")[0]!] ?? 0; });
          res.once("close", () => { sawDownload = false; });
          callback(res);
        });
      } } as typeof https;
    },
    async dns() {
      return { ...dns, Resolver: class {
        async resolve4() { return ["127.0.0.1"]; }
        async resolve6() { return []; }
        cancel() {}
      } } as unknown as typeof dns;
    },
    async dgram() {
      if (unavailableUdp) throw new Error("node:dgram unavailable");
      return { ...dgram, createSocket() {
        if (socketFails) throw new Error("socket cannot open");
        const socket = dgram.createSocket("udp4");
        const connect = socket.connect.bind(socket);
        socket.connect = ((_port: number, _host: string, callback: () => void) => connect(udpPort, "127.0.0.1", callback)) as typeof socket.connect;
        return socket;
      } } as typeof dgram;
    }
  };
  return createNodeNetworkTransport({ token, now }, modules);
}
const collectLocal = (unavailableUdp = false) => collectNetworkSample({ token, startedAtMs, transport: localTransport(unavailableUdp) });

it("streams the complete HTTPS ladder, fixed-length zero uploads, receipt and verified UDP echoes", async () => {
  reset(); extraEchoes = true;
  const concat = Buffer.concat;
  Buffer.concat = ((...args: Parameters<typeof Buffer.concat>) => {
    if (sawDownload) downloadConcats++;
    return concat(...args);
  }) as typeof Buffer.concat;
  let sample: NetworkSampleV1;
  try { sample = await collectLocal(); } finally { Buffer.concat = concat; }
  assert.deepEqual(sample.legs.map(l => l.id), Object.keys(sizes));
  assert.ok(sample.legs.every(l => l.status === "succeeded" && l.bytes === sizes[l.id]));
  assert.equal(sample.ipv4Egress, true); assert.equal(sample.ipv6Egress, false);
  assert.equal(sample.udp.status, "succeeded");
  assert.equal(sample.udp.sentUs.length, 20); assert.equal(sample.udp.echoes.length, 20);
  assert.equal(sample.metrics.lossBps, 0);
  assert.equal(sample.receipt?.legs.length, 5); assert.deepEqual(sample.errors, []);
  assert.equal(badUploads, 0); assert.equal(downloadConcats, 0);
  assert.ok(peakBuffered < 1_048_576, `peak buffered download bytes ${peakBuffered}`);
  assert.deepEqual(routes, ["/v1/healthz", "/v1/blob/1m", "/v1/upload", "/v1/blob/10m", "/v1/upload", "/v1/blob/100m", "/v1/receipt"]);
  assert.ok(sample.durationMs <= 30000); normalizeNetworkSample(sample);
});

it("does not run either 10m leg below the 4 Mbit/s gate over local HTTPS", async () => {
  reset(); delays = { "/v1/blob/1m": 2100, "/v1/upload": 2100 };
  const sample = await collectLocal(true);
  assert.deepEqual(sample.legs.map(l => l.id), ["download1m", "upload1m"]);
  assert.ok(sample.legs.every(l => l.status === "succeeded"));
});
it("runs 10m but omits 100m when the local 10m leg takes at least four seconds", async () => {
  reset(); delays = { "/v1/blob/10m": 4000 };
  const sample = await collectLocal(true);
  assert.deepEqual(sample.legs.map(l => l.id), ["download1m", "upload1m", "download10m", "upload10m"]);
});
for (const [name, error] of [
  ["short-header", "invalid_response"], ["short-body", "invalid_response"], ["wrong-byte", "byte_count_mismatch"],
  ["region", "invalid_response"], ["404", "token_refused"], ["429", "rate_limited"]] as const) {
  it(`records Cargo's ${error} for local HTTPS ${name}`, async () => {
    reset(); fault = name;
    const sample = await collectLocal(true);
    const leg = sample.legs.find(l => l.id === "download1m")!;
    assert.equal(leg.status, "failed"); assert.equal(leg.error, error);
    assert.ok(!sample.legs.some(l => l.id === "download10m"));
    if (name === "404" || name === "429") {
      assert.equal(sample.legs.find(l => l.id === "upload1m")!.error, error);
      assert.ok(sample.errors.includes(error));
    }
  });
}
it("checks the upload JSON bytes and region", async () => {
  reset(); fault = "upload-reply";
  const sample = await collectLocal(true);
  assert.equal(sample.legs.find(l => l.id === "upload1m")!.error, "byte_count_mismatch");
  assert.ok(!sample.legs.some(l => l.id === "upload10m"));
});
it("records UDP sent without echoes as loss and keeps the HTTP sample", async () => {
  reset(); noEcho = true;
  const sample = await collectLocal();
  assert.equal(sample.udp.status, "unreachable"); assert.equal(sample.udp.error, "timeout");
  assert.equal(sample.udp.sentUs.length, 20); assert.deepEqual(sample.udp.echoes, []);
  assert.equal(sample.metrics.lossBps, 10000);
  const outcome = networkSampleOutcomes(sample)[2]!;
  assert.equal(outcome.bytesSent, 1280); assert.equal(outcome.bytesReceived, 0);
});
it("continues the full HTTP ladder when node:dgram cannot load", async () => {
  reset();
  const sample = await collectLocal(true);
  assert.equal(sample.udp.status, "unreachable"); assert.equal(sample.udp.error, "connect_failed");
  assert.deepEqual(sample.udp.sentUs, []); assert.equal(sample.metrics.lossBps, null);
  assert.equal(sample.legs.length, 5); assert.ok(sample.legs.every(l => l.status === "succeeded"));
});
for (const name of ["bad-receipt", "oversized-receipt"]) {
  it(`drops ${name} accounting instead of claiming it is authoritative`, async () => {
    reset(); fault = name;
    const sample = await collectLocal(true);
    assert.equal(sample.receipt, null); assert.ok(sample.errors.includes("receipt_unavailable"));
    assert.equal(sample.legs.length, 5);
  });
}

function fake(options: { initialMs?: number; durationMs?: number; failed?: boolean } = {}) {
  let ms = options.initialMs ?? 0;
  const calls: string[] = [];
  const transfer = async (id: NetworkLegId): Promise<NetworkLeg> => {
    calls.push(id); const startOffsetUs = ms * 1000;
    const durationMs = options.durationMs ?? 100; ms += durationMs;
    return { id, status: options.failed === true ? "failed" : "succeeded", startOffsetUs,
      durationUs: durationMs * 1000, bytes: options.failed === true ? 42 : sizes[id], error: options.failed === true ? "timeout" : null };
  };
  const transport: NetworkTransport = {
    elapsedUs: () => ms * 1000,
    async prepare() { return { ipv4Egress: true, ipv6Egress: true, error: null }; },
    async udp() { calls.push("udp"); const startOffsetUs = ms * 1000; ms += 3000;
      return { status: "unreachable", startOffsetUs, durationUs: 3_000_000, sentUs: [], echoes: [], error: "connect_failed" }; },
    download: transfer, upload: transfer,
    async receipt() { calls.push("receipt"); throw "receipt_unavailable"; }
  };
  return { transport, calls };
}
it("pins the admission vector's three outcomes byte-for-byte", () => {
  const vector = JSON.parse(readFileSync(new URL("./vectors/processor-coverage-network-v1.json", import.meta.url), "utf8"));
  assert.deepEqual(networkSampleOutcomes(vector.result.networkSample), vector.result.outcomes.filter((o: { probeId: string }) => ["bandwidth-download", "bandwidth-upload", "udp-path"].includes(o.probeId)));
});
it("reserves receipt time and marks budget skips exactly as Cargo does", async () => {
  const f = fake({ initialMs: 25000 });
  const sample = await collectNetworkSample({ token, startedAtMs, transport: f.transport });
  assert.deepEqual(f.calls, ["udp", "receipt"]);
  assert.deepEqual(sample.legs.map(l => [l.id, l.status, l.error]), [["download1m", "skipped_budget", "budget_exhausted"], ["upload1m", "skipped_budget", "budget_exhausted"]]);
  const late = fake({ initialMs: 27000 });
  const skipped = await collectNetworkSample({ token, startedAtMs, transport: late.transport });
  assert.equal(skipped.udp.status, "skipped_budget");
  const expired = fake({ initialMs: 30000 });
  const noReceipt = await collectNetworkSample({ token, startedAtMs, transport: expired.transport });
  assert.deepEqual(expired.calls, []); assert.ok(noReceipt.errors.includes("receipt_unavailable"));
});
it("records full-ladder and slow-link gates with the injectable transport", async () => {
  for (const [durationMs, count] of [[100, 5], [3000, 2]] as const) {
    const f = fake({ durationMs });
    const sample = await collectNetworkSample({ token, startedAtMs, transport: f.transport });
    assert.equal(sample.legs.length, count); normalizeNetworkSample(sample);
  }
});
it("uses Cargo status precedence, partial bytes and floor-based outcome durations", () => {
  const sample = JSON.parse(readFileSync(new URL("./vectors/processor-coverage-network-v1.json", import.meta.url), "utf8")).result.networkSample as NetworkSampleV1;
  sample.legs.push({ id: "download10m", status: "failed", startOffsetUs: 10_000_001, durationUs: 1999, bytes: 42, error: "timeout" });
  const outcome = networkSampleOutcomes(sample)[0]!;
  assert.equal(outcome.status, "succeeded"); assert.equal(outcome.bytesReceived, 1_000_042);
  assert.equal(outcome.completedAtMs, sample.startedAtMs + 10002);
  assert.deepEqual(outcome.errors, [{ code: "timeout", message: "timeout" }]);
  sample.legs[0]!.status = "unreachable";
  assert.equal(networkSampleOutcomes(sample)[0]!.status, "failed");
  sample.legs[2]!.status = "skipped_budget";
  assert.equal(networkSampleOutcomes(sample)[0]!.status, "unreachable");
  sample.legs = [];
  assert.equal(networkSampleOutcomes(sample)[0]!.status, "skipped_budget");
});
it("rejects another prober URL before touching an injected transport", async () => {
  const f = fake();
  const sample = await collectNetworkSample({ token, startedAtMs, proberUrl: "https://example.com", transport: f.transport });
  assert.deepEqual(f.calls, []); assert.deepEqual(sample.legs, []);
  assert.equal(sample.udp.status, "unreachable"); assert.deepEqual(sample.errors, ["invalid_response"]);
});
it("turns missing HTTPS/DNS and socket-open failures into unreachable evidence", async () => {
  const broken = createNodeNetworkTransport({ token }, {
    https: async () => { throw new Error("unavailable"); }, dns: async () => dns, dgram: async () => dgram
  });
  const sample = await collectNetworkSample({ token, startedAtMs, transport: broken });
  assert.deepEqual(sample.errors, ["connect_failed", "receipt_unavailable"]);
  assert.ok(sample.legs.every(l => l.status === "unreachable"));
  reset();
  const continued = await collectNetworkSample({ token, startedAtMs, transport: localTransport(false, true) });
  assert.equal(continued.udp.status, "unreachable"); assert.equal(continued.legs.length, 5);
});
it("bounds a stalled adapter to 30 seconds and closes it", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let closed = false;
  const f = fake(); f.transport.prepare = () => new Promise(() => {}); f.transport.close = () => { closed = true; };
  const result = collectNetworkSample({ token, startedAtMs, transport: f.transport });
  t.mock.timers.tick(30000);
  const sample = await result;
  assert.equal(sample.durationMs, 30000); assert.deepEqual(sample.errors, ["timeout"]); assert.equal(closed, true);
  normalizeNetworkSample(sample);
});
