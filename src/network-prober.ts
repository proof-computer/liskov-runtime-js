import {
  deriveNetworkMetrics, normalizeNetworkSample,
  type NetworkError, type NetworkLeg, type NetworkLegId, type NetworkReceipt,
  type NetworkSampleV1, type NetworkStatus, type UdpSample
} from "./network-sample.js";
import type { LiskovProcessorCoverageOutcome } from "./processor-coverage.js";
import type { ClientRequest, IncomingMessage } from "node:http";

const PROBER_URL = "https://liskov-network-prober.fly.dev";
const HOST = "liskov-network-prober.fly.dev";
const BUDGET_US = 30_000_000;
const SIZES = { download1m: 1_000_000, upload1m: 1_000_000, download10m: 10_000_000, upload10m: 10_000_000, download100m: 100_000_000 };
const TIMEOUTS = { download1m: 4000, upload1m: 4000, download10m: 8000, upload10m: 8000, download100m: 12000 };
type DownloadId = "download1m" | "download10m" | "download100m";
type UploadId = "upload1m" | "upload10m";
export interface NetworkPreparation { ipv4Egress: boolean; ipv6Egress: boolean; error: NetworkError | null }
/** Each operation includes its own deadline; elapsedUs is monotonic from sample start. */
export interface NetworkTransport {
  elapsedUs(): number;
  prepare(): Promise<NetworkPreparation>;
  udp(): Promise<UdpSample>;
  download(id: DownloadId): Promise<NetworkLeg>;
  upload(id: UploadId): Promise<NetworkLeg>;
  /** Reject with a NetworkError when authenticated accounting is unavailable. */
  receipt(): Promise<NetworkReceipt>;
  /** Cancel outstanding operations when the whole-sample deadline expires. */
  close?(): void;
}
export interface CollectNetworkSampleOptions {
  token: string;
  startedAtMs: number;
  proberUrl?: string;
  /** Monotonic milliseconds, defaulting to performance.now(). */
  now?: () => number;
  transport?: NetworkTransport;
}
const emptyMetrics = () => ({ downloadKbps: null, uploadKbps: null, medianRttUs: null, p90RttUs: null, jitterUs: null, lossBps: null });
function emptySample(startedAtMs: number, error: NetworkError): NetworkSampleV1 {
  return { version: 1, startedAtMs, durationMs: 0, region: "lhr", ipv4Egress: false, ipv6Egress: false,
    legs: [], udp: { status: "unreachable", startOffsetUs: 0, durationUs: 0, sentUs: [], echoes: [], error },
    metrics: emptyMetrics(), receipt: null, errors: [error] };
}
function skippedUdp(startOffsetUs: number): UdpSample {
  return { status: "skipped_budget", startOffsetUs, durationUs: 0, sentUs: [], echoes: [], error: "budget_exhausted" };
}
function failedLeg(id: NetworkLegId, startOffsetUs: number, error: NetworkError): NetworkLeg {
  return { id, startOffsetUs, status: "unreachable", durationUs: 0, bytes: 0, error };
}
function networkError(error: unknown, fallback: NetworkError): NetworkError {
  const codes: NetworkError[] = ["dns_failed", "connect_failed", "tls_failed", "timeout", "http_status", "invalid_response", "byte_count_mismatch", "rate_limited", "token_refused", "budget_exhausted", "receipt_unavailable"];
  return typeof error === "string" && codes.includes(error as NetworkError) ? error as NetworkError : fallback;
}

/** Collect the Cargo prober ladder. Transport failures become bounded evidence, never a rejection. */
export async function collectNetworkSample(options: CollectNetworkSampleOptions): Promise<NetworkSampleV1> {
  const startedAtMs = Number.isSafeInteger(options.startedAtMs) && options.startedAtMs >= 0 && options.startedAtMs <= 9_007_199_254_710_991 ? options.startedAtMs : 0;
  if ((options.proberUrl ?? PROBER_URL) !== PROBER_URL || startedAtMs !== options.startedAtMs) {
    return normalizeNetworkSample(emptySample(startedAtMs, "invalid_response"));
  }
  let transport: NetworkTransport | undefined;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    transport = options.transport ?? createNodeNetworkTransport(options);
    const t = transport;
    const run = async (): Promise<NetworkSampleV1> => {
      let preparation: NetworkPreparation;
      try { preparation = await t.prepare(); }
      catch (error) { preparation = { ipv4Egress: false, ipv6Egress: false, error: networkError(error, "connect_failed") }; }
      const sample: NetworkSampleV1 = { ...emptySample(startedAtMs, "budget_exhausted"),
        ipv4Egress: preparation.ipv4Egress, ipv6Egress: preparation.ipv6Egress,
        udp: skippedUdp(Math.min(t.elapsedUs(), BUDGET_US)), errors: preparation.error === null ? [] : [preparation.error] };
      if (t.elapsedUs() + 3_000_000 <= 29_000_000) {
        try { sample.udp = await t.udp(); }
        catch (error) { sample.udp = { ...sample.udp, status: "unreachable", error: networkError(error, "connect_failed") }; }
      }
      for (const id of Object.keys(SIZES) as NetworkLegId[]) {
        const prior = id === "download10m" ? "download1m" : id === "upload10m" ? "upload1m" : id === "download100m" ? "download10m" : null;
        if (prior !== null && !sample.legs.some(l => l.id === prior && l.status === "succeeded" && l.durationUs > 0 &&
          (id === "download100m" ? l.durationUs < 4_000_000 : Math.floor(l.bytes * 8000 / l.durationUs) >= 4000))) continue;
        const start = Math.min(t.elapsedUs(), BUDGET_US);
        let leg = failedLeg(id, start, "connect_failed");
        if (start + TIMEOUTS[id] * 1000 > 29_000_000) {
          leg = { ...leg, status: "skipped_budget", error: "budget_exhausted" };
        } else {
          try { leg = id.startsWith("download") ? await t.download(id as DownloadId) : await t.upload(id as UploadId); }
          catch (error) { leg.error = networkError(error, "connect_failed"); }
        }
        sample.legs.push(leg);
      }
      if (t.elapsedUs() <= 29_000_000) {
        try { sample.receipt = await t.receipt(); }
        catch (error) { sample.errors.push(networkError(error, "receipt_unavailable")); }
      } else sample.errors.push("receipt_unavailable");
      sample.durationMs = Math.min(Math.ceil(t.elapsedUs() / 1000), 30000);
      sample.metrics = deriveNetworkMetrics(sample);
      // Cargo drops accounting that races a dropped transfer instead of making it authoritative.
      if (sample.receipt !== null) {
        try { return normalizeNetworkSample(sample); }
        catch { sample.receipt = null; sample.errors.push("receipt_unavailable"); }
      }
      return normalizeNetworkSample(sample);
    };
    return await Promise.race([run(), new Promise<NetworkSampleV1>(resolve => {
      deadline = setTimeout(() => {
        const sample = emptySample(startedAtMs, "timeout");
        sample.durationMs = 30000;
        sample.udp = skippedUdp(0);
        resolve(normalizeNetworkSample(sample));
      }, 30000);
    })]);
  } catch (error) {
    return normalizeNetworkSample(emptySample(startedAtMs, networkError(error, "invalid_response")));
  } finally {
    if (deadline !== undefined) clearTimeout(deadline);
    // A faulty injected cleanup must not turn sample collection into a rejection.
    try { transport?.close?.(); } catch { /* no persistence or financial effects */ }
  }
}

/** The exact three outcomes required by Rust coverage admission. */
export function networkSampleOutcomes(sample: NetworkSampleV1): LiskovProcessorCoverageOutcome[] {
  const make = (probeId: string, status: NetworkStatus, start: number, end: number, bytesSent: number, bytesReceived: number, errors: NetworkError[]): LiskovProcessorCoverageOutcome => {
    const startedAtMs = sample.startedAtMs + Math.floor(start / 1000);
    const completedAtMs = sample.startedAtMs + Math.floor(end / 1000);
    return { probeId, status, region: sample.region, startedAtMs, completedAtMs, durationMs: completedAtMs - startedAtMs,
      bytesSent, bytesReceived, errors: errors.map(code => ({ code, message: code })) };
  };
  const outcomes = [true, false].map(download => {
    const legs = sample.legs.filter(l => l.id.startsWith("download") === download);
    const status = (["succeeded", "failed", "unreachable"] as const).find(s => legs.some(l => l.status === s)) ?? "skipped_budget";
    const bytes = legs.reduce((n, l) => n + l.bytes, 0);
    const start = legs.length ? Math.min(...legs.map(l => l.startOffsetUs)) : 0;
    const end = legs.length ? Math.max(...legs.map(l => l.startOffsetUs + l.durationUs)) : start;
    return make(download ? "bandwidth-download" : "bandwidth-upload", status, start, end, download ? 0 : bytes, download ? bytes : 0,
      legs.flatMap(l => l.error === null ? [] : [l.error]));
  });
  const u = sample.udp;
  outcomes.push(make("udp-path", u.status, u.startOffsetUs, u.startOffsetUs + u.durationUs, u.sentUs.length * 64, u.echoes.length * 64, u.error === null ? [] : [u.error]));
  return outcomes;
}

// Module loaders are the offline seam for exercising real sockets against local protocol servers.
interface NodeModules {
  https(): Promise<typeof import("node:https")>;
  dns(): Promise<typeof import("node:dns/promises")>;
  dgram(): Promise<typeof import("node:dgram")>;
}
const nodeModules: NodeModules = { https: () => import("node:https"), dns: () => import("node:dns/promises"), dgram: () => import("node:dgram") };
const statusError = (status: number): NetworkError => status === 404 ? "token_refused" : status === 429 ? "rate_limited" : "http_status";

/** Default streaming transport; the root export exposes only the sampling API. */
export function createNodeNetworkTransport(options: Pick<CollectNetworkSampleOptions, "token" | "now">, modules: NodeModules = nodeModules): NetworkTransport {
  const now = options.now ?? (() => performance.now());
  const origin = now();
  const elapsedUs = () => Math.max(0, Math.min(BUDGET_US, Math.floor((now() - origin) * 1000)));
  const cancel = new Set<() => void>();
  let closed = false;
  let https: typeof import("node:https") | undefined;
  let v4: string | undefined;
  let preferred: string | undefined;
  let loadError: NetworkError = "connect_failed";

  function request(path: string, ip: string, timeoutMs: number, id?: NetworkLegId, count?: { bytes: number }): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let req: ClientRequest | undefined;
      let response: IncomingMessage | undefined;
      let done = false;
      let connectTimer: ReturnType<typeof setTimeout> | undefined;
      const chunks: Buffer[] = [];
      let jsonBytes = 0;
      const finish = (error: NetworkError | null, value?: unknown) => {
        if (done) return;
        done = true; clearTimeout(timer); if (connectTimer !== undefined) clearTimeout(connectTimer); cancel.delete(abort);
        response?.destroy(); req?.destroy();
        if (error !== null) reject(error); else resolve(value);
      };
      const abort = () => finish("timeout");
      const timer = setTimeout(abort, timeoutMs);
      cancel.add(abort);
      if (closed || https === undefined) { finish("connect_failed"); return; }
      const download = id?.startsWith("download") === true;
      const upload = id !== undefined && !download;
      try {
        req = https.request({ hostname: HOST, port: 443, servername: HOST, method: upload ? "POST" : "GET",
          path, agent: false, family: ip.includes(":") ? 6 : 4, lookup: (_hostname, _options, callback) => callback(null, ip, ip.includes(":") ? 6 : 4),
          headers: download ? { "accept-encoding": "identity" } : upload ? { "content-length": SIZES[id!] } : {} }, res => {
          response = res;
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) { finish(statusError(status)); return; }
          if (download && (res.headers["content-length"] !== String(SIZES[id!]) || res.headers["x-liskov-region"] !== "lhr")) {
            finish("invalid_response"); return;
          }
          res.on("error", () => finish("invalid_response"));
          res.on("aborted", () => finish("invalid_response"));
          res.on("data", (chunk: Buffer) => {
            if (done) return;
            if (download) {
              const offset = count!.bytes;
              if (offset + chunk.length > SIZES[id!]) { finish("byte_count_mismatch"); return; }
              for (let i = 0; i < chunk.length; i++) {
                if (chunk[i] !== (offset + i) % 251) { finish("byte_count_mismatch"); return; }
              }
              count!.bytes += chunk.length;
            } else {
              jsonBytes += chunk.length;
              if (jsonBytes > 4096) { finish("invalid_response"); return; }
              chunks.push(chunk);
            }
          });
          res.on("end", () => {
            if (done) return;
            if (download) { finish(count!.bytes === SIZES[id!] ? null : "byte_count_mismatch"); return; }
            try { finish(null, JSON.parse(Buffer.concat(chunks, jsonBytes).toString("utf8"))); }
            catch { finish("invalid_response"); }
          });
        });
        connectTimer = setTimeout(() => finish("connect_failed"), 1000);
        req.on("socket", socket => socket.once("secureConnect", () => { if (connectTimer !== undefined) clearTimeout(connectTimer); }));
        req.on("error", () => finish("connect_failed"));
        if (upload) {
          const zeros = Buffer.alloc(16384);
          const write = () => {
            if (done) return;
            try {
              while (count!.bytes < SIZES[id!]) {
                const size = Math.min(zeros.length, SIZES[id!] - count!.bytes);
                const ready = req!.write(zeros.subarray(0, size));
                count!.bytes += size;
                if (!ready) { req!.once("drain", write); return; }
              }
              req!.end();
            } catch { finish("connect_failed"); }
          };
          write();
        } else req.end();
      } catch { finish("connect_failed"); }
    });
  }
  const query = (path: string) => `${path}?t=${encodeURIComponent(options.token)}`;
  async function transfer(id: NetworkLegId): Promise<NetworkLeg> {
    const start = elapsedUs();
    const leg = failedLeg(id, start, loadError);
    if (preferred === undefined) return leg;
    const count = { bytes: 0 };
    try {
      const value = await request(query(id.startsWith("download") ? `/v1/blob/${id.slice(8)}` : "/v1/upload"), preferred, TIMEOUTS[id], id, count);
      if (!id.startsWith("download")) {
        const reply = value as { bytes?: unknown; region?: unknown } | null;
        if (reply?.bytes !== SIZES[id] || reply.region !== "lhr") throw "byte_count_mismatch";
      }
      leg.status = "succeeded"; leg.error = null;
    } catch (error) { leg.status = "failed"; leg.error = networkError(error, "connect_failed"); }
    leg.durationUs = Math.min(elapsedUs() - start, TIMEOUTS[id] * 1000);
    leg.bytes = Math.min(count.bytes, SIZES[id]);
    return leg;
  }

  return {
    elapsedUs, download: transfer, upload: transfer,
    async prepare() {
      let dns: typeof import("node:dns/promises");
      try { [https, dns] = await Promise.all([modules.https(), modules.dns()]); }
      catch { return { ipv4Egress: false, ipv6Egress: false, error: loadError }; }
      const addresses = await new Promise<[string | undefined, string | undefined]>(resolve => {
        let resolver: InstanceType<typeof dns.Resolver> | undefined;
        let done = false;
        const finish = (result: [string | undefined, string | undefined]) => {
          if (done) return;
          done = true; clearTimeout(timer); cancel.delete(abort); resolver?.cancel(); resolve(result);
        };
        const abort = () => finish([undefined, undefined]);
        const timer = setTimeout(abort, 1000); cancel.add(abort);
        if (closed) { abort(); return; }
        try {
          resolver = new dns.Resolver();
          void Promise.all([resolver.resolve4(HOST).catch(() => []), resolver.resolve6(HOST).catch(() => [])])
            .then(([a, aaaa]) => finish([a[0], aaaa[0]]), abort);
        } catch { abort(); }
      });
      [v4] = addresses;
      if (addresses.every(ip => ip === undefined)) {
        return { ipv4Egress: false, ipv6Egress: false, error: "dns_failed" };
      }
      const checked = await Promise.all(addresses.map(async ip => {
        if (ip === undefined) return undefined;
        try {
          const value = await request("/v1/healthz", ip, 1000) as { ok?: unknown; region?: unknown } | null;
          return value?.ok === true && value.region === "lhr" ? ip : undefined;
        } catch { return undefined; }
      }));
      preferred = checked[0] ?? checked[1];
      return { ipv4Egress: checked[0] !== undefined, ipv6Egress: checked[1] !== undefined, error: preferred === undefined ? "connect_failed" : null };
    },
    async udp() {
      const start = elapsedUs();
      const result: UdpSample = { status: "unreachable", startOffsetUs: start, durationUs: 0, sentUs: [], echoes: [], error: "connect_failed" };
      if (v4 === undefined) return result;
      if (!/^0x[0-9a-fA-F]{64}$/u.test(options.token)) return { ...result, error: "token_refused" };
      let dgram: typeof import("node:dgram");
      try { dgram = await modules.dgram(); } catch { return result; }
      return new Promise<UdpSample>(resolve => {
        let socket: import("node:dgram").Socket | undefined;
        let sendTimer: ReturnType<typeof setTimeout> | undefined;
        let done = false;
        const token = Buffer.from(options.token.slice(2), "hex");
        const seen = new Set<number>();
        const relative = () => Math.min(elapsedUs() - start, 3_000_000);
        const finish = () => {
          if (done) return;
          done = true; clearTimeout(stop); if (sendTimer !== undefined) clearTimeout(sendTimer); cancel.delete(finish);
          try { socket?.close(); } catch { /* a socket that never opened */ }
          result.durationUs = relative();
          if (result.echoes.length > 0) { result.status = "succeeded"; result.error = null; }
          else if (result.sentUs.length > 0) result.error = "timeout";
          resolve(result);
        };
        const stop = setTimeout(finish, Math.max(0, 3000 - relative() / 1000)); cancel.add(finish);
        if (closed) { finish(); return; }
        const send = () => {
          if (done || result.sentUs.length >= 20 || relative() >= 3_000_000) return;
          const sequence = result.sentUs.length;
          const sent = relative();
          // Millisecond clocks can round two sends to the same timestamp; defer rather than emit invalid evidence.
          if (sequence > 0 && sent <= result.sentUs[sequence - 1]!) { sendTimer = setTimeout(send, 1); return; }
          const packet = Buffer.alloc(64);
          token.copy(packet); packet.writeUInt16BE(sequence, 32); packet.writeBigUInt64BE(BigInt(sent), 34); packet.write("LNP1", 42);
          try {
            socket!.send(packet, error => {
              if (done) return;
              if (error !== null) { finish(); return; }
              result.sentUs.push(sent);
              if (result.sentUs.length < 20) sendTimer = setTimeout(send, Math.max(0, result.sentUs.length * 100 - relative() / 1000));
            });
          } catch { finish(); }
        };
        try {
          socket = dgram.createSocket("udp4"); socket.on("error", finish);
          socket.on("message", packet => {
            if (done || packet.length !== 64 || !packet.subarray(0, 32).equals(token) || packet.toString("ascii", 42, 46) !== "LNP1" || packet.subarray(46).some(b => b !== 0)) return;
            const sequence = packet.readUInt16BE(32);
            if (sequence >= result.sentUs.length || seen.has(sequence) || packet.readBigUInt64BE(34) !== BigInt(result.sentUs[sequence]!)) return;
            const receivedUs = relative();
            if (receivedUs < result.sentUs[sequence]!) return;
            seen.add(sequence); result.echoes.push({ sequence, receivedUs });
          });
          socket.bind(0, "0.0.0.0", () => { if (!done) { try { socket!.connect(5000, v4!, send); } catch { finish(); } } });
        } catch { finish(); }
      });
    },
    async receipt() {
      if (preferred === undefined) throw "receipt_unavailable";
      try {
        const value = await request(query("/v1/receipt"), preferred, 1000);
        if (value === null || typeof value !== "object") throw "receipt_unavailable";
        return value as NetworkReceipt;
      }
      catch (error) { throw networkError(error, "receipt_unavailable") === "connect_failed" || error === "timeout" || error === "invalid_response" ? "receipt_unavailable" : error; }
    },
    close() { closed = true; for (const abort of [...cancel]) abort(); }
  };
}
