/** Versioned, bounded signed network evidence. Rust contracts own this schema. */
export type NetworkStatus = "succeeded" | "failed" | "skipped_budget" | "unreachable";
export type NetworkError = "dns_failed" | "connect_failed" | "tls_failed" | "timeout" | "http_status" | "invalid_response" | "byte_count_mismatch" | "rate_limited" | "token_refused" | "budget_exhausted" | "receipt_unavailable";
export type NetworkLegId = "download1m" | "upload1m" | "download10m" | "upload10m" | "download100m";
export interface NetworkLeg { id: NetworkLegId; status: NetworkStatus; startOffsetUs: number; durationUs: number; bytes: number; error: NetworkError | null }
export interface UdpSample { status: NetworkStatus; startOffsetUs: number; durationUs: number; sentUs: number[]; echoes: { sequence: number; receivedUs: number }[]; error: NetworkError | null }
export interface NetworkMetrics { downloadKbps: number | null; uploadKbps: number | null; medianRttUs: number | null; p90RttUs: number | null; jitterUs: number | null; lossBps: number | null }
export interface NetworkReceipt { version: 1; challengeDigest: string; expiresAtSec: number; region: "lhr"; legs: { id: NetworkLegId; bytes: number; durationUs: number; complete: boolean }[]; udpEchoes: number; mac: string }
export interface NetworkSampleV1 { version: 1; startedAtMs: number; durationMs: number; region: "lhr"; ipv4Egress: boolean; ipv6Egress: boolean; legs: NetworkLeg[]; udp: UdpSample; metrics: NetworkMetrics; receipt: NetworkReceipt | null; errors: NetworkError[] }
const sizes: Record<NetworkLegId, number> = { download1m: 1_000_000, upload1m: 1_000_000, download10m: 10_000_000, upload10m: 10_000_000, download100m: 100_000_000 };
const timeouts: Record<NetworkLegId, number> = { download1m: 4_000_000, upload1m: 4_000_000, download10m: 8_000_000, upload10m: 8_000_000, download100m: 12_000_000 };
const codes = ["dns_failed", "connect_failed", "tls_failed", "timeout", "http_status", "invalid_response", "byte_count_mismatch", "rate_limited", "token_refused", "budget_exhausted", "receipt_unavailable"];
function ensure(condition: unknown): asserts condition { if (!condition) throw new Error("invalid network sample v1"); }
function exact(value: unknown, keys: string): void { ensure(value !== null && typeof value === "object" && !Array.isArray(value)); ensure(Object.keys(value).sort().join(",") === keys.split(",").sort().join(",")); }
function integer(n: unknown, max = Number.MAX_SAFE_INTEGER): void { ensure(typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && n <= max); }
function error(e: unknown): void { ensure(e === null || (typeof e === "string" && codes.includes(e))); }
function status(s: unknown): void { ensure(typeof s === "string" && ["succeeded", "failed", "skipped_budget", "unreachable"].includes(s)); }
export function deriveNetworkMetrics(sample: NetworkSampleV1): NetworkMetrics {
  const rate = (download: boolean): number | null => {
    const legs = sample.legs.filter(l => l.id.startsWith("download") === download && l.status === "succeeded" && l.durationUs > 0).sort((a,b) => sizes[b.id] - sizes[a.id]);
    return legs.length ? Math.floor(legs[0]!.bytes * 8000 / legs[0]!.durationUs) : null;
  };
  let jitter = 0; let previous: number | null = null;
  const rtts = sample.udp.echoes.map(e => {
    const rtt = e.receivedUs - sample.udp.sentUs[e.sequence]!;
    if (previous !== null) jitter += Math.abs(rtt - previous) - Math.floor((jitter + 8) / 16);
    previous = rtt; return rtt;
  }).sort((a,b) => a-b);
  return { downloadKbps: rate(true), uploadKbps: rate(false),
    medianRttUs: rtts.length ? Math.floor((rtts[Math.floor((rtts.length-1)/2)]! + rtts[Math.floor(rtts.length/2)]!) / 2) : null,
    p90RttUs: rtts.length ? rtts[Math.ceil(rtts.length * 0.9)-1]! : null,
    jitterUs: rtts.length < 2 ? null : Math.floor(jitter / 16),
    lossBps: sample.udp.sentUs.length ? Math.floor((sample.udp.sentUs.length-rtts.length)*10000/sample.udp.sentUs.length) : null };
}
export function normalizeNetworkSample(sample: NetworkSampleV1): NetworkSampleV1 {
  exact(sample, "version,startedAtMs,durationMs,region,ipv4Egress,ipv6Egress,legs,udp,metrics,receipt,errors");
  ensure(sample.version === 1 && sample.region === "lhr"); integer(sample.startedAtMs, 9_007_199_254_710_991); integer(sample.durationMs, 30000);
  ensure(typeof sample.ipv4Egress === "boolean" && typeof sample.ipv6Egress === "boolean");
  ensure(Array.isArray(sample.errors) && sample.errors.length <= 4); sample.errors.forEach(e => { ensure(e !== null); error(e); });
  ensure(Array.isArray(sample.legs) && sample.legs.length <= 5); const ids = new Set<NetworkLegId>();
  for (const l of sample.legs) {
    exact(l, "id,status,startOffsetUs,durationUs,bytes,error"); ensure(Object.hasOwn(sizes,l.id) && !ids.has(l.id)); ids.add(l.id); status(l.status); error(l.error);
    integer(l.startOffsetUs); integer(l.durationUs,timeouts[l.id]); integer(l.bytes,sizes[l.id]); ensure(l.startOffsetUs+l.durationUs <= sample.durationMs*1000);
    if (l.status === "succeeded") ensure(l.bytes === sizes[l.id] && l.error === null);
    if (l.status === "skipped_budget") ensure(l.bytes === 0 && l.durationUs === 0);
  }
  const u = sample.udp; exact(u,"status,startOffsetUs,durationUs,sentUs,echoes,error"); status(u.status); error(u.error); integer(u.startOffsetUs); integer(u.durationUs,3_000_000); ensure(u.startOffsetUs+u.durationUs <= sample.durationMs*1000);
  ensure(Array.isArray(u.sentUs) && u.sentUs.length <= 20); ensure(Array.isArray(u.echoes) && u.echoes.length <= u.sentUs.length);
  u.sentUs.forEach((t,i) => { integer(t,u.durationUs); if (i) ensure(t > u.sentUs[i-1]!); }); const sequences = new Set<number>();
  u.echoes.forEach((e,i) => { exact(e,"sequence,receivedUs"); integer(e.sequence,u.sentUs.length-1); integer(e.receivedUs,u.durationUs); ensure(!sequences.has(e.sequence) && e.receivedUs >= u.sentUs[e.sequence]!); sequences.add(e.sequence); if (i) ensure(e.receivedUs >= u.echoes[i-1]!.receivedUs); });
  if (u.status === "succeeded") ensure(u.echoes.length > 0); if (u.status === "skipped_budget") ensure(u.sentUs.length === 0);
  exact(sample.metrics,"downloadKbps,uploadKbps,medianRttUs,p90RttUs,jitterUs,lossBps"); const derived = deriveNetworkMetrics(sample);
  for (const k of Object.keys(derived) as (keyof NetworkMetrics)[]) ensure(sample.metrics[k] === derived[k]);
  if (sample.receipt !== null) {
    const r = sample.receipt; exact(r,"version,challengeDigest,expiresAtSec,region,legs,udpEchoes,mac"); ensure(r.version === 1 && r.region === "lhr");
    ensure(typeof r.challengeDigest === "string" && /^sha256:[0-9a-f]{64}$/u.test(r.challengeDigest)); ensure(typeof r.mac === "string" && /^[0-9a-f]{64}$/u.test(r.mac)); integer(r.expiresAtSec,0xffffffff); integer(r.udpEchoes,64);
    ensure(Array.isArray(r.legs) && r.legs.length <= 5); const seen = new Set<NetworkLegId>();
    for (const l of r.legs) { exact(l,"id,bytes,durationUs,complete"); ensure(Object.hasOwn(sizes,l.id) && !seen.has(l.id)); seen.add(l.id); integer(l.bytes,sizes[l.id]); integer(l.durationUs,30_000_000); ensure(typeof l.complete === "boolean"); }
    for (const l of sample.legs.filter(l => l.status === "succeeded")) ensure(r.legs.some(v => v.id === l.id && v.complete && v.bytes === l.bytes));
    ensure(r.udpEchoes >= u.echoes.length);
  }
  return structuredClone(sample);
}
