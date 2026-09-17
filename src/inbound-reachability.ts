/** Versioned, bounded inbound reachability evidence. Rust contracts own this schema. */
export type InboundFamily = "v4" | "v6";
export type InboundVerdict =
  | "reachable"
  | "connect_timeout"
  | "connect_refused"
  | "connect_failed"
  | "no_signature"
  | "prober_no_egress";
export interface InboundFamilyVerdict {
  version: 1;
  challengeDigest: string;
  region: "lhr";
  family: InboundFamily;
  verdict: InboundVerdict;
  connectMs: number;
  nonce: string;
  signature: string | null;
  mac: string;
}
export interface InboundReachabilityV1 {
  version: 1;
  startedAtMs: number;
  durationMs: number;
  families: InboundFamilyVerdict[];
}
const FAMILIES: InboundFamily[] = ["v4", "v6"];
const VERDICTS: InboundVerdict[] = ["reachable", "connect_timeout", "connect_refused", "connect_failed", "no_signature", "prober_no_egress"];
const CONNECT_TIMEOUT_MS = 2_000;
const BUDGET_MS = 4_000;
const NONCE_BYTES = 32;
const SIGNATURE_BYTES = 64;
function ensure(condition: unknown): asserts condition { if (!condition) throw new Error("invalid inbound reachability v1"); }
function exact(value: unknown, keys: string): void { ensure(value !== null && typeof value === "object" && !Array.isArray(value)); ensure(Object.keys(value).sort().join(",") === keys.split(",").sort().join(",")); }
function integer(n: unknown, max = Number.MAX_SAFE_INTEGER): void { ensure(typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && n <= max); }
function lowerHex(value: unknown, bytes: number): void { ensure(typeof value === "string" && value.length === bytes * 2 && /^[0-9a-f]*$/u.test(value)); }
/**
 * The device assembles this block from verdicts the prober signed one at a
 * time, so it may carry fewer families than were asked for — but never a
 * verdict it wrote itself, and never one claiming more than it says.
 */
export function normalizeInboundReachability(block: InboundReachabilityV1): InboundReachabilityV1 {
  exact(block, "version,startedAtMs,durationMs,families");
  ensure(block.version === 1);
  integer(block.startedAtMs, 9_007_199_254_710_991);
  integer(block.durationMs, BUDGET_MS);
  ensure(Array.isArray(block.families) && block.families.length >= 1 && block.families.length <= 2);
  const seen = new Set<InboundFamily>();
  for (const verdict of block.families) {
    exact(verdict, "version,challengeDigest,region,family,verdict,connectMs,nonce,signature,mac");
    ensure(verdict.version === 1 && verdict.region === "lhr");
    ensure(FAMILIES.includes(verdict.family) && !seen.has(verdict.family));
    seen.add(verdict.family);
    ensure(VERDICTS.includes(verdict.verdict));
    // One probe, one challenge: every verdict must name the same one.
    ensure(verdict.challengeDigest === block.families[0]!.challengeDigest);
    ensure(typeof verdict.challengeDigest === "string" && /^sha256:[0-9a-f]{64}$/u.test(verdict.challengeDigest));
    lowerHex(verdict.nonce, NONCE_BYTES);
    lowerHex(verdict.mac, 32);
    integer(verdict.connectMs, CONNECT_TIMEOUT_MS);
    // A signature exists exactly when the prober got a path and a reply.
    if (verdict.verdict === "reachable") {
      ensure(typeof verdict.signature === "string" && verdict.signature.startsWith("0x"));
      lowerHex(verdict.signature.slice(2), SIGNATURE_BYTES);
    } else {
      ensure(verdict.signature === null);
    }
    // A refused connection is immediate; a timeout consumed the whole wait.
    if (verdict.verdict === "connect_timeout") ensure(verdict.connectMs === CONNECT_TIMEOUT_MS);
    if (verdict.verdict === "prober_no_egress") ensure(verdict.connectMs === 0);
  }
  return structuredClone(block);
}
