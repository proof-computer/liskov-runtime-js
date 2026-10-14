import { Buffer } from "node:buffer";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { canonicalJson } from "./shared.js";

/**
 * ADR-0234 traversal codec for the JS runtime.
 *
 * This slice handles the signed envelope and the capability decision only.
 * Acurast JS has no source-proven raw socket, listener, or gateway API, and
 * Node dgram success is not that proof. The supported operation set stays empty:
 * a valid grant reports unsupported primitives and does not send.
 */

export const TRAVERSAL_CAPABILITY_DOMAIN = "proof.liskov.network-traversal-capability.v1";
export const TRAVERSAL_BLOCK_MAX_BYTES = 8 * 1024;
export const TRAVERSAL_ENVELOPE_MAX_BYTES = 16 * 1024;
/** Native signature field reserved by the owner envelope check. */
export const TRAVERSAL_SIGNATURE_RESERVE_BYTES = 148;
export const TRAVERSAL_CAPABILITY_MAX_MS = 120_000;
export const TRAVERSAL_EXPERIMENT_MAX_MS = 30_000;
export const TRAVERSAL_CLEANUP_RESERVE_MS = 5_000;

const CAPABILITY_MAC_DOMAIN = Buffer.from(`${TRAVERSAL_CAPABILITY_DOMAIN}\0`, "utf8");
const SAFE_INTEGER = 9_007_199_254_740_991;

const MODES = ["observe", "mapping", "pair"] as const;
const OPERATIONS = [
  "discover_gateway",
  "observe_mapping",
  "observe_filtering",
  "baseline_tcp",
  "baseline_udp",
  "register_endpoint",
  "map_pcp",
  "map_nat_pmp",
  "map_upnp",
  "pair_direct_udp",
  "pair_relay_control"
] as const;
const ROUTER_PROTOCOLS = ["pcp", "nat_pmp", "upnp_igd"] as const;
const ROLES = ["first", "second"] as const;
const STAGES = [
  "discovery",
  "baseline",
  "mapping_create",
  "mapping_verify",
  "mapping_cleanup",
  "endpoint_registration",
  "direct",
  "relay_control",
  "mapping_behaviour",
  "filtering_behaviour"
] as const;
const METHODS = ["unassisted", "udp_mapping", "udp_filtering", "pcp", "nat_pmp", "upnp_igd", "pair"] as const;
const TRANSPORTS = ["tcp", "udp", "router_control", "relay_control"] as const;
const FAMILIES = ["v4", "v6"] as const;
const AUTHORITIES = [
  "external_path",
  "device_reported_router",
  "helper_observed_peer",
  "prober_observed_registration",
  "prober_observed_behaviour"
] as const;
const OUTCOMES = [
  "succeeded",
  "failed",
  "unsupported_topology",
  "unsupported_runtime_api",
  "unsupported_safe_ownership",
  "unsupported_finite_lease",
  "unverifiable_endpoint",
  "skipped_budget",
  "not_started",
  "direct_not_established_in_test",
  "one_way_peer",
  "peer_absent",
  "wrong_peer",
  "late_join",
  "candidate_rebinding",
  "budget_exhausted",
  "prober_no_egress",
  "creation_outcome_unknown",
  "expiry_unknown",
  "endpoint_independent",
  "address_dependent",
  "address_and_port_dependent",
  "unknown"
] as const;
const ERROR_CLASSES = [
  "timeout",
  "connect_failed",
  "invalid_response",
  "rate_limited",
  "token_refused",
  "budget_exhausted",
  "mapping_conflict",
  "lease_refused",
  "cleanup_failed",
  "prober_unavailable",
  "peer_unavailable"
] as const;
const CLEANUPS = [
  "confirmed_deleted",
  "delete_failed",
  "lease_expiry_pending",
  "not_created",
  "creation_outcome_unknown",
  "expiry_unknown"
] as const;
const UNSUPPORTED_WITHOUT_PROOF = new Set([
  "unsupported_topology",
  "unsupported_runtime_api",
  "unsupported_safe_ownership",
  "skipped_budget",
  "not_started"
]);

const EXTERNAL_PATH_DOMAIN = "proof.liskov.network-traversal-external-path.v1";
const ROUTER_RESPONSE_DOMAIN = "proof.liskov.network-traversal-device-router.v1";
const DIRECT_PEER_DOMAIN = "proof.liskov.network-traversal-helper-direct.v1";
const RELAY_PEER_DOMAIN = "proof.liskov.network-traversal-helper-relay.v1";
const BEHAVIOUR_DOMAIN = "proof.liskov.network-traversal-observed-behaviour.v1";
const REGISTRATION_DOMAIN = "proof.liskov.network-traversal-endpoint-registration.v1";

export type TraversalMode = (typeof MODES)[number];
export type TraversalOperation = (typeof OPERATIONS)[number];
export type TraversalPrimitive = "socket" | "listener" | "gateway";
export type TraversalRefusalCode =
  | "Malformed"
  | "UnknownVersion"
  | "WrongDomain"
  | "InvalidBinding"
  | "InvalidScope"
  | "InvalidBudget"
  | "InvalidDeadline"
  | "InvalidConsent"
  | "InvalidPair"
  | "InvalidProof"
  | "Oversize"
  | "NotYetValid"
  | "Expired"
  | "InsufficientTime"
  | "InvalidMac"
  | "NonCanonical";

export class TraversalRefusalError extends Error {
  constructor(readonly code: TraversalRefusalCode) {
    super(code);
    this.name = "TraversalRefusalError";
  }
}

export interface TraversalBudgets {
  experimentMs: number;
  cleanupReserveMs: number;
  outboundDatagrams: number;
  datagramBytes: number;
  controlRequests: number;
  externalDialbacks: number;
  relayBytesPerDirection: number;
  concurrentMappingLeases: number;
  cleanupDatagrams: number;
  cleanupControlRequests: number;
}

export interface TraversalMappingConsent {
  consentReference: string;
  processorAllowlistDigest: string;
  exclusiveReservationDigest: string;
  priorUncertaintyResolved: boolean;
  finiteExpiryVerified: boolean;
  expiresAtMs: number;
  protocols: string[];
  requestedLeaseSec: number;
  maximumLeaseSec: number;
}

export interface TraversalParticipant {
  role: "first" | "second";
  launchInstanceDigest: string;
  claimAuthorityDigest: string;
  runtimeSigner: string;
}

export interface TraversalPair {
  pairId: string;
  expiresAtMs: number;
  participants: [TraversalParticipant, TraversalParticipant];
}

export interface TraversalDescriptorV1 {
  version: 1;
  runId: string;
  mode: TraversalMode;
  claimAuthorityDigest: string;
  profileVersion: string;
  catalogVersion: string;
  artifactDigest: string;
  helperVersion: string;
  helperDigest: string;
  endpointSetRevision: string;
  issuedAtMs: number;
  expiresAtMs: number;
  deadlineMs: number;
  operations: TraversalOperation[];
  budgets: TraversalBudgets;
  mapping: TraversalMappingConsent | null;
  pair: TraversalPair | null;
  participantRole: "first" | "second" | null;
}

export interface TraversalPhaseV1 {
  stage: string;
  method: string;
  transport: string;
  family: string;
  authority: string;
  outcome: string;
  elapsedMs: number;
  grantedLeaseSec: number | null;
  cleanup: string | null;
  protocolError: number | null;
  errorClass: string | null;
  proofDigest: string | null;
}

export interface NetworkTraversalV1 {
  version: 1;
  descriptorDigest: string;
  runId: string;
  mode: TraversalMode;
  startedAtMs: number;
  durationMs: number;
  phases: TraversalPhaseV1[];
  proofs: unknown[];
}

export interface InjectedTraversalTransport {
  nowMs(): number;
  cancelled(): boolean;
  offeredPayload?: Uint8Array;
  send(payload: Uint8Array): void;
}

export interface JsTraversalSettlement {
  effects: "none" | "unsupported";
  reason:
    | "unsupported-primitives"
    | "unknown-grant"
    | "misbound"
    | "expired"
    | "not-yet-valid"
    | "invalid-grant"
    | "cancelled"
    | "deadline"
    | "payload-cap"
    | "coverage-grant";
  routerMutationAuthorized: false;
  networkTraversal?: NetworkTraversalV1;
  primitives: TraversalPrimitive[];
}

const OPERATION_PRIMITIVE: Record<TraversalOperation, { primitive: TraversalPrimitive; stage: string; method: string; transport: string; authority: string }> = {
  discover_gateway: { primitive: "gateway", stage: "discovery", method: "pcp", transport: "router_control", authority: "device_reported_router" },
  observe_mapping: { primitive: "socket", stage: "mapping_behaviour", method: "udp_mapping", transport: "udp", authority: "prober_observed_behaviour" },
  observe_filtering: { primitive: "socket", stage: "filtering_behaviour", method: "udp_filtering", transport: "udp", authority: "prober_observed_behaviour" },
  baseline_tcp: { primitive: "listener", stage: "baseline", method: "unassisted", transport: "tcp", authority: "external_path" },
  baseline_udp: { primitive: "listener", stage: "baseline", method: "unassisted", transport: "udp", authority: "external_path" },
  register_endpoint: { primitive: "listener", stage: "endpoint_registration", method: "pair", transport: "udp", authority: "prober_observed_registration" },
  map_pcp: { primitive: "gateway", stage: "discovery", method: "pcp", transport: "router_control", authority: "device_reported_router" },
  map_nat_pmp: { primitive: "gateway", stage: "discovery", method: "nat_pmp", transport: "router_control", authority: "device_reported_router" },
  map_upnp: { primitive: "gateway", stage: "discovery", method: "upnp_igd", transport: "router_control", authority: "device_reported_router" },
  pair_direct_udp: { primitive: "socket", stage: "direct", method: "pair", transport: "udp", authority: "helper_observed_peer" },
  pair_relay_control: { primitive: "socket", stage: "relay_control", method: "pair", transport: "relay_control", authority: "helper_observed_peer" }
};

function refuse(code: TraversalRefusalCode): never {
  throw new TraversalRefusalError(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function keysOf(value: Record<string, unknown>): string[] {
  return Object.keys(value);
}

function rejectUnknown(value: Record<string, unknown>, allowed: readonly string[], code: TraversalRefusalCode = "Malformed"): void {
  for (const key of keysOf(value)) {
    if (!allowed.includes(key)) refuse(code);
  }
}

function requireKey(value: Record<string, unknown>, key: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(value, key)) refuse("Malformed");
  return value[key];
}

function text(value: string): boolean {
  return value.length > 0 && value.length <= 128 && [...value].every((char) => {
    const code = char.charCodeAt(0);
    return code >= 0x21 && code <= 0x7e;
  });
}

function lowerHex(value: string, bytes: number): boolean {
  return value.length === bytes * 2 && /^[0-9a-f]+$/u.test(value);
}

function digest(value: string): boolean {
  return value.startsWith("sha256:") && lowerHex(value.slice(7), 32);
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], code: TraversalRefusalCode): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) refuse(code);
  return value as T;
}

function safeUint(value: unknown, code: TraversalRefusalCode): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > SAFE_INTEGER) refuse(code);
  return Number(value);
}

function boundedInt(value: unknown, max: number, code: TraversalRefusalCode): number {
  const number = safeUint(value, code);
  if (number > max) refuse(code);
  return number;
}

function sha256Text(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

function strictlyIncreasing<T extends string>(values: readonly T[], order: readonly T[]): boolean {
  let previous = -1;
  for (const value of values) {
    const rank = order.indexOf(value);
    if (rank <= previous) return false;
    previous = rank;
  }
  return true;
}

function nullable<T>(value: unknown, parse: (value: unknown) => T, code: TraversalRefusalCode): T | null {
  if (value === null) return null;
  return parse(value);
}

function proofDomain(authority: string, stage: string, method: string, transport: string): string {
  if (
    authority === "external_path"
    && (stage === "baseline" || stage === "mapping_verify")
    && (transport === "tcp" || transport === "udp")
    && ((stage === "baseline" && method === "unassisted") || (stage === "mapping_verify" && (method === "pcp" || method === "nat_pmp" || method === "upnp_igd")))
  ) return EXTERNAL_PATH_DOMAIN;
  if (
    authority === "device_reported_router"
    && (stage === "discovery" || stage === "mapping_create" || stage === "mapping_cleanup")
    && transport === "router_control"
    && (method === "pcp" || method === "nat_pmp" || method === "upnp_igd")
  ) return ROUTER_RESPONSE_DOMAIN;
  if (authority === "helper_observed_peer" && stage === "direct" && transport === "udp" && method === "pair") return DIRECT_PEER_DOMAIN;
  if (authority === "helper_observed_peer" && stage === "relay_control" && transport === "relay_control" && method === "pair") return RELAY_PEER_DOMAIN;
  if (authority === "prober_observed_registration" && stage === "endpoint_registration" && transport === "udp" && method === "pair") return REGISTRATION_DOMAIN;
  if (
    authority === "prober_observed_behaviour"
    && transport === "udp"
    && ((stage === "mapping_behaviour" && method === "udp_mapping") || (stage === "filtering_behaviour" && method === "udp_filtering"))
  ) return BEHAVIOUR_DOMAIN;
  return refuse("InvalidProof");
}

function normalizeBudgets(value: unknown): TraversalBudgets {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, [
    "experimentMs", "cleanupReserveMs", "outboundDatagrams", "datagramBytes", "controlRequests",
    "externalDialbacks", "relayBytesPerDirection", "concurrentMappingLeases", "cleanupDatagrams", "cleanupControlRequests"
  ]);
  const budgets: TraversalBudgets = {
    experimentMs: safeUint(requireKey(value, "experimentMs"), "InvalidBudget"),
    cleanupReserveMs: safeUint(requireKey(value, "cleanupReserveMs"), "InvalidBudget"),
    outboundDatagrams: boundedInt(requireKey(value, "outboundDatagrams"), 65535, "InvalidBudget"),
    datagramBytes: boundedInt(requireKey(value, "datagramBytes"), 65535, "InvalidBudget"),
    controlRequests: boundedInt(requireKey(value, "controlRequests"), 65535, "InvalidBudget"),
    externalDialbacks: boundedInt(requireKey(value, "externalDialbacks"), 65535, "InvalidBudget"),
    relayBytesPerDirection: safeUint(requireKey(value, "relayBytesPerDirection"), "InvalidBudget"),
    concurrentMappingLeases: boundedInt(requireKey(value, "concurrentMappingLeases"), 255, "InvalidBudget"),
    cleanupDatagrams: boundedInt(requireKey(value, "cleanupDatagrams"), 65535, "InvalidBudget"),
    cleanupControlRequests: boundedInt(requireKey(value, "cleanupControlRequests"), 65535, "InvalidBudget")
  };
  if (
    budgets.experimentMs === 0
    || budgets.experimentMs > TRAVERSAL_EXPERIMENT_MAX_MS
    || budgets.cleanupReserveMs === 0
    || budgets.cleanupReserveMs > TRAVERSAL_CLEANUP_RESERVE_MS
    || budgets.cleanupReserveMs >= budgets.experimentMs
    || budgets.outboundDatagrams > 64
    || budgets.datagramBytes > 512
    || budgets.controlRequests > 12
    || budgets.externalDialbacks > 4
    || budgets.relayBytesPerDirection > 65_536
    || budgets.concurrentMappingLeases > 2
    || budgets.cleanupDatagrams > budgets.outboundDatagrams
    || budgets.cleanupControlRequests > budgets.controlRequests
    || (budgets.outboundDatagrams > 0 && budgets.datagramBytes === 0)
  ) refuse("InvalidBudget");
  return budgets;
}

function normalizeConsent(value: unknown): TraversalMappingConsent {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, [
    "consentReference", "processorAllowlistDigest", "exclusiveReservationDigest", "priorUncertaintyResolved",
    "finiteExpiryVerified", "expiresAtMs", "protocols", "requestedLeaseSec", "maximumLeaseSec"
  ]);
  const protocolsValue = requireKey(value, "protocols");
  if (!Array.isArray(protocolsValue)) refuse("Malformed");
  const protocols = protocolsValue.map((protocol) => oneOf(protocol, ROUTER_PROTOCOLS, "InvalidConsent"));
  const prior = requireKey(value, "priorUncertaintyResolved");
  const finite = requireKey(value, "finiteExpiryVerified");
  if (typeof prior !== "boolean" || typeof finite !== "boolean") refuse("Malformed");
  const consentReference = requireKey(value, "consentReference");
  if (typeof consentReference !== "string") refuse("Malformed");
  return {
    consentReference,
    processorAllowlistDigest: requireDigest(requireKey(value, "processorAllowlistDigest"), "InvalidConsent"),
    exclusiveReservationDigest: requireDigest(requireKey(value, "exclusiveReservationDigest"), "InvalidConsent"),
    priorUncertaintyResolved: prior,
    finiteExpiryVerified: finite,
    expiresAtMs: safeUint(requireKey(value, "expiresAtMs"), "InvalidConsent"),
    protocols,
    requestedLeaseSec: boundedInt(requireKey(value, "requestedLeaseSec"), 65535, "InvalidConsent"),
    maximumLeaseSec: boundedInt(requireKey(value, "maximumLeaseSec"), 65535, "InvalidConsent")
  };
}

function requireDigest(value: unknown, code: TraversalRefusalCode): string {
  if (typeof value !== "string" || !digest(value)) refuse(code);
  return value;
}

function requireText(value: unknown, code: TraversalRefusalCode): string {
  if (typeof value !== "string" || !text(value)) refuse(code);
  return value;
}

function normalizeParticipant(value: unknown): TraversalParticipant {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, ["role", "launchInstanceDigest", "claimAuthorityDigest", "runtimeSigner"]);
  const runtimeSigner = requireKey(value, "runtimeSigner");
  if (typeof runtimeSigner !== "string" || !runtimeSigner.startsWith("0x") || !lowerHex(runtimeSigner.slice(2), 32)) {
    refuse("InvalidPair");
  }
  return {
    role: oneOf(requireKey(value, "role"), ROLES, "InvalidPair"),
    launchInstanceDigest: requireDigest(requireKey(value, "launchInstanceDigest"), "InvalidPair"),
    claimAuthorityDigest: requireDigest(requireKey(value, "claimAuthorityDigest"), "InvalidPair"),
    runtimeSigner
  };
}

function normalizePair(value: unknown): TraversalPair {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, ["pairId", "expiresAtMs", "participants"]);
  const pairId = requireKey(value, "pairId");
  if (typeof pairId !== "string" || !lowerHex(pairId, 16)) refuse("InvalidPair");
  const participants = requireKey(value, "participants");
  if (!Array.isArray(participants) || participants.length !== 2) refuse("InvalidPair");
  return {
    pairId,
    expiresAtMs: safeUint(requireKey(value, "expiresAtMs"), "InvalidPair"),
    participants: [normalizeParticipant(participants[0]), normalizeParticipant(participants[1])]
  };
}

export function normalizeTraversalDescriptor(value: unknown): TraversalDescriptorV1 {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, [
    "version", "runId", "mode", "claimAuthorityDigest", "profileVersion", "catalogVersion", "artifactDigest",
    "helperVersion", "helperDigest", "endpointSetRevision", "issuedAtMs", "expiresAtMs", "deadlineMs",
    "operations", "budgets", "mapping", "pair", "participantRole"
  ]);
  if (requireKey(value, "version") !== 1) refuse("UnknownVersion");
  const runId = requireKey(value, "runId");
  if (typeof runId !== "string" || !lowerHex(runId, 16)) refuse("InvalidBinding");
  const mode = oneOf(requireKey(value, "mode"), MODES, "Malformed");
  const operationsValue = requireKey(value, "operations");
  if (!Array.isArray(operationsValue)) refuse("Malformed");
  const operations = operationsValue.map((operation) => oneOf(operation, OPERATIONS, "InvalidScope"));
  const descriptor: TraversalDescriptorV1 = {
    version: 1,
    runId,
    mode,
    claimAuthorityDigest: requireDigest(requireKey(value, "claimAuthorityDigest"), "InvalidBinding"),
    profileVersion: requireText(requireKey(value, "profileVersion"), "InvalidBinding"),
    catalogVersion: requireText(requireKey(value, "catalogVersion"), "InvalidBinding"),
    artifactDigest: requireDigest(requireKey(value, "artifactDigest"), "InvalidBinding"),
    helperVersion: requireText(requireKey(value, "helperVersion"), "InvalidBinding"),
    helperDigest: requireDigest(requireKey(value, "helperDigest"), "InvalidBinding"),
    endpointSetRevision: requireText(requireKey(value, "endpointSetRevision"), "InvalidBinding"),
    issuedAtMs: safeUint(requireKey(value, "issuedAtMs"), "InvalidDeadline"),
    expiresAtMs: safeUint(requireKey(value, "expiresAtMs"), "InvalidDeadline"),
    deadlineMs: safeUint(requireKey(value, "deadlineMs"), "InvalidDeadline"),
    operations,
    budgets: normalizeBudgets(requireKey(value, "budgets")),
    mapping: requireKey(value, "mapping") === null ? null : normalizeConsent(requireKey(value, "mapping")),
    pair: requireKey(value, "pair") === null ? null : normalizePair(requireKey(value, "pair")),
    participantRole: nullable(requireKey(value, "participantRole"), (role) => oneOf(role, ROLES, "InvalidPair"), "InvalidPair")
  };
  validateDescriptor(descriptor);
  if (canonicalBytes(descriptor).length > TRAVERSAL_BLOCK_MAX_BYTES) refuse("Oversize");
  return descriptor;
}

function validateDescriptor(descriptor: TraversalDescriptorV1): void {
  const lifetime = descriptor.expiresAtMs - descriptor.issuedAtMs;
  if (
    descriptor.expiresAtMs <= descriptor.issuedAtMs
    || lifetime > TRAVERSAL_CAPABILITY_MAX_MS
    || descriptor.deadlineMs <= descriptor.issuedAtMs
    || descriptor.deadlineMs > descriptor.expiresAtMs
  ) refuse("InvalidDeadline");
  if (descriptor.operations.length === 0 || descriptor.operations.length > 11 || !strictlyIncreasing(descriptor.operations, OPERATIONS)) {
    refuse("InvalidScope");
  }
  for (const operation of descriptor.operations) {
    const mappingOp = operation === "map_pcp" || operation === "map_nat_pmp" || operation === "map_upnp";
    const pairOp = operation === "register_endpoint" || operation === "pair_direct_udp" || operation === "pair_relay_control";
    const observeOp = !mappingOp && !pairOp;
    const allowed = mappingOp
      ? descriptor.mode === "mapping"
      : pairOp
        ? descriptor.mode === "pair"
        : observeOp && descriptor.mode !== "pair";
    if (!allowed) refuse("InvalidScope");
  }
  if (descriptor.mode === "mapping") {
    if (descriptor.mapping === null) refuse("InvalidConsent");
    const consent = descriptor.mapping;
    const mutates: Record<string, TraversalOperation> = { pcp: "map_pcp", nat_pmp: "map_nat_pmp", upnp_igd: "map_upnp" };
    if (
      !text(consent.consentReference)
      || !consent.priorUncertaintyResolved
      || !consent.finiteExpiryVerified
      || consent.expiresAtMs < descriptor.expiresAtMs
      || consent.requestedLeaseSec !== 60
      || consent.maximumLeaseSec < 60
      || consent.maximumLeaseSec > 120
      || consent.protocols.length === 0
      || consent.protocols.length > 3
      || !strictlyIncreasing(consent.protocols, ROUTER_PROTOCOLS)
      || descriptor.budgets.concurrentMappingLeases === 0
      || consent.protocols.some((protocol) => !descriptor.operations.includes(mutates[protocol]!))
      || ROUTER_PROTOCOLS.some((protocol) => descriptor.operations.includes(mutates[protocol]!) && !consent.protocols.includes(protocol))
      || descriptor.budgets.cleanupDatagrams < descriptor.budgets.concurrentMappingLeases
      || descriptor.budgets.cleanupControlRequests < descriptor.budgets.concurrentMappingLeases
    ) refuse("InvalidConsent");
  } else if (descriptor.mapping !== null) {
    refuse("InvalidScope");
  } else if (
    descriptor.budgets.concurrentMappingLeases !== 0
    || descriptor.budgets.cleanupDatagrams !== 0
    || descriptor.budgets.cleanupControlRequests !== 0
  ) {
    refuse("InvalidScope");
  }
  if (descriptor.mode === "pair") {
    if (descriptor.pair === null || descriptor.participantRole === null) refuse("InvalidPair");
    const [first, second] = descriptor.pair.participants;
    if (
      descriptor.pair.expiresAtMs !== descriptor.expiresAtMs
      || first.role !== "first"
      || second.role !== "second"
      || first.launchInstanceDigest === second.launchInstanceDigest
      || first.claimAuthorityDigest === second.claimAuthorityDigest
      || descriptor.pair.participants.find((participant) => participant.role === descriptor.participantRole)?.claimAuthorityDigest
        !== descriptor.claimAuthorityDigest
    ) refuse("InvalidPair");
  } else if (descriptor.pair !== null || descriptor.participantRole !== null) {
    refuse("InvalidScope");
  }
  if (descriptor.mode !== "pair" && descriptor.budgets.relayBytesPerDirection !== 0) refuse("InvalidScope");
}

export function traversalDescriptorDigest(descriptor: TraversalDescriptorV1): string {
  return sha256Text(canonicalJson(descriptor));
}

function normalizeTranscript(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, [
    "version", "domain", "descriptorDigest", "runId", "pairId", "participantRole", "authority", "stage", "method",
    "transport", "family", "challenge", "peerChallenge", "expiresAtMs", "outcome", "elapsedMs", "grantedLeaseSec",
    "cleanup", "protocolError", "errorClass"
  ]);
  if (requireKey(value, "version") !== 1) refuse("UnknownVersion");
  const authority = oneOf(requireKey(value, "authority"), AUTHORITIES, "InvalidProof");
  const stage = oneOf(requireKey(value, "stage"), STAGES, "InvalidProof");
  const method = oneOf(requireKey(value, "method"), METHODS, "InvalidProof");
  const transport = oneOf(requireKey(value, "transport"), TRANSPORTS, "InvalidProof");
  const domain = requireKey(value, "domain");
  if (domain !== proofDomain(authority, stage, method, transport)) refuse("WrongDomain");
  const challenge = requireKey(value, "challenge");
  const runId = requireKey(value, "runId");
  if (typeof challenge !== "string" || !lowerHex(challenge, 32) || typeof runId !== "string" || !lowerHex(runId, 16)) {
    refuse("InvalidBinding");
  }
  return {
    version: 1,
    domain,
    descriptorDigest: requireDigest(requireKey(value, "descriptorDigest"), "InvalidBinding"),
    runId,
    pairId: nullable(requireKey(value, "pairId"), (item) => {
      if (typeof item !== "string" || !lowerHex(item, 16)) refuse("InvalidPair");
      return item;
    }, "InvalidPair"),
    participantRole: nullable(requireKey(value, "participantRole"), (role) => oneOf(role, ROLES, "InvalidPair"), "InvalidPair"),
    authority,
    stage,
    method,
    transport,
    family: oneOf(requireKey(value, "family"), FAMILIES, "InvalidProof"),
    challenge,
    peerChallenge: nullable(requireKey(value, "peerChallenge"), (item) => {
      if (typeof item !== "string" || !lowerHex(item, 32)) refuse("InvalidProof");
      return item;
    }, "InvalidProof"),
    expiresAtMs: safeUint(requireKey(value, "expiresAtMs"), "InvalidBinding"),
    outcome: oneOf(requireKey(value, "outcome"), OUTCOMES, "InvalidProof"),
    elapsedMs: boundedInt(requireKey(value, "elapsedMs"), TRAVERSAL_EXPERIMENT_MAX_MS, "InvalidBinding"),
    grantedLeaseSec: nullable(requireKey(value, "grantedLeaseSec"), (item) => boundedInt(item, 65535, "InvalidProof"), "InvalidProof"),
    cleanup: nullable(requireKey(value, "cleanup"), (item) => oneOf(item, CLEANUPS, "InvalidProof"), "InvalidProof"),
    protocolError: nullable(requireKey(value, "protocolError"), (item) => boundedInt(item, 65535, "InvalidProof"), "InvalidProof"),
    errorClass: nullable(requireKey(value, "errorClass"), (item) => oneOf(item, ERROR_CLASSES, "InvalidProof"), "InvalidProof")
  };
}

function normalizeProof(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) refuse("Malformed");
  const kind = requireKey(value, "kind");
  if (kind === "prober_receipt") {
    rejectUnknown(value, ["kind", "receipt"]);
    const receipt = requireKey(value, "receipt");
    if (!isRecord(receipt)) refuse("Malformed");
    rejectUnknown(receipt, ["version", "transcript", "deviceSignature", "mac"]);
    if (requireKey(receipt, "version") !== 1) refuse("UnknownVersion");
    const deviceSignature = requireKey(receipt, "deviceSignature");
    const mac = requireKey(receipt, "mac");
    if (typeof deviceSignature !== "string" || !deviceSignature.startsWith("0x") || !lowerHex(deviceSignature.slice(2), 64)) {
      refuse("InvalidProof");
    }
    if (typeof mac !== "string" || !lowerHex(mac, 32)) refuse("InvalidMac");
    return { kind, receipt: { version: 1, transcript: normalizeTranscript(requireKey(receipt, "transcript")), deviceSignature, mac } };
  }
  if (kind === "device_signature") {
    rejectUnknown(value, ["kind", "transcript", "signature"]);
    const signature = requireKey(value, "signature");
    if (typeof signature !== "string" || !signature.startsWith("0x") || !lowerHex(signature.slice(2), 64)) refuse("InvalidProof");
    const transcript = normalizeTranscript(requireKey(value, "transcript"));
    if (transcript.authority !== "device_reported_router" && transcript.authority !== "helper_observed_peer") refuse("InvalidProof");
    return { kind, transcript, signature };
  }
  refuse("Malformed");
}

function normalizePhase(value: unknown): TraversalPhaseV1 {
  if (!isRecord(value)) refuse("Malformed");
  rejectUnknown(value, [
    "stage", "method", "transport", "family", "authority", "outcome", "elapsedMs", "grantedLeaseSec",
    "cleanup", "protocolError", "errorClass", "proofDigest"
  ]);
  const authority = oneOf(requireKey(value, "authority"), AUTHORITIES, "InvalidProof");
  const stage = oneOf(requireKey(value, "stage"), STAGES, "InvalidProof");
  const method = oneOf(requireKey(value, "method"), METHODS, "InvalidProof");
  const transport = oneOf(requireKey(value, "transport"), TRANSPORTS, "InvalidProof");
  proofDomain(authority, stage, method, transport);
  return {
    stage,
    method,
    transport,
    family: oneOf(requireKey(value, "family"), FAMILIES, "InvalidProof"),
    authority,
    outcome: oneOf(requireKey(value, "outcome"), OUTCOMES, "InvalidProof"),
    elapsedMs: safeUint(requireKey(value, "elapsedMs"), "InvalidDeadline"),
    grantedLeaseSec: nullable(requireKey(value, "grantedLeaseSec"), (item) => boundedInt(item, 65535, "InvalidProof"), "InvalidProof"),
    cleanup: nullable(requireKey(value, "cleanup"), (item) => oneOf(item, CLEANUPS, "InvalidProof"), "InvalidProof"),
    protocolError: nullable(requireKey(value, "protocolError"), (item) => boundedInt(item, 65535, "InvalidProof"), "InvalidProof"),
    errorClass: nullable(requireKey(value, "errorClass"), (item) => oneOf(item, ERROR_CLASSES, "InvalidProof"), "InvalidProof"),
    proofDigest: nullable(requireKey(value, "proofDigest"), (item) => requireDigest(item, "InvalidProof"), "InvalidProof")
  };
}

export function normalizeNetworkTraversal(value: unknown): NetworkTraversalV1 {
  if (!isRecord(value)) refuse("Malformed");
  const size = canonicalBytes(value).length;
  if (size > TRAVERSAL_BLOCK_MAX_BYTES) refuse("Oversize");
  rejectUnknown(value, ["version", "descriptorDigest", "runId", "mode", "startedAtMs", "durationMs", "phases", "proofs"]);
  if (requireKey(value, "version") !== 1) refuse("UnknownVersion");
  const runId = requireKey(value, "runId");
  if (typeof runId !== "string" || !lowerHex(runId, 16)) refuse("InvalidBinding");
  const startedAtMs = safeUint(requireKey(value, "startedAtMs"), "InvalidBinding");
  const durationMs = safeUint(requireKey(value, "durationMs"), "InvalidBinding");
  if (durationMs > TRAVERSAL_EXPERIMENT_MAX_MS || startedAtMs + durationMs > SAFE_INTEGER) refuse("InvalidBinding");
  const phasesValue = requireKey(value, "phases");
  const proofsValue = requireKey(value, "proofs");
  if (!Array.isArray(phasesValue) || !Array.isArray(proofsValue)) refuse("Malformed");
  if (phasesValue.length === 0 || phasesValue.length > 16 || proofsValue.length > 8) refuse("InvalidBinding");
  const mode = oneOf(requireKey(value, "mode"), MODES, "Malformed");
  const phases = phasesValue.map(normalizePhase);
  const proofs = proofsValue.map(normalizeProof);
  const block: NetworkTraversalV1 = {
    version: 1,
    descriptorDigest: requireDigest(requireKey(value, "descriptorDigest"), "InvalidBinding"),
    runId,
    mode,
    startedAtMs,
    durationMs,
    phases,
    proofs
  };
  const used = new Set<string>();
  for (const proof of proofs) {
    const transcript = proofRecordTranscript(proof);
    if (transcript.descriptorDigest !== block.descriptorDigest || transcript.runId !== block.runId) refuse("InvalidBinding");
  }
  for (const phase of phases) {
    if (phase.elapsedMs > durationMs) refuse("InvalidDeadline");
    if (!stageAllowed(mode, phase.stage)) refuse("InvalidScope");
    if (phase.outcome === "succeeded" && phase.errorClass !== null) refuse("InvalidProof");
    if (phase.outcome === "failed" && phase.errorClass === null) refuse("InvalidProof");
    if (phase.proofDigest === null) {
      if (
        !UNSUPPORTED_WITHOUT_PROOF.has(phase.outcome)
        || phase.grantedLeaseSec !== null
        || phase.cleanup !== null
        || phase.protocolError !== null
      ) refuse("InvalidProof");
    } else if (used.has(phase.proofDigest)) {
      refuse("InvalidProof");
    } else {
      used.add(phase.proofDigest);
      const proof = proofs.find((item) => sha256Text(canonicalJson(item)) === phase.proofDigest);
      if (proof === undefined || !phaseMatches(phase, proofRecordTranscript(proof))) refuse("InvalidProof");
    }
  }
  if (used.size !== proofs.length) refuse("InvalidProof");
  if (canonicalBytes(block).length > TRAVERSAL_BLOCK_MAX_BYTES) refuse("Oversize");
  return block;
}

function proofRecordTranscript(proof: Record<string, unknown>): Record<string, unknown> {
  if (proof.kind === "prober_receipt") {
    const receipt = proof.receipt as Record<string, unknown>;
    return receipt.transcript as Record<string, unknown>;
  }
  return proof.transcript as Record<string, unknown>;
}

function phaseMatches(phase: TraversalPhaseV1, transcript: Record<string, unknown>): boolean {
  return phase.stage === transcript.stage
    && phase.method === transcript.method
    && phase.transport === transcript.transport
    && phase.family === transcript.family
    && phase.authority === transcript.authority
    && phase.outcome === transcript.outcome
    && phase.elapsedMs === transcript.elapsedMs
    && phase.grantedLeaseSec === transcript.grantedLeaseSec
    && phase.cleanup === transcript.cleanup
    && phase.protocolError === transcript.protocolError
    && phase.errorClass === transcript.errorClass;
}

function stageAllowed(mode: TraversalMode, stage: string): boolean {
  if (mode === "observe") {
    return !["mapping_create", "mapping_verify", "mapping_cleanup", "direct", "relay_control", "endpoint_registration"].includes(stage);
  }
  if (mode === "mapping") return !["direct", "relay_control", "endpoint_registration"].includes(stage);
  return ["endpoint_registration", "direct", "relay_control"].includes(stage);
}

export function decodeTraversalCapability(bytes: Uint8Array | string, key: Uint8Array, nowMs: number): TraversalDescriptorV1 {
  const encoded = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes);
  if (encoded.length > TRAVERSAL_BLOCK_MAX_BYTES) refuse("Oversize");
  let parsed: unknown;
  try {
    parsed = JSON.parse(encoded.toString("utf8")) as unknown;
  } catch {
    refuse("Malformed");
  }
  if (!isRecord(parsed)) refuse("Malformed");
  rejectUnknown(parsed, ["domain", "descriptor", "mac"]);
  if (requireKey(parsed, "domain") !== TRAVERSAL_CAPABILITY_DOMAIN) refuse("WrongDomain");
  const mac = requireKey(parsed, "mac");
  if (typeof mac !== "string") refuse("Malformed");
  const descriptor = normalizeTraversalDescriptor(requireKey(parsed, "descriptor"));
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) refuse("InvalidDeadline");
  if (nowMs < descriptor.issuedAtMs) refuse("NotYetValid");
  if (nowMs >= descriptor.expiresAtMs) refuse("Expired");
  const capability = { domain: TRAVERSAL_CAPABILITY_DOMAIN, descriptor, mac };
  const canonical = canonicalBytes(capability);
  if (canonical.length !== encoded.length || !timingSafeEqual(canonical, encoded)) refuse("NonCanonical");
  if (key.length !== 32 || !lowerHex(mac, 32)) refuse("InvalidMac");
  const expected = createHmac("sha256", key).update(CAPABILITY_MAC_DOMAIN).update(canonicalBytes(descriptor)).digest();
  const actual = Buffer.from(mac, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) refuse("InvalidMac");
  return descriptor;
}

export function canStartTraversal(
  descriptor: TraversalDescriptorV1,
  nowMs: number,
  jobExpiresAtMs: number,
  deliveryReserveMs: number
): void {
  if (!Number.isSafeInteger(nowMs) || nowMs < descriptor.issuedAtMs) refuse("NotYetValid");
  if (nowMs >= descriptor.expiresAtMs) refuse("Expired");
  if (!Number.isSafeInteger(jobExpiresAtMs) || !Number.isSafeInteger(deliveryReserveMs) || deliveryReserveMs < 0) {
    refuse("InsufficientTime");
  }
  const end = nowMs + descriptor.budgets.experimentMs;
  const delivered = end + deliveryReserveMs;
  if (!Number.isSafeInteger(end) || !Number.isSafeInteger(delivered) || end > descriptor.deadlineMs || delivered > Math.min(descriptor.expiresAtMs, jobExpiresAtMs)) {
    refuse("InsufficientTime");
  }
}

function none(reason: JsTraversalSettlement["reason"]): JsTraversalSettlement {
  return { effects: "none", reason, routerMutationAuthorized: false, primitives: [] };
}

/**
 * Decide what a JS runtime may do with one grant. Traversal grants never call
 * `bandwidthLadder` or `mutateRouter`. Missing primitives become explicit
 * unsupported outcomes, not a failed network attempt. Cancellation, an
 * impossible deadline, and an offered payload over the grant cap stop first
 * and send nothing.
 */
export function settleJsTraversalGrant(input: {
  grant: unknown;
  macKey?: Uint8Array;
  claimAuthorityDigest?: string;
  jobExpiresAtMs: number;
  deliveryReserveMs: number;
  transport: InjectedTraversalTransport;
  bandwidthLadder: () => void;
  mutateRouter: () => void;
}): JsTraversalSettlement {
  // The callbacks are the effect seam. Nothing in this runtime may invoke them:
  // traversal does not run the bandwidth ladder, and no JS grant may mutate a router.
  if (typeof input.bandwidthLadder !== "function" || typeof input.mutateRouter !== "function") return none("invalid-grant");
  if (isCoverageGrant(input.grant)) return none("coverage-grant");
  const encoded = capabilityBytes(input.grant);
  if (encoded === undefined || input.macKey === undefined) return none(encoded === undefined ? "unknown-grant" : "invalid-grant");
  const nowMs = input.transport.nowMs();
  let descriptor: TraversalDescriptorV1;
  try {
    descriptor = decodeTraversalCapability(encoded, input.macKey, nowMs);
  } catch (error) {
    if (!(error instanceof TraversalRefusalError)) throw error;
    if (error.code === "Expired") return none("expired");
    if (error.code === "NotYetValid") return none("not-yet-valid");
    return none("invalid-grant");
  }
  if (input.claimAuthorityDigest === undefined || descriptor.claimAuthorityDigest !== input.claimAuthorityDigest) {
    return none("misbound");
  }
  if (input.transport.cancelled()) return none("cancelled");
  try {
    canStartTraversal(descriptor, nowMs, input.jobExpiresAtMs, input.deliveryReserveMs);
  } catch (error) {
    if (error instanceof TraversalRefusalError && (error.code === "InsufficientTime" || error.code === "Expired" || error.code === "NotYetValid")) {
      return none(error.code === "InsufficientTime" ? "deadline" : error.code === "Expired" ? "expired" : "not-yet-valid");
    }
    throw error;
  }
  const offered = input.transport.offeredPayload;
  if (
    offered !== undefined
    && (offered.byteLength > descriptor.budgets.datagramBytes || offered.byteLength > 512 || offered.byteLength > TRAVERSAL_BLOCK_MAX_BYTES)
  ) {
    return none("payload-cap");
  }
  const primitives = [...new Set(descriptor.operations.map((operation) => OPERATION_PRIMITIVE[operation].primitive))];
  const phases: TraversalPhaseV1[] = descriptor.operations.map((operation) => {
    const template = OPERATION_PRIMITIVE[operation];
    return {
      stage: template.stage,
      method: template.method,
      transport: template.transport,
      family: "v4",
      authority: template.authority,
      outcome: "unsupported_runtime_api",
      elapsedMs: 0,
      grantedLeaseSec: null,
      cleanup: null,
      protocolError: null,
      errorClass: null,
      proofDigest: null
    };
  });
  const networkTraversal = normalizeNetworkTraversal({
    version: 1,
    descriptorDigest: traversalDescriptorDigest(descriptor),
    runId: descriptor.runId,
    mode: descriptor.mode,
    startedAtMs: nowMs,
    durationMs: 0,
    phases,
    proofs: []
  });
  return { effects: "unsupported", reason: "unsupported-primitives", routerMutationAuthorized: false, networkTraversal, primitives };
}

function isCoverageGrant(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return value.kind === "coverage"
    || value.kind === "networkSample"
    || value.domain === "proof.liskov.processor-coverage-result.v1";
}

function capabilityBytes(value: unknown): Uint8Array | string | undefined {
  if (typeof value === "string" || value instanceof Uint8Array) {
    const textValue = typeof value === "string" ? value : Buffer.from(value).toString("utf8");
    try {
      const parsed = JSON.parse(textValue) as unknown;
      if (isRecord(parsed) && parsed.domain === TRAVERSAL_CAPABILITY_DOMAIN) return value;
    } catch {
      return undefined;
    }
    return undefined;
  }
  if (isRecord(value) && value.domain === TRAVERSAL_CAPABILITY_DOMAIN) return canonicalJson(value);
  return undefined;
}
