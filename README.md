# @proof-computer/liskov-runtime

Job-side TypeScript runtime SDK for PROOF Applications that run on Acurast and
are bootstrapped by Liskov.

This package is the code that a job imports before its Application starts. It
is not a Liskov server SDK, deployment tool, control-plane client, wallet
library, or executor library. It runs inside the customer job's Acurast
runtime and provides the default Liskov boot path:

- Acurast environment and `_STD_` lookup.
- Acurast runtime identity, signing, and decrypt helpers.
- Liskov runtime-env fetch and refresh.
- Lockbox-backed runtime secrets.
- Built-in encrypted Liskov logging.
- Bounded Liskov runtime diagnostics and health events.
- Runtime readiness/status and test hooks.

## Install

The first supported dependency source is the public GitHub release tag:

```json
{
  "dependencies": {
    "@proof-computer/liskov-runtime": "github:proof-computer/liskov-runtime-js#v0.3.24"
  }
}
```

npmjs publication is a separate release step and is not required for the
initial runtime cutover.

The package tarball intentionally contains only `dist`, `README.md`,
`SECURITY.md`, and package metadata. Example source and tests stay in the
repository.

Runtime v0.3.21 opts Liskov-owned POST requests into the server response tunnel
used by Acurast processors that omit successful `httpPOST` response bodies. The
adapter unwraps the original 2xx status and JSON before bootstrap, Lockbox, or
Blackbox callers see it; ordinary fetch transports and servers that do not
recognize the opt-in header retain their existing behavior.

Runtime v0.3.22 adds identity-bound v2 diagnostics and a terminal application
boundary. `handle.diagnostics.report(...)` sends ordinary signed events, while
`handle.diagnostics.fatal(...)` is first-call-wins, closes health and logging,
and makes one bounded signed attempt before the caller terminates. Applications
can install `installLiskovRuntimeProcessFailureHandlers(...)`, attach the handle
immediately after bootstrap, and choose an explicit `"continue"` or `"exit"`
policy for unhandled rejections. Bootstrap failures after identity resolution
are reported even when bootstrap never returns a handle.

Runtime v0.3.23 treats each process boot within an Acurast registration as a
distinct runtime instance. The SDK creates and signs one runtime-bootstrap
nonce per process and reuses it across HTTP retries. New backends return that
nonce as `runtimeInstanceId`, which the SDK binds into signed
`proof.liskov.runtime-diagnostic.v3` events; older responses remain supported
through the v2 diagnostic fallback.

Runtime v0.3.24 makes the canonical Application UID authoritative for new
first-party runtime sessions while preserving the legacy Application ID in
every compatibility surface. Runtime bootstrap v2 carries both identifiers;
signed Runtime Environment v2, Lockbox request/response/encrypted-payload v2,
Blackbox config v2, and runtime diagnostics v4 bind them where applicable. A
UID-bearing request fails closed on a missing UID, binding mismatch, or
protocol downgrade; v1-v3 contracts remain available for previously published
jobs.

## Minimal Entrypoint

Use `bootstrapSlipwayRuntime()` before importing Application code:

```ts
import { bootstrapSlipwayRuntime } from "@proof-computer/liskov-runtime";

const runtime = await bootstrapSlipwayRuntime({
  component: "worker",
  revision: process.env.APP_REVISION
});

try {
  await runtime.log("app.boot");
  await runtime.whenReady();
  await import("./app.js");
} finally {
  await runtime.flush();
  runtime.stop();
}
```

`whenReady()` is a fail-fast check, not a long polling loop. It resolves with
the current status when every required capability is ready, and throws
`SlipwayRuntimeNotReadyError` with the current status when a required
capability is pending, failed, or blocked.

## Runtime Handle

`bootstrapSlipwayRuntime()` returns:

```ts
interface BootstrapSlipwayRuntimeHandle {
  readonly home: string;
  readonly env: {
    get(name: string): string | undefined;
    require(name: string): string;
  };
  status(): SlipwayRuntimeStatus;
  whenReady(): Promise<SlipwayRuntimeStatus>;
  log(
    event: string,
    details?: Record<string, unknown>,
    options?: { severity?: "debug" | "info" | "warn" | "error"; labels?: Record<string, string> }
  ): Promise<void>;
  flush(): Promise<{ ok: boolean; state: string; flushed: number; pending: number; dropped: number; message?: string }>;
  refreshNow(): Promise<SlipwayRuntimeEnvLoadResult | undefined>;
  stop(): void;
}
```

Additional readback fields are present for diagnostics and tests:
`runtimeEnv`, `lockbox`, and `runtimeHealth`. Application code should normally
use `env`, `status`, `whenReady`, `log`, `flush`, `refreshNow`, and `stop`.

`stop()` is synchronous and idempotent for the current handle shape. It cancels
runtime-env refresh, runtime-health timers, and background secret retries. Call
`flush()` first when a one-shot job needs to give logging a final chance.

## Bootstrap Options

The top-level options are intentionally small and testable:

```ts
await bootstrapSlipwayRuntime({
  appId: "application-id",
  component: "worker",
  revision: "git-or-artifact-revision",
  home: "/runtime/.slipway",
  secrets: { mode: "required" },
  logging: { mode: "background", earlyBufferMaxRecords: 100 },
  runtimeHealth: { intervalMs: 30_000, initialDelayMs: 30_000 },
  diagnostics: (event) => console.error(JSON.stringify(event))
});
```

Common options:

- `appId`, `component`, `revision`: metadata added to status, diagnostics, and
  logging records where available.
- `home`: explicit state root. Defaults to `SLIPWAY_HOME`, then
  `$HOME/.slipway`, then `/tmp/slipway`.
- `secrets.mode`: `required`, `background`, or `off`.
- `secrets.retry`: background retry budget. Defaults are
  `initialDelayMs=0`, `intervalMs=5000`, `maxElapsedMs=60000`, and
  `maxAttempts=12`.
- `logging.mode`: `required`, `background`, or `off`. The default is
  `background`.
- `logging.earlyBufferMaxRecords`: in-memory log records to keep before
  logging config is available. Default: `100`.
- `logging.spoolMode`: `auto`, `disk`, or `memory`.
- `logging.spoolDir`: override the Blackbox spool directory.
- `logging.timeoutMs`: network timeout for logging writes.
- `logging.onError`: observes logging failures without breaking the runtime
  wrapper.
- `diagnostics`: local callback for redacted runtime diagnostics.
- `diagnosticSendTimeoutMs`, `diagnosticRemoteBackoffMs`: bounds for remote
  runtime-diagnostic delivery.
- `runtimeHealth`: optional interval/initial-delay/send-timeout overrides for
  `runtime.health` diagnostics.

Test hooks:

- `env`: process-env replacement.
- `std`: Acurast `_STD_` replacement.
- `environment`: Acurast `environment(name)` replacement.
- `identityProvider`: fake identity/sign/decrypt provider.
- `fetchImpl`: fake network implementation.
- `nowMs`, `randomBytes`: deterministic clock and nonce/digest inputs.
- `setTimeoutImpl`, `clearTimeoutImpl`: deterministic timer harness.

## Environment Lookup

Runtime values are resolved from:

1. The supplied `options.env`, or `process.env`.
2. Acurast `_STD_.env`.
3. Acurast `environment(name)`.

Use the runtime accessor after bootstrap because runtime-env and secrets may
install values during startup:

```ts
const webhookUrl = runtime.env.require("WEBHOOK_URL");
const optionalMode = runtime.env.get("FEATURE_MODE") ?? "default";
```

`require()` throws `Liskov runtime env <NAME> is required` when the value is
absent.

## Liskov Runtime Env

Liskov jobs receive compact public bootstrap config through
`PROOF_SLIPWAY_BOOTSTRAP`:

```json
{
  "v": 1,
  "u": "https://slipway.example",
  "a": "application-id",
  "p": "64-character-policy-digest",
  "d": "deployment-id",
  "x": {
    "t": "diagnostics-token",
    "h": { "i": 30000, "d": 30000, "to": 1500 }
  }
}
```

Expanded keys such as `slipwayUrl`, `applicationId`, `policyDigest`,
`deploymentId`, `diagnostics.token`, and `diagnostics.health` are also
accepted.

When the bootstrap is present, the runtime signs a
`proof.slipway.runtime-env-request.v1` request and POSTs it to
`/api/jobs/runtime-env`. The response must bind the same application id,
policy digest, deployment id, job id, and processor id. Returned values are
installed into runtime env before Lockbox secrets are requested.

`refreshNow()` forces an immediate runtime-env refresh when
`PROOF_SLIPWAY_BOOTSTRAP` exists, then performs one deduped secrets attempt if
background secrets are still pending, then refreshes logging. The current v0
periodic runtime-env refresh is internal; Applications should use
`refreshNow()` when they need an explicit reload.

## Secrets

Lockbox secrets are a built-in Liskov runtime capability. Jobs receive compact
secret bootstrap config through `PROOF_LOCKBOX_BOOTSTRAP`:

```json
{
  "v": 1,
  "u": "https://secrets.liskov.proof.computer",
  "a": "application-id",
  "g": "grant-id",
  "p": "64-character-policy-digest",
  "d": "deployment-id",
  "s": ["secret-id"]
}
```

Legacy expanded `PROOF_LOCKBOX_*` values remain supported for older jobs, but
compact bootstrap is the preferred Acurast shape.

### Required

Required mode is the default when Lockbox bootstrap exists:

```ts
const runtime = await bootstrapSlipwayRuntime({
  secrets: { mode: "required" }
});
```

Bootstrap waits for Lockbox, verifies the encrypted payload, installs returned
env/file secrets, and fails closed if the request is rejected or the payload
does not verify.

### Background

Background mode is for Applications that can boot in a locked or degraded mode:

```ts
const runtime = await bootstrapSlipwayRuntime({
  secrets: {
    mode: "background",
    retry: {
      initialDelayMs: 0,
      intervalMs: 5_000,
      maxElapsedMs: 60_000,
      maxAttempts: 12
    }
  }
});
```

Bootstrap returns before the first Lockbox request. The secrets capability
reports `pending`, `degraded`, `failed`, or `ready`, but it is not a readiness
blocker because it is not required. `refreshNow()` performs one immediate
attempt while the retry budget is still open. `stop()` cancels scheduled
background retries.

### Off

Use `secrets: { mode: "off" }` for jobs that intentionally ignore Lockbox
bootstrap values.

### Installation Rules

Env secrets are installed into runtime env by name. An authenticated signed
bootstrap is authoritative for its current job and replaces ambient values
left by a reused runtime. Legacy env-provided bootstrap keeps existing values
unless `PROOF_LOCKBOX_OVERWRITE_ENV=true` is set. When a signed grant owns
`blackbox-log-config`, logging buffers until that current config is installed;
it never attaches an older job's ambient sink config.

File secrets require `PROOF_LOCKBOX_FILE_BASE_DIR` or the compact bootstrap
file-base field. File targets are written below that directory with mode
`0600`; path traversal outside the base directory is rejected.

## Logging

Blackbox is presented to Applications as Liskov logging. Application code
should call `runtime.log()` instead of constructing a Blackbox writer:

```ts
await runtime.log("worker.tick", { processed: 12 }, {
  severity: "info",
  labels: { component: "worker" }
});

const result = await runtime.flush();
```

The runtime validates and attaches logging after runtime-env and Lockbox
installation. If a log is written before logging config is available, the
runtime keeps it in the early in-memory buffer. When config appears later,
`refreshNow()` or the next `log()` drains the buffer into encrypted Blackbox
records.

The default `background` logging mode never blocks readiness. Use
`logging: { mode: "required" }` only when missing or invalid logging config
must make the Application non-ready. Use `logging: { mode: "off" }` to drop
runtime logs intentionally.

Accepted config shapes:

- Pre-bound sink: `sinkId` + `jobId` + `writeUrl` + `dek`, with an optional
  `resumeUrl`. This remains the preferred production provisioning mode. Older
  configs derive `/resume` only when `writeUrl` ends in `/events`.
- Factory token: `factoryToken` + `baseUrl` + `dek`. The writer self-registers
  the job-bound sink on first flush and receives the same write, resume, and
  canonical-chain contract as a pre-bound sink.

Both shapes can be supplied as `BLACKBOX_LOG_CONFIG` JSON or expanded
`BLACKBOX_*` env values. Records are encrypted locally before upload and
posted batches contain no plaintext log messages. Disk spool state defaults to:

```text
$SLIPWAY_HOME/logging/spool
```

Every config defaults to the `hkdf-sha256-ed25519-v1` writer derivation; newly
provisioned configs also record that value explicitly as `writerKeyDerivation`.
Every invocation therefore derives the same Ed25519 request writer from the
protected 32-byte log DEK: HKDF-SHA256 uses UTF-8 salt
`proof.liskov.blackbox.writer-key.v1`, UTF-8 info `Ed25519`, and a 32-byte
output interpreted as an Ed25519 seed. This keeps sibling invocations on one
canonical append chain while separating the writer key from record encryption.
Low-level callers can still supply an explicit signer for an unmarked config;
the managed runtime does not use that compatibility override.

When disk spool is unavailable in `auto` mode, the writer falls back to memory.
Before constructing a new batch, the runtime resolves the server's canonical
head in either provisioning mode. If another writer advances the sink between
that resolution and upload, the runtime consumes the conflict response's head
and retries the encrypted pending batch with at most three sequence rebases.
The encrypted records themselves are unchanged. Invalid or inconsistent
resume, success, or conflict heads fail closed through `logging.onError` while
the spool remains intact. Some Acurast runtimes omit the body of a successful
`201` callback: after an accepted write the SDK resolves the signed server head,
and after a created factory registration it performs one idempotent replay.
Both paths keep the server authoritative and leave the spool intact if the
follow-up cannot prove the committed position.
Unknown config shapes report through diagnostics and `logging.onError`; they do
not silently degrade to a no-op.

## Diagnostics And Health

Runtime diagnostics are best-effort and bounded. When
Liskov bootstrap is available and the runtime can authenticate with either a
diagnostics token or the Acurast runtime identity provider, diagnostics are
POSTed to `/api/jobs/runtime-diagnostics` as
`proof.slipway.runtime-diagnostic.v1`. Signed-bootstrap jobs do not need a
diagnostics token; the request carries a runtime signature, job id, and
processor address when identity is available.

Useful stages include:

- `runtime.start`
- `slipway.runtime_env.identity`
- `slipway.runtime_env.signed`
- `slipway.runtime_env.fetch`
- `slipway.runtime_env.response`
- `slipway.runtime_env.applied`
- `lockbox.secret_request.identity`
- `lockbox.secret_request.signed`
- `lockbox.secret_request.fetch`
- `lockbox.secret_request.response`
- `lockbox.secret_request.decrypted`
- `lockbox.secret_request.installed`
- `lockbox.secret_request.retry`
- `slipway.logging.attach`
- `slipway.logging.write`
- `slipway.logging.buffer`
- `runtime.health`

Local diagnostic callbacks and remote diagnostic sends use a 1.5 second
default timeout. Remote diagnostic failures pause further remote diagnostic
attempts for 30 seconds so startup, runtime-env, and Lockbox flows cannot be
blocked by observability.

Health diagnostics start under the same authentication rule as other remote
diagnostics. Defaults are a 30 second initial delay and 30 second interval.
Compact bootstrap health fields `x.h.i`, `x.h.d`, and `x.h.to`, or the
matching expanded fields, override interval, initial delay, and send timeout.

Diagnostics redact string fields that look like tokens, secrets, private keys,
signatures, passwords, or authorization values. Count and boolean presence
fields are retained.

## Readiness And Status

Use `status()` for redacted readback:

```ts
const status = runtime.status();

if (!status.ready) {
  console.error(status.blockers);
}
```

Status shape:

```ts
interface SlipwayRuntimeStatus {
  ok: boolean;
  ready: boolean;
  home: string;
  applicationId?: string;
  deploymentId?: string;
  revision?: string;
  blockers: Array<{ capability: string; code: string; message: string }>;
  capabilities: {
    runtimeEnv: CapabilityStatus;
    secrets: CapabilityStatus;
    logging: CapabilityStatus;
    diagnostics: CapabilityStatus;
    switchboard: CapabilityStatus;
  };
}
```

Capability states are `off`, `pending`, `ready`, `degraded`, `failed`, or
`blocked`. A capability blocks readiness only when `required=true` and
`state !== "ready"`.

Current v0 behavior:

- `runtimeEnv` is required when `PROOF_SLIPWAY_BOOTSTRAP` is present.
- `secrets` is required only in required mode.
- `logging` is required only in required mode.
- `diagnostics` is non-fatal and reports ready once the local emitter exists.
- `switchboard` is reported as off by this package; Switchboard readiness lives
  in `@proof-computer/slipway-switchboard`.

## Acurast Host Allowlisting

The runtime does not call `_STD_.net.addAllowedHostnames()` implicitly.
Acurast only admits hosts to the unrestricted outbound whitelist when the
deployment owner has configured the required forward and reverse `_acu.*` DNS
TXT proofs for each hostname/IP. Until Liskov owns and documents those records
for a host, the runtime must make ordinary network requests and report any
network failure through diagnostics.

## Testing Fakes

The runtime is designed to be tested without live Acurast spend:

```ts
const env: Record<string, string | undefined> = {
  PROOF_SLIPWAY_BOOTSTRAP: JSON.stringify({
    v: 1,
    u: "https://slipway.test",
    a: "app",
    p: "1".repeat(64),
    d: "42"
  })
};

const runtime = await bootstrapSlipwayRuntime({
  env,
  identityProvider: fakeIdentityProvider,
  fetchImpl: fakeFetch,
  nowMs: () => 1_000,
  logging: { spoolMode: "memory" },
  setTimeoutImpl: fakeSetTimeout,
  clearTimeoutImpl: fakeClearTimeout
});
```

Use `logging.spoolMode: "memory"` in deterministic unit tests. Use
`secrets.mode: "background"` plus fake timers to prove pending/degraded/ready
state without sleeping. Use the local `diagnostics` callback for redacted event
assertions.

The repository tests prove runtime-env, required/background/off secrets,
factory-token logging, early buffer drain, config refresh, diagnostics,
health, DNS-gated no-allowlist behavior, and source-only Acurast examples
without artifact pins or live deployment.

## Examples

Source-only example ports live under `examples/`:

- `examples/acurast-env-vars`: reads runtime-env values, posts only a redacted
  env summary, and writes through `runtime.log()`.
- `examples/acurast-fetch`: fetches a price payload, posts a webhook payload,
  and writes a Liskov runtime log.

The Switchboard webserver example lives in
`public_repos/slipway-switchboard-js/examples/acurast-webserver` because
Switchboard ingress is optional and stays in a separate adapter package.

These examples are complete for the current no-spend documentation baseline.
The next package-cleanup boundary is server-side Turn 6 factory-token product
flow alignment, not more selected Acurast example ports.

## Security Boundaries

- Do not put Liskov server control tokens in runtime env or diagnostics.
- Do not put plaintext runtime secrets in Liskov runtime-env.
- Runtime secrets must come from Lockbox and be encrypted to the job response
  encryption key.
- HTTPS is required for Liskov, Lockbox, and Blackbox URLs outside local/test
  hosts unless an explicit insecure override is supplied.
- Signed runtime-env and Lockbox v2 requests bind Application UID,
  compatibility application id, policy digest, deployment id, job id,
  processor id, nonce, and expiry.
- Lockbox encrypted payloads must bind payload digest, request/response fields,
  and requested secret ids before installation.
- File-target secrets are written only under the configured base directory.
- `@proof-computer/liskov-runtime` runs inside the job TEE. Liskov control
  plane services, Lockbox, Blackbox, and CLI/server workflows are separate
  off-TEE systems.
- This package does not make Switchboard a required dependency. Use
  `@proof-computer/slipway-switchboard` only for Liskov-managed Switchboard
  ingress jobs.

See `SECURITY.md` for the release checklist.

## Package Gates

Run the release gates before tagging:

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
pnpm pack:dry-run
```
