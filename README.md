# @proof-computer/slipway-js

Job-side TypeScript runtime SDK for PROOF Applications that run on Acurast and
are bootstrapped by Slipway.

`slipway-js` is not a Slipway server SDK, control-plane client, deployment
tool, or wallet/executor library. It is only the small runtime helper that a
job imports before application code starts.

## Install

The first supported dependency source is the public GitHub release tag:

```json
{
  "dependencies": {
    "@proof-computer/slipway-js": "github:proof-computer/slipway-js#v0.1.1"
  }
}
```

npmjs publication is a separate release step and is not required for the
initial runtime cutover.

## Runtime Model

Slipway jobs use three channels:

- Acurast environment carries compact public bootstrap values:
  `PROOF_SLIPWAY_BOOTSTRAP` and, when secrets are needed,
  `PROOF_LOCKBOX_BOOTSTRAP`.
- Slipway serves non-secret runtime configuration through signed
  `proof.slipway.runtime-env-request.v1` requests to
  `POST /api/jobs/runtime-env`.
- Lockbox serves secrets through signed
  `proof.lockbox.job-secret-request.v1` requests to
  `POST /api/jobs/secret-requests`, returning payloads encrypted to the
  Acurast job encryption key.

`bootstrapSlipwayRuntime()` applies Slipway runtime env first, then Lockbox
secrets. It returns handles for runtime-env refresh and runtime health
diagnostics.

```ts
import { bootstrapSlipwayRuntime } from "@proof-computer/slipway-js";

const runtime = await bootstrapSlipwayRuntime();
try {
  await import("./app.js");
} finally {
  runtime.stop();
}
```

The package is Application-agnostic. It does not import Slipway server code and
does not assume validator-specific env names.

## Bootstrap Inputs

`PROOF_SLIPWAY_BOOTSTRAP` is JSON. Compact keys are preferred on Acurast:

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

`PROOF_LOCKBOX_BOOTSTRAP` is JSON:

```json
{
  "v": 1,
  "u": "https://lockbox.example",
  "a": "application-id",
  "g": "grant-id",
  "p": "64-character-policy-digest",
  "d": "deployment-id",
  "s": ["secret-id"]
}
```

Legacy expanded `PROOF_LOCKBOX_*` env values remain supported for older jobs,
but compact bootstrap is the preferred Acurast shape.

## Diagnostics

Runtime diagnostics are best-effort and bounded. Local diagnostic callbacks and
remote Slipway diagnostic POSTs use a 1.5 second default timeout. Remote
diagnostic failures pause further remote diagnostic attempts for 30 seconds so
startup, runtime-env, and Lockbox flows cannot be blocked by observability.

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
- `runtime.health`

`runtime.start` includes generic runtime capability and bootstrap presence
attributes. Diagnostics redact string fields that look like tokens, secrets,
private keys, signatures, passwords, or authorization values; count and
boolean presence fields are retained.

## Blackbox Logging

The package exports a legacy-compatible encrypted Blackbox logger for runtime
logs that arrive through Lockbox as `BLACKBOX_LOG_CONFIG` or the expanded
`BLACKBOX_*` env set. Records are encrypted locally before upload and posted
batches contain no plaintext log messages.

```ts
import { createBlackboxRemoteLogger } from "@proof-computer/slipway-js";

const log = createBlackboxRemoteLogger();
await log("runtime.ready", { revision: "runtime-revision-1" });
```

The logger signs batch writes with the Acurast Ed25519 runtime signer.

## Security Boundaries

- Do not put Slipway server control tokens in runtime env or diagnostics.
- Do not put plaintext runtime secrets in Slipway runtime-env.
- Runtime secrets must come from Lockbox and be encrypted to the job response
  encryption key.
- HTTPS is required for Slipway, Lockbox, and Blackbox URLs outside local/test
  hosts unless an explicit insecure override is supplied.
- Signed runtime-env and Lockbox requests bind application id, policy digest,
  deployment id, job id, processor id, nonce, and expiry.
- Lockbox encrypted payloads must bind payload digest, request/response fields,
  and requested secret ids before installation.
- File-target secrets are written only under the configured base directory.

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
