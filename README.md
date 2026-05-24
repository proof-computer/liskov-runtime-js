# @proof-computer/slipway-js

Private TypeScript runtime SDK for PROOF Application jobs running under
Acurast and bootstrapped by Slipway.

The runtime model has three channels:

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
secrets. It returns a refresh handle for the non-secret runtime env plane.

```ts
import { bootstrapSlipwayRuntime } from "@proof-computer/slipway-js";

const handle = await bootstrapSlipwayRuntime();
try {
  await import("./app.js");
} finally {
  handle.stop();
}
```

The package is Application-agnostic. It does not import Slipway server code,
does not assume validator-specific env names, and accepts dependency injection
for env lookup, `_STD_`, fetch, clocks, randomness, diagnostics, timers, and
file writes.
