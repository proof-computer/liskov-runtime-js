# Security Checklist

Use this checklist before cutting a public
`@proof-computer/liskov-runtime` tag.

## Runtime Authority

- Runtime jobs must not receive Liskov server control tokens.
- Runtime jobs must not receive Lockbox control tokens.
- Runtime jobs sign runtime-env and Lockbox requests with the Acurast
  job-owned Ed25519 signer.
- Signed v2 requests must bind Application UID, compatibility application id,
  policy digest, deployment id, job id, processor id, nonce, and expiry.

## Secret Handling

- Plaintext runtime secrets must not be served through Slipway runtime-env.
- Plaintext runtime secrets must not be emitted in diagnostics or Blackbox log
  batches.
- Lockbox payloads must be encrypted to the job response encryption key.
- Lockbox encrypted payload digest and plaintext digest must be verified before
  installing secrets.
- Lockbox v2 encrypted payloads must verify the canonical response-AAD digest
  and the decrypted Application UID/application-id binding before installation.
- Lockbox plaintext payload fields must match the signed request and response.
- File-target secret writes must stay under the configured base directory and
  use mode `0600`.
- Runtime and CLI state must live under `SLIPWAY_HOME`, defaulting to
  `~/.slipway` when a home directory is available. Blackbox/Lockbox-specific
  home directories must not be promoted as the user-facing model.

## Transport

- Slipway, secrets, and logging runtime URLs must use HTTPS by default.
- HTTP is allowed only for localhost/test hosts or explicit insecure local
  override env.
- Diagnostic POSTs must be bounded and best-effort; failed diagnostic delivery
  must not block runtime-env or Lockbox startup.

## Diagnostics

- Diagnostics may report counts, status codes, revisions, hostnames, component
  names, and boolean capability flags.
- Diagnostics must redact string attributes that look like tokens, secrets,
  private keys, signatures, passwords, or authorization headers.
- `runtime.start` and `runtime.fatal.*` must not expose compact bootstrap payloads or plaintext env
  values.
- V2 diagnostic signatures must cover the normalized job and processor
  identities plus stage, status, sequence, timestamp, component, code, message,
  and attributes. Terminal delivery must remain bounded even when identity,
  signing, or transport hangs.
- V3 diagnostic signatures must additionally bind `runtimeInstanceId` from the
  signed runtime-bootstrap response. Bootstrap transport retries must reuse one
  nonce and signature for the lifetime of the process boot.
- V4 diagnostic signatures must additionally bind the authenticated
  `applicationUid`; a UID-bearing bootstrap response must never downgrade to a
  v2 or v3 diagnostic.
- Slipway logging batches must contain encrypted log records only.

## Package Artifact

- `package.json` must be public-ready: `private: false`, version `0.3.26`, and
  repository metadata pointing at `proof-computer/liskov-runtime-js`.
- The package `files` allowlist must include only `dist`, `README.md`, and
  `SECURITY.md`.
- `npm pack --dry-run --json` must show no source files, tests, local env,
  lockfiles, or generated runtime artifacts.
- CI must pass typecheck, test, build, and package dry-run before a tag is
  pushed.
