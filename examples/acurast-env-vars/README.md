# Slipway Runtime Acurast Env Vars Example

Adapted from Acurast's `app-env-vars` example. This version boots
`@proof-computer/slipway-runtime`, reads `WEBHOOK_URL` and
`MY_SECRET_ENV_VAR` through the runtime env accessor, posts only a redacted
presence/digest summary, and writes through `runtime.log()`.

The example is source-only in this repository. It is not included in the npm
package tarball.

This example is complete for the current no-spend package docs baseline. The
next package-cleanup boundary is Turn 6 factory-token product-flow alignment,
not additional selected Acurast example ports.
