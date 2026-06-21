# Slipway Runtime Acurast Fetch Example

Adapted from Acurast's `app-fetch` example. This version boots
`@proof-computer/slipway-runtime`, fetches a price payload, posts a webhook
payload, and writes a Slipway runtime log. It does not call Acurast host
allowlisting; that requires deployment-owner `_acu.*` DNS proofs.

The example is source-only in this repository. It is not included in the npm
package tarball.

This example is complete for the current no-spend package docs baseline. The
next package-cleanup boundary is Turn 6 factory-token product-flow alignment,
not additional selected Acurast example ports.
