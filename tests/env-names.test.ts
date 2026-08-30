import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_LISKOV_CORE_URL,
  DEFAULT_LISKOV_SECRETS_URL,
  LEGACY_LISKOV_BOOTSTRAP_ENV,
  LEGACY_LOCKBOX_BOOTSTRAP_ENV,
  LISKOV_BOOTSTRAP_ENV,
  LISKOV_BOOTSTRAP_ENV_NAMES,
  LOCKBOX_BOOTSTRAP_ENV,
  LOCKBOX_BOOTSTRAP_ENV_NAMES,
  liskovSignedBootstrapUrls,
  readLockboxRuntimeConfig,
  readSlipwayRuntimeEnvConfig
} from "../src/index.js";

const POLICY_DIGEST = "1".repeat(64);

function slipwayBootstrap(url: string): string {
  return JSON.stringify({ v: 1, u: url, a: "app", p: POLICY_DIGEST, d: "42" });
}

function lockboxBootstrap(url: string): string {
  return JSON.stringify({
    v: 1,
    u: url,
    a: "app",
    g: "grant-1",
    p: POLICY_DIGEST,
    d: "42",
    s: ["api-token"]
  });
}

describe("compiled-in core URL default", () => {
  // BKLG-20260829-t4rp slice 6: the console hostname is an operator-facing name
  // that is moving to a different origin. A deployed job cannot be re-pointed
  // cheaply, so the compiled-in default must name the fleet-only hostname.
  it("names the fleet hostname, not the operator console", () => {
    assert.equal(DEFAULT_LISKOV_CORE_URL, "https://runtime.liskov.proof.computer");
    const url = new URL(DEFAULT_LISKOV_CORE_URL);
    assert.equal(url.protocol, "https:");
    assert.equal(url.host, "runtime.liskov.proof.computer");
    assert.equal(url.search, "");
    assert.equal(url.hash, "");
  });

  it("is the last resort behind every documented override", () => {
    assert.equal(liskovSignedBootstrapUrls({ env: {} }).coreUrl, DEFAULT_LISKOV_CORE_URL);
    assert.equal(
      liskovSignedBootstrapUrls({ coreUrl: "https://from-option.test", env: {} }).coreUrl,
      "https://from-option.test"
    );
    assert.equal(
      liskovSignedBootstrapUrls({
        env: {
          PROOF_LISKOV_CORE_URL: "https://from-liskov-core-url.test",
          PROOF_SLIPWAY_URL: "https://from-slipway-url.test"
        }
      }).coreUrl,
      "https://from-liskov-core-url.test"
    );
    assert.equal(
      liskovSignedBootstrapUrls({ env: { PROOF_SLIPWAY_URL: "https://from-slipway-url.test" } })
        .coreUrl,
      "https://from-slipway-url.test"
    );
  });

  it("leaves the secrets host alone", () => {
    assert.equal(DEFAULT_LISKOV_SECRETS_URL, "https://secrets.liskov.proof.computer");
  });
});

describe("LISKOV_ environment name aliases", () => {
  // BKLG-20260829-m8kd step 1: readers prefer the LISKOV_ name and fall back to
  // the legacy one. Nothing emits the new names yet, so this is a no-op.
  it("orders the bootstrap names new-first", () => {
    assert.deepEqual(LISKOV_BOOTSTRAP_ENV_NAMES, ["LISKOV_BOOTSTRAP", "PROOF_SLIPWAY_BOOTSTRAP"]);
    assert.deepEqual(LOCKBOX_BOOTSTRAP_ENV_NAMES, [
      "LISKOV_LOCKBOX_BOOTSTRAP",
      "PROOF_LOCKBOX_BOOTSTRAP"
    ]);
  });

  it("never aliases BRIDGE_SOCKET, which belongs to Acurast", () => {
    for (const name of [...LISKOV_BOOTSTRAP_ENV_NAMES, ...LOCKBOX_BOOTSTRAP_ENV_NAMES]) {
      assert.notEqual(name, "BRIDGE_SOCKET");
    }
  });

  it("prefers LISKOV_BOOTSTRAP over the legacy bootstrap name", () => {
    const config = readSlipwayRuntimeEnvConfig({
      env: {
        [LISKOV_BOOTSTRAP_ENV]: slipwayBootstrap("https://new.test"),
        [LEGACY_LISKOV_BOOTSTRAP_ENV]: slipwayBootstrap("https://legacy.test")
      }
    });
    assert.equal(config?.slipwayUrl, "https://new.test");
  });

  it("still reads the legacy bootstrap name on its own", () => {
    const config = readSlipwayRuntimeEnvConfig({
      env: { [LEGACY_LISKOV_BOOTSTRAP_ENV]: slipwayBootstrap("https://legacy.test") }
    });
    assert.equal(config?.slipwayUrl, "https://legacy.test");
    assert.equal(readSlipwayRuntimeEnvConfig({ env: {} }), undefined);
  });

  it("prefers LISKOV_LOCKBOX_BOOTSTRAP over the legacy lockbox name", () => {
    const config = readLockboxRuntimeConfig({
      env: {
        [LOCKBOX_BOOTSTRAP_ENV]: lockboxBootstrap("https://new-lockbox.test"),
        [LEGACY_LOCKBOX_BOOTSTRAP_ENV]: lockboxBootstrap("https://legacy-lockbox.test")
      }
    });
    assert.equal(config?.lockboxUrl, "https://new-lockbox.test");
  });

  it("still reads the legacy lockbox name on its own", () => {
    const config = readLockboxRuntimeConfig({
      env: { [LEGACY_LOCKBOX_BOOTSTRAP_ENV]: lockboxBootstrap("https://legacy-lockbox.test") }
    });
    assert.equal(config?.lockboxUrl, "https://legacy-lockbox.test");
    assert.equal(readLockboxRuntimeConfig({ env: {} }), undefined);
  });

  it("reads the new names from the Acurast on-chain environment channel too", () => {
    // The setEnvironment handoff reaches the SDK through globalThis.environment,
    // not process.env; the alias has to hold on every channel a reader uses.
    const config = readSlipwayRuntimeEnvConfig({
      env: {},
      environment: (name) =>
        name === LISKOV_BOOTSTRAP_ENV ? slipwayBootstrap("https://from-chain.test") : undefined
    });
    assert.equal(config?.slipwayUrl, "https://from-chain.test");
  });
});
