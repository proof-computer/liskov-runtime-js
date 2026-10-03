import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_LISKOV_CORE_URL,
  DEFAULT_LISKOV_SECRETS_URL,
  LEGACY_LISKOV_BOOTSTRAP_ENV,
  DEFAULT_LISKOV_BOOTSTRAP_REQUEST_TTL_MS,
  LEGACY_LOCKBOX_BOOTSTRAP_ENV,
  LISKOV_BOOTSTRAP_ENV,
  LISKOV_BOOTSTRAP_ENV_NAMES,
  LISKOV_CORE_URL_ENV,
  LISKOV_HOME_ENV_NAME,
  LOCKBOX_BOOTSTRAP_ENV,
  LOCKBOX_BOOTSTRAP_ENV_NAMES,
  SLIPWAY_HOME_ENV_NAME,
  liskovSignedBootstrapAllowInsecureHttp,
  liskovSignedBootstrapRequestTtlMs,
  liskovSignedBootstrapUrls,
  readLockboxRuntimeConfig,
  readSlipwayRuntimeEnvConfig,
  resolveAcurastRuntimeIdentity,
  resolveSlipwayHome
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
    assert.equal(LISKOV_CORE_URL_ENV, "LISKOV_CORE_URL");
    assert.equal(
      liskovSignedBootstrapUrls({
        env: { LISKOV_CORE_URL: "https://from-liskov-core-url.test" }
      }).coreUrl,
      "https://from-liskov-core-url.test"
    );
  });

  it("no longer reads PROOF_LISKOV_CORE_URL", () => {
    // BKLG-20261002-qihk: the platform emits LISKOV_CORE_URL beside it with the
    // same value, so the legacy name alone resolves the default.
    assert.equal(
      liskovSignedBootstrapUrls({ env: { PROOF_LISKOV_CORE_URL: "https://x.test" } }).coreUrl,
      DEFAULT_LISKOV_CORE_URL
    );
  });

  it("no longer reads PROOF_SLIPWAY_URL", () => {
    // BKLG-20260922-91r7: the legacy core-URL name alone resolves the default.
    assert.equal(
      liskovSignedBootstrapUrls({ env: { PROOF_SLIPWAY_URL: "https://from-slipway-url.test" } })
        .coreUrl,
      DEFAULT_LISKOV_CORE_URL
    );
  });

  it("leaves the secrets host alone", () => {
    assert.equal(DEFAULT_LISKOV_SECRETS_URL, "https://secrets.liskov.proof.computer");
  });

  it("reads no secrets URL or signed-bootstrap tuning from the environment", () => {
    // BKLG-20261002-qihk: these names had no emitter, and the two tuning names
    // exceed Acurast's 32-byte setEnvironment key limit.
    const env = {
      PROOF_LISKOV_SECRETS_URL: "https://from-env-secrets.test",
      PROOF_LISKOV_BOOTSTRAP_ALLOW_INSECURE_HTTP: "true",
      PROOF_LISKOV_BOOTSTRAP_REQUEST_TTL_MS: "5"
    };
    assert.equal(liskovSignedBootstrapUrls({ env }).secretsUrl, DEFAULT_LISKOV_SECRETS_URL);
    assert.equal(liskovSignedBootstrapAllowInsecureHttp({ env }), undefined);
    assert.equal(liskovSignedBootstrapRequestTtlMs({ env }), DEFAULT_LISKOV_BOOTSTRAP_REQUEST_TTL_MS);
    assert.equal(
      liskovSignedBootstrapUrls({ secretsUrl: "https://from-option.test", env }).secretsUrl,
      "https://from-option.test"
    );
    assert.equal(liskovSignedBootstrapAllowInsecureHttp({ allowInsecureHttp: true, env }), true);
    assert.equal(liskovSignedBootstrapRequestTtlMs({ requestTtlMs: 7, env }), 7);
  });
});

describe("LISKOV_ environment name aliases", () => {
  // BKLG-20260922-91r7: the public bootstrap is read only as LISKOV_BOOTSTRAP.
  // BKLG-20261002-qihk: the Lockbox bootstrap is read only as
  // LISKOV_LOCKBOX_BOOTSTRAP.
  it("reads each bootstrap only under its LISKOV_ name", () => {
    assert.deepEqual(LISKOV_BOOTSTRAP_ENV_NAMES, ["LISKOV_BOOTSTRAP"]);
    assert.deepEqual(LOCKBOX_BOOTSTRAP_ENV_NAMES, ["LISKOV_LOCKBOX_BOOTSTRAP"]);
    assert.equal(LEGACY_LOCKBOX_BOOTSTRAP_ENV, "PROOF_LOCKBOX_BOOTSTRAP");
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

  it("ignores the legacy bootstrap name", () => {
    const config = readSlipwayRuntimeEnvConfig({
      env: { [LEGACY_LISKOV_BOOTSTRAP_ENV]: slipwayBootstrap("https://legacy.test") }
    });
    assert.equal(config, undefined);
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

  it("ignores the legacy lockbox name", () => {
    const config = readLockboxRuntimeConfig({
      env: { [LEGACY_LOCKBOX_BOOTSTRAP_ENV]: lockboxBootstrap("https://legacy-lockbox.test") }
    });
    assert.equal(config, undefined);
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

describe("LISKOV_HOME", () => {
  // BKLG-20261002-qihk: the state root override is LISKOV_HOME; the default
  // directories keep their .slipway names.
  it("overrides the state root", () => {
    assert.equal(LISKOV_HOME_ENV_NAME, "LISKOV_HOME");
    assert.equal(resolveSlipwayHome({ env: { LISKOV_HOME: "/h" } }), "/h");
  });

  it("no longer reads SLIPWAY_HOME", () => {
    assert.equal(resolveSlipwayHome({ env: { SLIPWAY_HOME: "/h", HOME: "/u" } }), "/u/.slipway");
    assert.equal(resolveSlipwayHome({ env: {} }), "/tmp/slipway");
  });

  it("keeps the deprecated constant pointing at the name that is read", () => {
    assert.equal(SLIPWAY_HOME_ENV_NAME, LISKOV_HOME_ENV_NAME);
    assert.equal(resolveSlipwayHome({ env: { [SLIPWAY_HOME_ENV_NAME]: "/h", HOME: "/u" } }), "/h");
  });
});

describe("Acurast identity defaults", () => {
  // BKLG-20261002-qihk: the identity defaults read only Acurast's own names,
  // then _STD_.
  const std = {
    job: { getId: () => "std-job" },
    device: { getAddress: () => "std-processor" }
  };

  it("does not take PROOF_ACURAST_* or SWITCHBOARD_MANAGED_* values", () => {
    for (const env of [
      { PROOF_ACURAST_JOB_ID: "env-job", PROOF_ACURAST_PROCESSOR_ID: "env-processor" },
      { SWITCHBOARD_MANAGED_JOB_ID: "env-job", SWITCHBOARD_MANAGED_PROCESSOR_ID: "env-processor" }
    ]) {
      const identity = resolveAcurastRuntimeIdentity({ env, std });
      assert.equal(identity.jobId, "std-job");
      assert.equal(identity.processorId, "std-processor");
    }
  });

  it("still takes the ACURAST_* names", () => {
    const identity = resolveAcurastRuntimeIdentity({
      env: { ACURAST_JOB_ID: "env-job", ACURAST_PROCESSOR_ID: "env-processor" },
      std
    });
    assert.equal(identity.jobId, "env-job");
    assert.equal(identity.processorId, "env-processor");
  });
});

describe("runtime-env tuning", () => {
  // BKLG-20261002-qihk (Q-20260922-gqgv): the six PROOF_SLIPWAY_RUNTIME_* knobs
  // had no emitter, and five exceed Acurast's 32-byte setEnvironment key limit.
  const bootstrap = JSON.stringify({
    v: 1,
    u: "https://core.test",
    a: "app",
    p: POLICY_DIGEST,
    d: "42",
    x: { t: "diag-token", h: { i: 30_000, d: 1_000, to: 5_000 } }
  });

  it("reads none of the PROOF_SLIPWAY_RUNTIME_* names", () => {
    const without = readSlipwayRuntimeEnvConfig({ env: { LISKOV_BOOTSTRAP: bootstrap } });
    const withLegacy = readSlipwayRuntimeEnvConfig({
      env: {
        LISKOV_BOOTSTRAP: bootstrap,
        PROOF_SLIPWAY_RUNTIME_ENV_ALLOW_INSECURE_HTTP: "true",
        PROOF_SLIPWAY_RUNTIME_ENV_REQUEST_TTL_MS: "5",
        PROOF_SLIPWAY_RUNTIME_ENV_NONCE: "env-nonce",
        PROOF_SLIPWAY_RUNTIME_HEALTH_INTERVAL_MS: "1",
        PROOF_SLIPWAY_RUNTIME_HEALTH_INITIAL_DELAY_MS: "2",
        PROOF_SLIPWAY_RUNTIME_DIAGNOSTIC_SEND_TIMEOUT_MS: "3"
      }
    });
    assert.deepEqual(withLegacy, without);
    assert.deepEqual(withLegacy?.runtimeHealth, { intervalMs: 30_000, initialDelayMs: 1_000, sendTimeoutMs: 5_000 });
    assert.notEqual(withLegacy?.nonce, "env-nonce");
    assert.equal(withLegacy?.nonce, undefined);
    assert.equal(withLegacy?.requestTtlMs, undefined);
    assert.equal(withLegacy?.allowInsecureHttp, false);
  });
});
