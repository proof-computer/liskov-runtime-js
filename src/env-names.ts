/**
 * Canonical names of the Liskov-owned runtime environment contract.
 *
 * Liskov-owned variables are migrating to the `LISKOV_*` prefix
 * (`BKLG-20260829-m8kd`). Step 1 is reader-side only: every reader prefers the
 * `LISKOV_*` name and falls back to the legacy one. The platform still emits
 * only the legacy names, so the alias is a no-op until the emitter flips.
 *
 * `BRIDGE_SOCKET` is deliberately absent: it belongs to the Acurast runtime,
 * not to Liskov, and must never be renamed or aliased.
 */

/** The public bootstrap config the platform hands a Liskov job. */
export const LISKOV_BOOTSTRAP_ENV = "LISKOV_BOOTSTRAP";

/** Migration bridge for {@link LISKOV_BOOTSTRAP_ENV}. */
export const LEGACY_LISKOV_BOOTSTRAP_ENV = "PROOF_SLIPWAY_BOOTSTRAP";

/** Reader preference order for the public bootstrap config. */
export const LISKOV_BOOTSTRAP_ENV_NAMES: readonly string[] = [
  LISKOV_BOOTSTRAP_ENV,
  LEGACY_LISKOV_BOOTSTRAP_ENV
];

/** The compact Lockbox secret bootstrap config. */
export const LOCKBOX_BOOTSTRAP_ENV = "LISKOV_LOCKBOX_BOOTSTRAP";

/** Migration bridge for {@link LOCKBOX_BOOTSTRAP_ENV}. */
export const LEGACY_LOCKBOX_BOOTSTRAP_ENV = "PROOF_LOCKBOX_BOOTSTRAP";

/** Reader preference order for the Lockbox secret bootstrap config. */
export const LOCKBOX_BOOTSTRAP_ENV_NAMES: readonly string[] = [
  LOCKBOX_BOOTSTRAP_ENV,
  LEGACY_LOCKBOX_BOOTSTRAP_ENV
];
