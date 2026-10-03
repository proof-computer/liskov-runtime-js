/**
 * Canonical names of the Liskov-owned runtime environment contract.
 *
 * Liskov-owned variables are migrating to the `LISKOV_*` prefix
 * (`BKLG-20260829-m8kd`). The platform emits only `LISKOV_BOOTSTRAP`, so the
 * public bootstrap is read under that name alone (`BKLG-20260922-91r7`). The
 * Lockbox reader still prefers the `LISKOV_*` name and falls back to the legacy
 * one for jobs deployed before the rename.
 *
 * `BRIDGE_SOCKET` is deliberately absent: it belongs to the Acurast runtime,
 * not to Liskov, and must never be renamed or aliased.
 */

/** The public bootstrap config the platform hands a Liskov job. */
export const LISKOV_BOOTSTRAP_ENV = "LISKOV_BOOTSTRAP";

/**
 * The retired name of {@link LISKOV_BOOTSTRAP_ENV}.
 *
 * @deprecated No longer read; exported so existing imports compile.
 */
export const LEGACY_LISKOV_BOOTSTRAP_ENV = "PROOF_SLIPWAY_BOOTSTRAP";

/** The names the public bootstrap config is read from. */
export const LISKOV_BOOTSTRAP_ENV_NAMES: readonly string[] = [LISKOV_BOOTSTRAP_ENV];

/** The compact Lockbox secret bootstrap config. */
export const LOCKBOX_BOOTSTRAP_ENV = "LISKOV_LOCKBOX_BOOTSTRAP";

/** Migration bridge for {@link LOCKBOX_BOOTSTRAP_ENV}. */
export const LEGACY_LOCKBOX_BOOTSTRAP_ENV = "PROOF_LOCKBOX_BOOTSTRAP";

/** Reader preference order for the Lockbox secret bootstrap config. */
export const LOCKBOX_BOOTSTRAP_ENV_NAMES: readonly string[] = [
  LOCKBOX_BOOTSTRAP_ENV,
  LEGACY_LOCKBOX_BOOTSTRAP_ENV
];
