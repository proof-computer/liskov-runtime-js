/**
 * Canonical names of the Liskov-owned runtime environment contract.
 *
 * Every Liskov-owned variable a job reads is `LISKOV_*`. Each is read under
 * its `LISKOV_*` name alone, with no fallback to a retired name:
 * `LISKOV_BOOTSTRAP` (`BKLG-20260922-91r7`), and `LISKOV_CORE_URL` and
 * `LISKOV_LOCKBOX_BOOTSTRAP` (`BKLG-20261002-qihk`). `LISKOV_HOME` is in
 * `home.ts`.
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

/** Overrides the compiled-in `DEFAULT_LISKOV_CORE_URL`. */
export const LISKOV_CORE_URL_ENV = "LISKOV_CORE_URL";

/** The compact Lockbox secret bootstrap config. */
export const LOCKBOX_BOOTSTRAP_ENV = "LISKOV_LOCKBOX_BOOTSTRAP";

/**
 * The retired name of {@link LOCKBOX_BOOTSTRAP_ENV}.
 *
 * @deprecated No longer read; exported so existing imports compile.
 */
export const LEGACY_LOCKBOX_BOOTSTRAP_ENV = "PROOF_LOCKBOX_BOOTSTRAP";

/** The names the Lockbox secret bootstrap config is read from. */
export const LOCKBOX_BOOTSTRAP_ENV_NAMES: readonly string[] = [LOCKBOX_BOOTSTRAP_ENV];
