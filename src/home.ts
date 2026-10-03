import path from "node:path";

/** Overrides the state root, which defaults to `$HOME/.slipway`, else `/tmp/slipway`. */
export const LISKOV_HOME_ENV_NAME = "LISKOV_HOME";

/**
 * The retired name of {@link LISKOV_HOME_ENV_NAME}, now equal to it, so an
 * importer that sets the variable through it sets the name that is read.
 *
 * @deprecated Use {@link LISKOV_HOME_ENV_NAME}.
 */
export const SLIPWAY_HOME_ENV_NAME = LISKOV_HOME_ENV_NAME;
export const DEFAULT_SLIPWAY_HOME_DIRNAME = ".slipway";
export const FALLBACK_SLIPWAY_HOME = "/tmp/slipway";

export interface ResolveSlipwayHomeOptions {
  home?: string;
  env?: Record<string, string | undefined>;
}

export function resolveSlipwayHome(options: ResolveSlipwayHomeOptions = {}): string {
  const env = options.env ?? process.env;
  const raw = firstNonEmpty(options.home, env[LISKOV_HOME_ENV_NAME]);
  if (raw !== undefined) return expandHome(raw, env);
  const homeDir = firstNonEmpty(env.HOME, env.USERPROFILE);
  return homeDir ? path.join(homeDir, DEFAULT_SLIPWAY_HOME_DIRNAME) : FALLBACK_SLIPWAY_HOME;
}

function expandHome(value: string, env: Record<string, string | undefined>): string {
  if (value === "~" || value.startsWith("~/") || value.startsWith("~\\")) {
    const homeDir = firstNonEmpty(env.HOME, env.USERPROFILE);
    if (!homeDir) return value;
    if (value === "~") return homeDir;
    return path.join(homeDir, value.slice(2));
  }
  return value;
}

function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  return values.find((value): value is string => typeof value === "string" && value.length > 0);
}
