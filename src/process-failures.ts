import type {
  LiskovRuntimeDiagnostics,
  LiskovRuntimeFatalKind
} from "./diagnostics.js";

export type LiskovUnhandledRejectionPolicy = "continue" | "exit";

export interface LiskovRuntimeProcessFailureTerminateInput {
  kind?: LiskovRuntimeFatalKind;
  code?: string;
  error?: unknown;
  message?: string;
  component?: string;
}

export interface LiskovRuntimeProcessFailureHandlers {
  attach(diagnostics: LiskovRuntimeDiagnostics): void;
  runMain(main: () => void | Promise<void>): Promise<void>;
  terminate(input?: LiskovRuntimeProcessFailureTerminateInput): Promise<void>;
  dispose(): void;
}

export interface InstallLiskovRuntimeProcessFailureHandlersOptions {
  unhandledRejection: LiskovUnhandledRejectionPolicy;
  component?: string;
  process?: LiskovRuntimeProcessLike;
  onStageZeroError?: (kind: LiskovRuntimeFatalKind, error: unknown) => void;
}

export interface LiskovRuntimeProcessLike {
  exitCode: string | number | null | undefined;
  on(event: "uncaughtException" | "unhandledRejection", listener: (...args: any[]) => void): unknown;
  off(event: "uncaughtException" | "unhandledRejection", listener: (...args: any[]) => void): unknown;
  exit(code?: number): never;
}

/**
 * Installs one explicit process boundary. Fatal paths set exitCode before the
 * bounded diagnostic attempt and then exit non-zero. The returned attach()
 * method lets an application bind the SDK diagnostics immediately after
 * bootstrap without making pre-identity failures look authenticated.
 */
export function installLiskovRuntimeProcessFailureHandlers(
  options: InstallLiskovRuntimeProcessFailureHandlersOptions
): LiskovRuntimeProcessFailureHandlers {
  const processLike = options.process ?? process;
  let diagnostics: LiskovRuntimeDiagnostics | undefined;
  let disposed = false;
  let terminalPromise: Promise<void> | undefined;

  const exitOnce = () => {
    processLike.exit(1);
  };

  const terminate = (input: LiskovRuntimeProcessFailureTerminateInput = {}): Promise<void> => {
    if (terminalPromise) return terminalPromise;
    processLike.exitCode = 1;
    const kind = input.kind ?? "explicit";
    if (!diagnostics) {
      options.onStageZeroError?.(kind, input.error ?? input.message ?? input.code ?? "runtime terminated");
    }
    terminalPromise = (async () => {
      try {
        await diagnostics?.fatal({
          kind,
          code: input.code ?? defaultFatalCode(kind),
          error: input.error,
          message: input.message,
          component: input.component ?? options.component
        });
      } catch {
        // The original failure and non-zero exit always win over observability.
      }
      exitOnce();
    })();
    return terminalPromise;
  };

  const onUncaughtException = (error: Error) => {
    void terminate({ kind: "uncaught_exception", code: "uncaught_exception", error });
  };
  const onUnhandledRejection = (reason: unknown) => {
    if (options.unhandledRejection === "continue") {
      if (diagnostics) {
        void diagnostics.report({
          stage: "runtime.unhandled_rejection",
          status: "failed",
          component: options.component,
          code: "unhandled_rejection",
          message: errorMessage(reason)
        });
      } else {
        options.onStageZeroError?.("unhandled_rejection", reason);
      }
      return;
    }
    void terminate({ kind: "unhandled_rejection", code: "unhandled_rejection", error: reason });
  };

  processLike.on("uncaughtException", onUncaughtException);
  processLike.on("unhandledRejection", onUnhandledRejection);

  return {
    attach(value) {
      diagnostics = value;
    },
    async runMain(main) {
      try {
        await main();
      } catch (error) {
        await terminate({ kind: "application_start", code: "application_start_failed", error });
      }
    },
    terminate,
    dispose() {
      if (disposed) return;
      disposed = true;
      processLike.off("uncaughtException", onUncaughtException);
      processLike.off("unhandledRejection", onUnhandledRejection);
    }
  };
}

function defaultFatalCode(kind: LiskovRuntimeFatalKind): string {
  return kind === "application_start" ? "application_start_failed" : kind;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
