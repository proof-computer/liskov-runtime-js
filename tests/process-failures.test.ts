import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { describe, it } from "node:test";

import type { LiskovRuntimeDiagnostics } from "../src/diagnostics.js";
import { installLiskovRuntimeProcessFailureHandlers } from "../src/process-failures.js";

class FakeProcess extends EventEmitter {
  exitCode: string | number | null | undefined;
  exits: number[] = [];

  exit(code?: string | number | null): never {
    this.exits.push(typeof code === "number" ? code : Number(code ?? 0));
    return undefined as never;
  }
}

describe("Liskov process failure boundary", () => {
  it("sets exit code before diagnostics, preserves first-call-wins, and exits after the attempt", async () => {
    const process = new FakeProcess();
    const fatalCodes: string[] = [];
    const diagnostics: LiskovRuntimeDiagnostics = {
      async report() {},
      async fatal(event) {
        assert.equal(process.exitCode, 1);
        fatalCodes.push(event.code);
      }
    };
    const boundary = installLiskovRuntimeProcessFailureHandlers({
      process,
      component: "fixture",
      unhandledRejection: "exit"
    });
    boundary.attach(diagnostics);
    const original = new Error("configuration rejected");
    const first = boundary.terminate({ kind: "application_start", code: "configuration_invalid", error: original });
    const racing = boundary.terminate({ kind: "explicit", code: "must_not_win" });
    assert.equal(first, racing);
    await first;
    assert.deepEqual(fatalCodes, ["configuration_invalid"]);
    assert.deepEqual(process.exits, [1]);
    boundary.dispose();
  });

  it("exits nonzero even when fatal diagnostics fail", async () => {
    const process = new FakeProcess();
    const boundary = installLiskovRuntimeProcessFailureHandlers({ process, unhandledRejection: "exit" });
    boundary.attach({
      async report() {},
      async fatal() { throw new Error("signing unavailable"); }
    });
    await boundary.runMain(() => { throw new Error("original startup failure"); });
    assert.equal(process.exitCode, 1);
    assert.deepEqual(process.exits, [1]);
  });

  it("reports continue-policy rejections without terminating", async () => {
    const process = new FakeProcess();
    const reports: Array<{ stage: string; code?: string }> = [];
    const boundary = installLiskovRuntimeProcessFailureHandlers({ process, unhandledRejection: "continue" });
    boundary.attach({
      async report(event) { reports.push(event); },
      async fatal() { assert.fail("continue policy must not call fatal"); }
    });
    process.emit("unhandledRejection", new Error("background failed"), Promise.resolve());
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(reports, [{
      stage: "runtime.unhandled_rejection",
      status: "failed",
      component: undefined,
      code: "unhandled_rejection",
      message: "background failed"
    }]);
    assert.deepEqual(process.exits, []);
    boundary.dispose();
  });

  it("treats uncaught exceptions as terminal and exposes stage-zero failures", async () => {
    const process = new FakeProcess();
    const stageZero: Array<{ kind: string; error: unknown }> = [];
    const original = new Error("uncaught");
    const boundary = installLiskovRuntimeProcessFailureHandlers({
      process,
      unhandledRejection: "exit",
      onStageZeroError(kind, error) { stageZero.push({ kind, error }); }
    });
    process.emit("uncaughtException", original, "uncaughtException");
    await boundary.terminate();
    assert.equal(process.exitCode, 1);
    assert.deepEqual(process.exits, [1]);
    assert.deepEqual(stageZero, [{ kind: "uncaught_exception", error: original }]);
  });
});
