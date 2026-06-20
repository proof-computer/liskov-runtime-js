import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

interface PackageJson {
  name?: string;
  version?: string;
  private?: boolean;
  repository?: { type?: string; url?: string };
  files?: string[];
  scripts?: Record<string, string>;
}

describe("public package metadata", () => {
  it("is ready for the v0.3.1 Liskov runtime package path", async () => {
    const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as PackageJson;

    assert.equal(packageJson.name, "@proof-computer/liskov-runtime");
    assert.equal(packageJson.version, "0.3.1");
    assert.equal(packageJson.private, false);
    assert.deepEqual(packageJson.repository, {
      type: "git",
      url: "git+https://github.com/proof-computer/liskov-runtime-js.git"
    });
    assert.deepEqual(packageJson.files?.sort(), ["README.md", "SECURITY.md", "dist"]);
    assert.equal(packageJson.scripts?.["pack:dry-run"], "npm pack --dry-run --json");
  });
});
