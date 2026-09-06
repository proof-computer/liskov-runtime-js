import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile, mkdir, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { it } from "node:test";
import { decryptAndVerifyLockboxRuntimePayload, installLockboxRuntimeSecrets,
  parseLockboxRuntimeJobSecretResponse, type LockboxRuntimeJobSecretPlaintextPayload } from "../src/lockbox.js";

const fixture = JSON.parse(await readFile(new URL("fixtures/file-secret-service-v2.json", import.meta.url), "utf8"));
async function decoded(): Promise<LockboxRuntimeJobSecretPlaintextPayload> {
  return decryptAndVerifyLockboxRuntimePayload({ request: fixture.request,
    response: parseLockboxRuntimeJobSecretResponse(fixture.response),
    identityProvider: { async resolveIdentity() { throw new Error("unused"); },
      async sign() { throw new Error("unused"); },
      // The runtime's secure signer decrypts; these bytes are captured from the
      // real secrets-service integration and its independent P256 decryptor.
      async decryptGrantPayload() { return Buffer.from(JSON.stringify(fixture.plaintext)); } } });
}

it("installs the real service mixed group with exact values, absolute paths and private permissions", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "liskov-secret-"));
  try {
    const payload = await decoded();
    const env: Record<string, string | undefined> = {};
    for (const secret of payload.secrets) if (secret.target === "file") secret.name = root + secret.name;
    const result = await installLockboxRuntimeSecrets({ payload, env, overwriteEnv: true });
    for (const secret of payload.secrets) {
      if (secret.target === "env") assert.equal(env[secret.name], secret.value);
      else {
        assert.equal(await readFile(secret.name, "utf8"), secret.value);
        assert.equal((await stat(secret.name)).mode & 0o777, 0o600);
      }
      assert.equal(JSON.stringify(result).includes(secret.value), false);
    }
    await installLockboxRuntimeSecrets({ payload, env, overwriteEnv: true });
  } finally { await rm(root, { recursive: true, force: true }); }
});

it("does not apply environment values or replace existing files when a file group is refused", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "liskov-secret-"));
  try {
    const payload = await decoded();
    const template = payload.secrets.find(secret => secret.target === "file")!;
    const target = path.join(root, "first");
    await writeFile(target, "previous");
    await mkdir(path.join(root, "blocked"));
    payload.secrets = [...payload.secrets.filter(secret => secret.target === "env"),
      { ...template, name: target }, { ...template, secretId: "second", name: path.join(root, "blocked") }];
    const env = { PREVIOUS: "still here" };
    await assert.rejects(installLockboxRuntimeSecrets({ payload, env }), /installation failed/u);
    assert.deepEqual(env, { PREVIOUS: "still here" });
    assert.equal(await readFile(target, "utf8"), "previous");
    await symlink(root, path.join(root, "redirect"));
    payload.secrets = [{ ...template, name: path.join(root, "redirect", "escape") }];
    await assert.rejects(installLockboxRuntimeSecrets({ payload, env }), /installation failed/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});

it("recovers an interrupted replacement and rejects changed or partial service metadata", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "liskov-secret-"));
  try {
    const payload = await decoded();
    const template = payload.secrets.find(secret => secret.target === "file")!;
    const key = createHash("sha256").update("config").digest("hex").slice(0, 32);
    await writeFile(path.join(root, `.liskov-secret-${key}.backup`), "previous");
    await writeFile(path.join(root, "config"), "interrupted");
    payload.secrets = [{ ...template, name: path.join(root, "config") }];
    await installLockboxRuntimeSecrets({ payload, env: {} });
    assert.equal(await readFile(path.join(root, "config"), "utf8"), template.value);
    const original = fixture.response.secretVersions;
    fixture.response.secretVersions = [];
    await assert.rejects(decoded(), /incomplete/u);
    fixture.response.secretVersions = structuredClone(original);
    fixture.response.secretVersions[0].name = "FOREIGN";
    await assert.rejects(decoded(), /destination/u);
    fixture.response.secretVersions = original;
  } finally { await rm(root, { recursive: true, force: true }); }
});
