import { constants } from "node:fs";
import { open, mkdir, lstat, rename, unlink, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

export interface SecretFile { path: string; value: string }

// Keep directory descriptors open on Linux so a replaced parent cannot redirect
// an installation. Staging and recovery names contain no secret values.
export async function installSecretFiles(group: readonly SecretFile[]): Promise<void> {
  const entries: Array<{ dir: FileHandle; target: string; stage: string; backup: string;
    hadOriginal: boolean; installed: boolean }> = [];
  try {
    if (new Set(group.map(file => file.path)).size !== group.length) {
      throw new Error("duplicate file secret destination");
    }
    for (const file of group) {
      const dir = await openDirectory(path.dirname(file.path));
      const anchor = process.platform === "linux" ? `/proc/self/fd/${dir.fd}` : path.dirname(file.path);
      const name = path.basename(file.path);
      if (name.startsWith(".liskov-secret-")) {
        await dir.close();
        throw new Error("reserved file secret destination");
      }
      const key = createHash("sha256").update(name).digest("hex").slice(0, 32);
      const entry = { dir, target: path.join(anchor, name),
        stage: path.join(anchor, `.liskov-secret-${key}.stage`),
        backup: path.join(anchor, `.liskov-secret-${key}.backup`),
        hadOriginal: false, installed: false };
      entries.push(entry);
      // Recover an interrupted replacement before staging the authenticated group.
      if (await regularFile(entry.backup)) {
        if (await regularFile(entry.target)) await unlink(entry.target);
        await rename(entry.backup, entry.target);
      }
      if (await regularFile(entry.stage)) await unlink(entry.stage);
      entry.hadOriginal = await regularFile(entry.target);
      const staged = await open(entry.stage, constants.O_WRONLY | constants.O_CREAT |
        constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await staged.writeFile(file.value, "utf8"); await staged.sync(); }
      finally { await staged.close(); }
    }
    for (const entry of entries) {
      if (entry.hadOriginal) await rename(entry.target, entry.backup);
      await rename(entry.stage, entry.target);
      entry.installed = true;
      await entry.dir.sync();
    }
  } catch (error) {
    // Complete rollback before exposing the failure to the caller; env has not
    // been changed yet. Surface rollback failures too, never report partial success.
    const failures: unknown[] = [error];
    for (const entry of entries.toReversed()) {
      try {
        if (entry.installed) await unlink(entry.target);
        if (await regularFile(entry.backup)) await rename(entry.backup, entry.target);
        if (await regularFile(entry.stage)) await unlink(entry.stage);
        await entry.dir.sync();
      } catch (rollbackError) { failures.push(rollbackError); }
    }
    await Promise.all(entries.map(entry => entry.dir.close()));
    throw new AggregateError(failures, "file secret installation failed");
  }
  try {
    for (const entry of entries) {
      if (entry.hadOriginal) await unlink(entry.backup);
      await entry.dir.sync();
    }
  } finally { await Promise.all(entries.map(entry => entry.dir.close())); }
}

async function regularFile(target: string): Promise<boolean> {
  try {
    const stat = await lstat(target);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("file secret target is not a regular file");
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function openDirectory(directory: string): Promise<FileHandle> {
  let handle = await open(path.parse(directory).root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let prefix = path.parse(directory).root;
  try {
    for (const component of directory.slice(prefix.length).split(path.sep).filter(Boolean)) {
      const parent = process.platform === "linux" ? `/proc/self/fd/${handle.fd}` : prefix;
      const next = path.join(parent, component);
      try { await mkdir(next, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      const child = await open(next, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      await handle.close();
      handle = child;
      prefix = path.join(prefix, component);
    }
    return handle;
  } catch (error) { await handle.close(); throw error; }
}
