export type DiskSpoolModules = {
  fs: typeof import("node:fs/promises");
  path: typeof import("node:path");
};

let testModules: DiskSpoolModules | undefined;

export async function loadDiskSpoolModules(): Promise<DiskSpoolModules> {
  if (testModules) return testModules;
  const [fs, path] = await Promise.all([import("node:fs/promises"), import("node:path")]);
  return { fs, path: (path as { default?: typeof import("node:path") }).default ?? path };
}

/** Internal fault-injection seam. This module is intentionally absent from the package export map. */
export function installDiskSpoolModulesForTest(modules: DiskSpoolModules): () => void {
  const previous = testModules;
  testModules = modules;
  return () => {
    testModules = previous;
  };
}
