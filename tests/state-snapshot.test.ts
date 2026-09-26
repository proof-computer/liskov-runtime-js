import assert from "node:assert/strict";
import { createCipheriv, createECDH, createHash, createPrivateKey, hkdfSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

// NodeNext rejects a ".ts" specifier; the test runner still loads this file.
import {
  MANIFEST_SIGNATURE_DOMAIN,
  StateSnapshotError,
  canonicalBytes,
  chunkId,
  deriveChunkIdKey,
  deriveChunkKey,
  manifestDigest,
  openChunk,
  parseManifest,
  parseWrappedDataKey,
  recipientKeyId,
  sealChunk,
  signManifest,
  statePlaneEnabled,
  verifyManifestSignature,
  verifySuccessor,
  wrapDataKey,
  unwrapDataKey,
  type DataKeyBinding,
  type Manifest,
  type StateSnapshotErrorCode,
  type WrappedDataKey
  // @ts-expect-error TS5097
} from "../src/state-snapshot.ts";

const EXPORT_KEYS = [
  ".",
  "./acurast",
  "./blackbox-logger",
  "./bootstrap",
  "./diagnostics",
  "./env",
  "./env-names",
  "./home",
  "./lockbox",
  "./proof-log-crypto",
  "./processor-coverage",
  "./runtime-env",
  "./encrypted-code"
];

interface ChunkCase {
  name: string;
  plaintextHex?: string;
  plaintextGenerator?: { kind: string; length: number };
  plaintextSha256Hex?: string;
  nonceHex: string;
  chunkIdHex: string;
  objectLength: number;
  objectHex?: string;
  objectSha256Hex?: string;
  objectHeadHex?: string;
  objectTailHex?: string;
}

interface ChunkVector {
  format: string;
  dekHex: string;
  lineageId: string;
  chunkKeyHex: string;
  chunkIdKeyHex: string;
  cases: ChunkCase[];
}

interface WrappedCase {
  name: string;
  recipientPrivHex: string;
  recipientPubHex: string;
  senderPrivHex: string;
  saltHex: string;
  ivHex: string;
  wrapped: {
    recipientKind: "lockbox" | "job" | "customer" | "broker_share";
    recipientKeyId: string;
    dekVersion: number;
    grant: {
      version: string;
      curveName: string;
      senderPublicKey: string;
      saltHex: string;
      ciphertextHex: string;
    };
  };
}

interface WrappedVector {
  format: string;
  dekHex: string;
  binding: DataKeyBinding;
  wrappedPlaintextUtf8: string;
  cases: WrappedCase[];
}

interface ManifestCase {
  name: string;
  signerSeedHex: string;
  manifestJson: string;
  canonicalHex: string;
  digestHex: string;
  signatureHex: string;
}

interface ManifestVector {
  format: string;
  signatureDomain: string;
  cases: ManifestCase[];
}

const chunkVector = JSON.parse(await readFile(new URL("./vectors/state_snapshot_chunk.json", import.meta.url), "utf8")) as ChunkVector;
const wrappedVector = JSON.parse(await readFile(new URL("./vectors/state_snapshot_wrapped_key.json", import.meta.url), "utf8")) as WrappedVector;
const manifestVector = JSON.parse(await readFile(new URL("./vectors/state_snapshot_manifest.json", import.meta.url), "utf8")) as ManifestVector;

function expectError(
  fn: () => unknown,
  code: StateSnapshotErrorCode,
  details?: Partial<Pick<StateSnapshotError, "len" | "version" | "field" | "declared" | "chunks" | "previous" | "next">>
): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof StateSnapshotError, `expected ${code}, got ${String(caught)}`);
  assert.equal(caught.code, code);
  if (details !== undefined) {
    for (const [key, value] of Object.entries(details)) {
      assert.equal(caught[key as keyof StateSnapshotError], value, key);
    }
  }
}

function chunkPlaintext(entry: ChunkCase): Buffer {
  if (entry.plaintextGenerator !== undefined) {
    assert.equal(entry.plaintextGenerator.kind, "index_mod_256");
    const out = Buffer.alloc(entry.plaintextGenerator.length);
    for (let index = 0; index < out.length; index += 1) out[index] = index & 0xff;
    return out;
  }
  return Buffer.from(entry.plaintextHex ?? "", "hex");
}

function cloneManifest(manifest: Manifest): Manifest {
  return structuredClone(manifest);
}

const GRANT_LABEL = Buffer.from("ECDH secp256r1 AES-256-GCM-SIV", "ascii");

function testGrantEncrypt(
  senderPriv: Buffer,
  senderPub: Buffer,
  recipientPub: Buffer,
  salt: Buffer,
  iv: Buffer,
  plaintext: Buffer
): Buffer {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(senderPriv);
  const shared = ecdh.computeSecret(recipientPub);
  const leftFirst = senderPub.length !== recipientPub.length
    ? senderPub.length < recipientPub.length
    : Buffer.compare(senderPub, recipientPub) <= 0;
  const info = Buffer.concat([GRANT_LABEL, leftFirst ? senderPub : recipientPub, leftFirst ? recipientPub : senderPub]);
  const key = Buffer.from(hkdfSync("sha256", shared, salt, info, 32));
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([iv, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

describe("state snapshot package boundary", () => {
  it("keeps the module off the package exports map", async () => {
    const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
      exports: Record<string, unknown>;
    };
    const keys = Object.keys(packageJson.exports);
    assert.equal(keys.some((key) => key.includes("state-snapshot")), false);
    assert.equal(JSON.stringify(packageJson.exports).includes("state-snapshot"), false);
    assert.deepEqual(keys, EXPORT_KEYS);
    const indexSource = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");
    const bootstrapSource = await readFile(new URL("../src/bootstrap.ts", import.meta.url), "utf8");
    const moduleSource = await readFile(new URL("../src/state-snapshot.ts", import.meta.url), "utf8");
    assert.equal(indexSource.includes("state-snapshot"), false);
    assert.equal(bootstrapSource.includes("state-snapshot"), false);
    assert.equal(moduleSource.includes("proof-log-crypto"), false);
    assert.equal(moduleSource.includes("process.env"), false);
  });
});

describe("statePlaneEnabled", () => {
  const applications = "app-a, app-b,\tapp-c,,  ";

  it("opens only for exact true and a listed id", () => {
    assert.equal(statePlaneEnabled("true", applications, "app-a"), true);
    assert.equal(statePlaneEnabled("true", applications, "app-b"), true);
    assert.equal(statePlaneEnabled("true", applications, "app-c"), true);
    assert.equal(statePlaneEnabled("true", "app-a ", "app-a"), true);
  });

  it("stays shut for a missing flag, TRUE, 1, a padded flag, and an unlisted id", () => {
    assert.equal(statePlaneEnabled(undefined, applications, "app-a"), false);
    assert.equal(statePlaneEnabled("TRUE", applications, "app-a"), false);
    assert.equal(statePlaneEnabled("1", applications, "app-a"), false);
    assert.equal(statePlaneEnabled(" true", applications, "app-a"), false);
    assert.equal(statePlaneEnabled("true ", applications, "app-a"), false);
    assert.equal(statePlaneEnabled("true", applications, "app-d"), false);
    assert.equal(statePlaneEnabled("true", applications, ""), false);
    assert.equal(statePlaneEnabled("true", undefined, "app-a"), false);
    assert.equal(statePlaneEnabled("true", applications, " app-a"), false);
    assert.equal(statePlaneEnabled("true", "\napp-a", "app-a"), false);
    assert.equal(statePlaneEnabled("true", "app-a\napp-b", "app-b"), false);
  });

  it("does not consult process.env", () => {
    const previousEnabled = process.env.LISKOV_STATE_DATA_PLANE_ENABLED;
    const previousApplications = process.env.LISKOV_STATE_DATA_PLANE_APPLICATIONS;
    process.env.LISKOV_STATE_DATA_PLANE_ENABLED = "true";
    process.env.LISKOV_STATE_DATA_PLANE_APPLICATIONS = "app-a";
    try {
      assert.equal(statePlaneEnabled(undefined, undefined, "app-a"), false);
    } finally {
      if (previousEnabled === undefined) delete process.env.LISKOV_STATE_DATA_PLANE_ENABLED;
      else process.env.LISKOV_STATE_DATA_PLANE_ENABLED = previousEnabled;
      if (previousApplications === undefined) delete process.env.LISKOV_STATE_DATA_PLANE_APPLICATIONS;
      else process.env.LISKOV_STATE_DATA_PLANE_APPLICATIONS = previousApplications;
    }
  });
});

describe("state snapshot chunks", () => {
  const dek = Buffer.from(chunkVector.dekHex, "hex");

  it("reproduces the chunk vector and opens each object", () => {
    assert.equal(chunkVector.format, "liskov-state-chunk-v1");
    assert.equal(deriveChunkKey(dek, chunkVector.lineageId).toString("hex"), chunkVector.chunkKeyHex);
    assert.equal(deriveChunkIdKey(dek, chunkVector.lineageId).toString("hex"), chunkVector.chunkIdKeyHex);
    for (const entry of chunkVector.cases) {
      const plaintext = chunkPlaintext(entry);
      if (entry.plaintextSha256Hex !== undefined) {
        assert.equal(createHash("sha256").update(plaintext).digest("hex"), entry.plaintextSha256Hex);
      }
      const sealed = sealChunk(dek, chunkVector.lineageId, Buffer.from(entry.nonceHex, "hex"), plaintext);
      assert.equal(sealed.chunkId.toString("hex"), entry.chunkIdHex, entry.name);
      assert.equal(chunkId(dek, chunkVector.lineageId, plaintext).toString("hex"), entry.chunkIdHex);
      assert.equal(sealed.object.length, entry.objectLength);
      if (entry.objectHex !== undefined) {
        assert.equal(sealed.object.toString("hex"), entry.objectHex);
      } else {
        assert.equal(createHash("sha256").update(sealed.object).digest("hex"), entry.objectSha256Hex);
        assert.equal(sealed.object.subarray(0, 64).toString("hex"), entry.objectHeadHex);
        assert.equal(sealed.object.subarray(sealed.object.length - 64).toString("hex"), entry.objectTailHex);
      }
      assert.equal(openChunk(dek, chunkVector.lineageId, sealed.chunkId, sealed.object).equals(plaintext), true);
    }
  });

  it("keeps one chunk id across nonces and refuses a bad open", () => {
    const entry = chunkVector.cases[1];
    assert.ok(entry !== undefined);
    const plaintext = chunkPlaintext(entry);
    const sealed = sealChunk(dek, chunkVector.lineageId, Buffer.from(entry.nonceHex, "hex"), plaintext);
    const again = sealChunk(dek, chunkVector.lineageId, Buffer.alloc(12, 0x11), plaintext);
    assert.equal(again.chunkId.equals(sealed.chunkId), true);
    assert.equal(again.object.equals(sealed.object), false);
    assert.notEqual(sealed.chunkId.toString("hex"), createHash("sha256").update(plaintext).digest("hex"));

    expectError(() => openChunk(dek, "stl_other_lineage", sealed.chunkId, sealed.object), "Decrypt");
    const wrongId = Buffer.from(sealed.chunkId);
    wrongId[0] ^= 0x01;
    expectError(() => openChunk(dek, chunkVector.lineageId, wrongId, sealed.object), "Decrypt");
    for (const len of [0, 1, 28]) {
      expectError(
        () => openChunk(dek, chunkVector.lineageId, sealed.chunkId, sealed.object.subarray(0, len)),
        "ChunkTruncated",
        { len }
      );
    }
    expectError(
      () => openChunk(dek, chunkVector.lineageId, sealed.chunkId, sealed.object.subarray(0, sealed.object.length - 1)),
      "Decrypt"
    );
    for (const version of [0x00, 0x02, 0xff]) {
      const object = Buffer.from(sealed.object);
      object[0] = version;
      expectError(() => openChunk(dek, chunkVector.lineageId, sealed.chunkId, object), "UnsupportedChunkVersion", { version });
    }
    const flipped = Buffer.from(sealed.object);
    flipped[flipped.length - 1] ^= 0x80;
    expectError(() => openChunk(dek, chunkVector.lineageId, sealed.chunkId, flipped), "Decrypt");

    const claimed = chunkId(dek, chunkVector.lineageId, Buffer.from("some other plaintext"));
    const nonce = Buffer.alloc(12, 0x42);
    const key = deriveChunkKey(dek, chunkVector.lineageId);
    const aad = Buffer.concat([Buffer.from("liskov-state-chunk-v1"), Buffer.from(chunkVector.lineageId), claimed]);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const forged = Buffer.concat([
      Buffer.from([0x01]),
      nonce,
      cipher.update(Buffer.from("the real plaintext")),
      cipher.final(),
      cipher.getAuthTag()
    ]);
    expectError(() => openChunk(dek, chunkVector.lineageId, claimed, forged), "ChunkIdMismatch");
  });
});

describe("wrapped data keys", () => {
  const dek = Buffer.from(wrappedVector.dekHex, "hex");
  const binding = wrappedVector.binding;

  function wrapCase(entry: WrappedCase, bound: DataKeyBinding = binding): WrappedDataKey {
    return wrapDataKey(
      dek,
      bound,
      entry.wrapped.recipientKind,
      Buffer.from(entry.recipientPubHex, "hex"),
      Buffer.from(entry.senderPrivHex, "hex"),
      Buffer.from(entry.saltHex, "hex"),
      Buffer.from(entry.ivHex, "hex")
    );
  }

  it("reproduces the wrapped-key vector and unwraps every recipient", () => {
    assert.equal(wrappedVector.format, "liskov-state-wrapped-dek-v1");
    assert.deepEqual(wrappedVector.cases.map((entry) => entry.wrapped.recipientKind), [
      "lockbox", "job", "customer", "broker_share"
    ]);
    for (const entry of wrappedVector.cases) {
      const wrapped = wrapCase(entry);
      assert.equal(wrapped.recipientKind, entry.wrapped.recipientKind);
      assert.equal(wrapped.recipientKeyId, entry.wrapped.recipientKeyId);
      assert.equal(wrapped.dekVersion, entry.wrapped.dekVersion);
      assert.equal(wrapped.grant.version, entry.wrapped.grant.version);
      assert.equal(wrapped.grant.curveName, entry.wrapped.grant.curveName);
      assert.equal(Buffer.from(wrapped.grant.senderPublicKey).toString("hex"), entry.wrapped.grant.senderPublicKey);
      assert.equal(Buffer.from(wrapped.grant.salt).toString("hex"), entry.wrapped.grant.saltHex);
      assert.equal(Buffer.from(wrapped.grant.ciphertext).toString("hex"), entry.wrapped.grant.ciphertextHex, entry.name);
      const parsed = parseWrappedDataKey(entry.wrapped);
      const opened = unwrapDataKey(
        parsed,
        Buffer.from(entry.recipientPrivHex, "hex"),
        Buffer.from(entry.recipientPubHex, "hex"),
        binding
      );
      assert.equal(opened.toString("hex"), wrappedVector.dekHex, entry.name);
    }
    const job = wrappedVector.cases[1];
    assert.ok(job !== undefined);
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(Buffer.from(job.recipientPrivHex, "hex"));
    const compressed = Buffer.from(ecdh.getPublicKey(null, "compressed"));
    assert.equal(compressed.length, 33);
    assert.equal(Buffer.from(job.recipientPubHex, "hex").length, 65);
    assert.equal(recipientKeyId(Buffer.from(job.recipientPubHex, "hex")), recipientKeyId(compressed));
    assert.equal(recipientKeyId(compressed), job.wrapped.recipientKeyId);
  });

  it("refuses a mismatched binding, key, scheme, or canonical plaintext", () => {
    const entry = wrappedVector.cases[0];
    const other = wrappedVector.cases[2];
    assert.ok(entry !== undefined && other !== undefined);
    const priv = Buffer.from(entry.recipientPrivHex, "hex");
    const pub = Buffer.from(entry.recipientPubHex, "hex");
    for (const [field, bound] of [
      ["org", { ...binding, org: "org_other" }],
      ["application", { ...binding, application: "app_other" }],
      ["lineage", { ...binding, lineage: "stl_other" }]
    ] as const) {
      const wrapped = wrapCase(entry, bound);
      expectError(() => unwrapDataKey(wrapped, priv, pub, binding), "WrappedKeyBinding", { field });
    }

    const relabelled = wrapCase(entry, { ...binding, dekVersion: binding.dekVersion + 1 });
    relabelled.dekVersion = binding.dekVersion;
    expectError(() => unwrapDataKey(relabelled, priv, pub, binding), "WrappedKeyBinding", { field: "dekVersion" });
    const wrapped = wrapCase(entry);
    expectError(
      () => unwrapDataKey(wrapped, priv, pub, { ...binding, dekVersion: binding.dekVersion + 1 }),
      "WrappedKeyBinding",
      { field: "dekVersion" }
    );
    expectError(
      () => unwrapDataKey(wrapped, Buffer.from(other.recipientPrivHex, "hex"), Buffer.from(other.recipientPubHex, "hex"), binding),
      "RecipientKeyMismatch"
    );
    expectError(
      () => unwrapDataKey(wrapped, priv, Buffer.from(other.recipientPubHex, "hex"), binding),
      "InvalidKey"
    );
    expectError(() => wrapDataKey(
      dek, { ...binding, dekVersion: Number.MAX_SAFE_INTEGER + 1 }, entry.wrapped.recipientKind, pub,
      Buffer.from(entry.senderPrivHex, "hex"), Buffer.from(entry.saltHex, "hex"), Buffer.from(entry.ivHex, "hex")
    ), "Encoding");

    const foreign = parseWrappedDataKey(structuredClone(entry.wrapped));
    foreign.grant.version = "acurast-p256-hkdf-aes-256-gcm-v2";
    expectError(() => unwrapDataKey(foreign, priv, pub, binding), "Encoding");
    const otherCurve = parseWrappedDataKey(structuredClone(entry.wrapped));
    otherCurve.grant.curveName = "secp256k1";
    expectError(() => unwrapDataKey(otherCurve, priv, pub, binding), "Encoding");
    const badKind = structuredClone(entry.wrapped) as { recipientKind: string };
    badKind.recipientKind = "processor";
    expectError(() => parseWrappedDataKey(badKind), "Encoding");
    const extra = structuredClone(entry.wrapped) as Record<string, unknown>;
    extra.unexpected = 1;
    expectError(() => parseWrappedDataKey(extra), "Encoding");

    const senderPub = Buffer.from(entry.wrapped.grant.senderPublicKey, "hex");
    const rewrap = (plaintext: string): WrappedDataKey => {
      const copy = wrapCase(entry);
      copy.grant.ciphertext = testGrantEncrypt(
        Buffer.from(entry.senderPrivHex, "hex"),
        senderPub,
        pub,
        Buffer.from(entry.saltHex, "hex"),
        Buffer.from(entry.ivHex, "hex"),
        Buffer.from(plaintext, "utf8")
      );
      return copy;
    };
    const canonical = wrappedVector.wrappedPlaintextUtf8;
    assert.equal(unwrapDataKey(rewrap(canonical), priv, pub, binding).toString("hex"), wrappedVector.dekHex);
    for (const forged of [
      canonical.replace("{", "{\"extra\":true,"),
      canonical.replace(":", ": "),
      canonical.replace("090a0b", "090A0B")
    ]) {
      expectError(() => unwrapDataKey(rewrap(forged), priv, pub, binding), "Encoding");
    }
  });
});

describe("state snapshot manifests", () => {
  const parsed = manifestVector.cases.map((entry) => ({
    entry,
    manifest: parseManifest(JSON.parse(entry.manifestJson) as unknown)
  }));
  const genesis = parsed[0];
  const successor = parsed[1];
  assert.ok(genesis !== undefined && successor !== undefined);

  it("reproduces canonical bytes, digests, signatures, and the successor link", () => {
    assert.equal(manifestVector.format, "liskov-state-manifest-v1");
    assert.equal(manifestVector.signatureDomain, MANIFEST_SIGNATURE_DOMAIN);
    for (const { entry, manifest } of parsed) {
      assert.equal(canonicalBytes(manifest).toString("hex"), entry.canonicalHex, entry.name);
      assert.equal(manifestDigest(manifest).toString("hex"), entry.digestHex);
      assert.equal(signManifest(manifest, Buffer.from(entry.signerSeedHex, "hex")).toString("hex"), entry.signatureHex);
      const digest = verifyManifestSignature(
        manifest,
        Buffer.from(entry.signatureHex, "hex"),
        manifest.writer.signerPublicKey
      );
      assert.equal(digest.toString("hex"), entry.digestHex);
    }
    assert.equal(genesis.manifest.sequence, 1);
    assert.equal(genesis.manifest.previousManifestDigest, undefined);
    assert.equal(Buffer.from(successor.manifest.previousManifestDigest ?? Buffer.alloc(0)).toString("hex"), genesis.entry.digestHex);
    verifySuccessor(genesis.manifest, successor.manifest);
  });

  it("refuses a bad signature, the wrong signer, and a broken chain", () => {
    const flipped = Buffer.from(successor.entry.signatureHex, "hex");
    flipped[0] ^= 0x01;
    expectError(
      () => verifyManifestSignature(successor.manifest, flipped, successor.manifest.writer.signerPublicKey),
      "BadSignature"
    );
    expectError(
      () => verifyManifestSignature(successor.manifest, Buffer.from(successor.entry.signatureHex, "hex"), genesis.manifest.writer.signerPublicKey),
      "SignerMismatch"
    );
    expectError(() => signManifest(successor.manifest, Buffer.from(genesis.entry.signerSeedHex, "hex")), "SignerMismatch");

    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const forgedKey = createPrivateKey({
      key: Buffer.concat([prefix, Buffer.from(genesis.entry.signerSeedHex, "hex")]),
      format: "der",
      type: "pkcs8"
    });
    const digest = manifestDigest(successor.manifest);
    const domain = Buffer.from(MANIFEST_SIGNATURE_DOMAIN, "ascii");
    const forged = sign(null, Buffer.concat([domain, digest]), forgedKey);
    expectError(
      () => verifyManifestSignature(successor.manifest, forged, successor.manifest.writer.signerPublicKey),
      "BadSignature"
    );
    const undomained = sign(null, digest, createPrivateKey({
      key: Buffer.concat([prefix, Buffer.from(successor.entry.signerSeedHex, "hex")]),
      format: "der",
      type: "pkcs8"
    }));
    expectError(
      () => verifyManifestSignature(successor.manifest, undomained, successor.manifest.writer.signerPublicKey),
      "BadSignature"
    );

    const changed = cloneManifest(successor.manifest);
    changed.capturedAtMs += 1;
    expectError(
      () => verifyManifestSignature(changed, Buffer.from(successor.entry.signatureHex, "hex"), changed.writer.signerPublicKey),
      "BadSignature"
    );
    const reordered = cloneManifest(successor.manifest);
    const first = reordered.recipients[0];
    const second = reordered.recipients[1];
    assert.ok(first !== undefined && second !== undefined);
    reordered.recipients[0] = second;
    reordered.recipients[1] = first;
    assert.notEqual(canonicalBytes(reordered).toString("hex"), successor.entry.canonicalHex);

    const left = cloneManifest(genesis.manifest);
    left.org = "ab";
    left.application = "c";
    const right = cloneManifest(genesis.manifest);
    right.org = "a";
    right.application = "bc";
    assert.notEqual(manifestDigest(left).toString("hex"), manifestDigest(right).toString("hex"));

    const gapped = cloneManifest(successor.manifest);
    gapped.sequence = 3;
    expectError(() => verifySuccessor(genesis.manifest, gapped), "SequenceGap", { previous: 1, next: 3 });
    expectError(() => verifySuccessor(successor.manifest, successor.manifest), "SequenceNotAdvanced", { previous: 2, next: 2 });
    expectError(() => verifySuccessor(successor.manifest, genesis.manifest), "SequenceNotAdvanced", { previous: 2, next: 1 });
    const repeat = cloneManifest(successor.manifest);
    repeat.sequence = 1;
    delete repeat.previousManifestDigest;
    expectError(() => verifySuccessor(genesis.manifest, repeat), "SequenceNotAdvanced", { previous: 1, next: 1 });

    const otherGenesis = cloneManifest(genesis.manifest);
    otherGenesis.capturedAtMs += 1;
    expectError(() => verifySuccessor(otherGenesis, successor.manifest), "Fork");
    const forked = cloneManifest(successor.manifest);
    forked.previousManifestDigest = Buffer.alloc(32);
    expectError(() => verifySuccessor(genesis.manifest, forked), "Fork");

    const crossed = cloneManifest(genesis.manifest);
    crossed.org = "org_other";
    expectError(() => verifySuccessor(successor.manifest, crossed), "CrossLineage", { field: "org" });
    for (const [field, mutate] of [
      ["org", (manifest: Manifest) => { manifest.org = "org_other"; }],
      ["application", (manifest: Manifest) => { manifest.application = "app_other"; }],
      ["lineage", (manifest: Manifest) => { manifest.lineage = "stl_other"; }]
    ] as const) {
      const next = cloneManifest(successor.manifest);
      mutate(next);
      expectError(() => verifySuccessor(genesis.manifest, next), "CrossLineage", { field });
    }

    const oversized = cloneManifest(successor.manifest);
    oversized.plaintextBytes += 1;
    const declared = successor.manifest.plaintextBytes + 1;
    const chunks = successor.manifest.plaintextBytes;
    expectError(() => verifySuccessor(genesis.manifest, oversized), "SizeMismatch", { declared, chunks });
    expectError(() => canonicalBytes(oversized), "SizeMismatch", { declared, chunks });
    expectError(
      () => verifyManifestSignature(oversized, Buffer.from(successor.entry.signatureHex, "hex"), successor.manifest.writer.signerPublicKey),
      "SizeMismatch",
      { declared, chunks }
    );
    expectError(() => signManifest(oversized, Buffer.from(successor.entry.signerSeedHex, "hex")), "SizeMismatch", { declared, chunks });
    expectError(() => verifySuccessor(oversized, successor.manifest), "SizeMismatch", { declared, chunks });
  });

  it("gives a malformed manifest no canonical bytes and refuses a loose transport rendering", () => {
    const cases: [string, Manifest, (manifest: Manifest) => void][] = [
      ["v", genesis.manifest, (manifest) => { manifest.v = 2; }],
      ["org", genesis.manifest, (manifest) => { manifest.org = ""; }],
      ["writer.jobId", genesis.manifest, (manifest) => { manifest.writer.jobId = ""; }],
      ["sequence", genesis.manifest, (manifest) => { manifest.sequence = 0; }],
      ["previousManifestDigest", genesis.manifest, (manifest) => { manifest.previousManifestDigest = Buffer.alloc(32); }],
      ["previousManifestDigest", successor.manifest, (manifest) => { delete manifest.previousManifestDigest; }],
      ["capturedAtMs", genesis.manifest, (manifest) => { manifest.capturedAtMs = Number.MAX_SAFE_INTEGER + 1; }],
      ["recipients[].dekVersion", genesis.manifest, (manifest) => { manifest.recipients[0]!.dekVersion += 1; }],
      ["recipients[].recipientKeyId", genesis.manifest, (manifest) => {
        manifest.recipients[0]!.recipientKeyId = manifest.recipients[0]!.recipientKeyId.toUpperCase();
      }]
    ];
    for (const [field, base, mutate] of cases) {
      const manifest = cloneManifest(base);
      mutate(manifest);
      expectError(() => canonicalBytes(manifest), "Malformed", { field });
    }

    const valid = JSON.parse(successor.entry.manifestJson) as Record<string, unknown>;
    const explicitNull = structuredClone(valid);
    explicitNull.previousManifestDigest = null;
    expectError(() => parseManifest(explicitNull), "Malformed", { field: "previousManifestDigest" });
    const unknown = structuredClone(valid);
    unknown.signature = "00";
    expectError(() => parseManifest(unknown), "Malformed", { field: "manifest" });
    const upper = structuredClone(valid) as { writer: { signerPublicKey: string } };
    upper.writer.signerPublicKey = upper.writer.signerPublicKey.toUpperCase();
    expectError(() => parseManifest(upper), "Malformed", { field: "writer.signerPublicKey" });
    const short = structuredClone(valid) as { chunks: { id: string }[] };
    short.chunks[0]!.id = "00";
    expectError(() => parseManifest(short), "Malformed", { field: "chunks[].id" });
  });
});
