/**
 * The drive for the published vector document.
 *
 * ⛔⛔ WHAT THIS FILE IS FOR: a copy of `connector-conformance-v1.json` that has drifted from the digest
 * this package pins must go RED here, before it can reach a registry. The document is the whole product,
 * it is not generated in this repository, and nothing else in this tree would notice a byte of it moving.
 *
 * ⭐ THE ASSERTION IS AGAINST A LITERAL, NOT AGAINST A RECOMPUTED VALUE. `digestOf(readVectorBytes())`
 * compared with `digestOf(readVectorBytes())` is a control that cannot fail.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CONNECTOR_CONFORMANCE_V1_SHA256,
  CONNECTOR_CONFORMANCE_VERSION,
  type ConformanceRejection,
  digestOf,
  digestPath,
  loadVectors,
  readVectorBytes,
  vectorsPath,
} from "../src/index.js";

describe("the published vector document", () => {
  it("hashes to the digest this package pins", () => {
    expect(digestOf(readVectorBytes())).toBe(CONNECTOR_CONFORMANCE_V1_SHA256);
  });

  it("ships a sidecar carrying that same digest, in `shasum -a 256 -c` format", () => {
    const sidecar = readFileSync(digestPath(), "utf8");
    // ⛔ BOTH HALVES. A sidecar naming the right digest against the wrong filename verifies nothing when
    // a reader runs `shasum -a 256 -c`, and one naming the right filename against a stale digest is the
    // defect this whole file exists for.
    const [digest, name] = sidecar.trim().split(/\s+/);
    expect(digest).toBe(CONNECTOR_CONFORMANCE_V1_SHA256);
    expect(name).toBe("connector-conformance-v1.json");
  });

  it("is loadable, and states its own version", () => {
    const doc = loadVectors();
    expect(doc.conformanceVersion).toBe(CONNECTOR_CONFORMANCE_VERSION);
    expect(doc.contractVersion).toBe(1);
    expect(doc.signingStringShape).toBe("<t>.<label>.<rawBody>");
  });

  it("carries the number of vectors it says it carries", () => {
    const doc = loadVectors();
    // ⛔ THE DOCUMENT'S OWN `count` IS NOT EVIDENCE OF ITSELF — it is held against the array, and the
    // array is held against a literal, so a vector silently dropped cannot be absorbed by the field
    // that describes it moving with it.
    expect(doc.vectors).toHaveLength(doc.count);
    expect(doc.count).toBe(22);
  });

  it("covers both endpoint operations, all four refusal reasons, and both outcomes", () => {
    const doc = loadVectors();
    // ⛔ A SUBJECT-SET FLOOR, NOT DECORATION. A document trimmed to its five accepting vectors would still
    // hash, still load, and still say `count` correctly — and a connector that refuses nothing would pass
    // it. What a platform is held to is the REFUSALS, so their presence is asserted by name.
    const reasons = new Set(
      doc.vectors.map((v) => v.rejection).filter((r) => r !== null),
    );
    const required: readonly ConformanceRejection[] = [
      "malformed-header",
      "stale-timestamp",
      "bad-signature",
      "operation-mismatch",
    ];
    for (const reason of required) expect(reasons.has(reason)).toBe(true);
    expect(reasons.size).toBe(required.length);

    expect(new Set(doc.vectors.map((v) => v.endpointOperation))).toEqual(
      new Set(["mint", "observe"]),
    );
    expect(doc.vectors.some((v) => v.expect === "accept")).toBe(true);
    expect(doc.vectors.some((v) => v.expect === "reject")).toBe(true);
  });

  it("states a rejection reason for every refusal and none for any acceptance", () => {
    for (const v of loadVectors().vectors) {
      if (v.expect === "reject") expect(v.rejection).not.toBeNull();
      else expect(v.rejection).toBeNull();
    }
  });

  it("names every vector uniquely, because a platform reports a red by id", () => {
    const doc = loadVectors();
    expect(new Set(doc.vectors.map((v) => v.id)).size).toBe(doc.vectors.length);
  });

  it("binds each operation's label under the `connector/` namespace", () => {
    const doc = loadVectors();
    expect(doc.labels).toEqual({
      mint: "connector/mint",
      observe: "connector/observe",
    });
  });
});

describe("loading a document that is not the published one", () => {
  it("REFUSES, rather than returning a document a verdict would be given over", () => {
    // ⭐ DRIVEN, NOT ASSERTED ABOUT. One byte of the real document changed, on disk, and the loader is
    // pointed at it: the refusal has to happen for this to pass, and a `digest === pinned` check deleted
    // from `loadVectors` makes this test red rather than merely uncovered.
    const bytes = readVectorBytes();
    const drifted = Buffer.from(bytes);
    const at = drifted.indexOf("conformanceVersion");
    expect(at).toBeGreaterThan(-1);
    drifted[at] = drifted[at] === 0x63 ? 0x43 : 0x63;
    expect(digestOf(drifted)).not.toBe(CONNECTOR_CONFORMANCE_V1_SHA256);

    const dir = mkdtempSync(join(tmpdir(), "connector-conformance-"));
    const path = join(dir, "connector-conformance-v1.json");
    writeFileSync(path, drifted);

    expect(() => loadVectors(path)).toThrow(/hashes to .* and this package pins/s);
  });

  it("accepts the published document by the same door, so the refusal discriminates", () => {
    // ⛔ THE NEGATIVE CONTROL FOR THE TEST ABOVE. A `loadVectors` that threw unconditionally would pass
    // it; nothing here would notice without this line.
    expect(() => loadVectors(vectorsPath())).not.toThrow();
  });
});
