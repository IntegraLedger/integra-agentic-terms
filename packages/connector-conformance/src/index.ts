/**
 * The connector conformance vectors, published so that a platform can hold its own connector to the wire
 * contract without asking anyone.
 *
 * ⛔⛔ THE VECTORS ARE THE PRODUCT; THIS MODULE IS A LOADER AND NOTHING ELSE. It does not implement the
 * contract, and it deliberately cannot check a connector for you — a conformance artifact that shipped a
 * reference implementation alongside the vectors would tempt a port to agree with the implementation
 * rather than with the contract, which is the same defect as a suite asserting a constant against itself.
 * What ships here is the document, the digest that pins it, and enough typing to read it.
 *
 * ## WHY THE DOCUMENT LIVES UNDER `src/`
 *
 * Because that is the directory this repository's published-parity gate compares byte for byte against the
 * registry. A conformance artifact whose published bytes are not held against the bytes in this tree is a
 * promise nobody checks, and the whole value of a vector document is that the copy a platform fetched is
 * the copy that was reviewed. Shipping it as `src/` puts it inside that subject set rather than beside it.
 *
 * ## ⛔ THE DIGEST IS PINNED HERE AND IT IS NOT DERIVED FROM THE FILE
 *
 * `CONNECTOR_CONFORMANCE_V1_SHA256` is a literal. A constant computed from the file it describes agrees
 * with it by construction and can never disagree — the shape this estate calls a control that cannot fail.
 * Held as a literal, any edit to the document makes the drive beside this file go red, and a reader who
 * fetched the tarball can compare the value on the npmjs page with the bytes they hold.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The vector document's own version. A second document would be `v2`, never an edit to this one. */
export const CONNECTOR_CONFORMANCE_VERSION = 1;

/**
 * The SHA-256 of `connector-conformance-v1.json`, as a lowercase hex digest.
 *
 * ⛔ A LITERAL, DELIBERATELY. See the note above: computing it from the file would make every comparison
 * against it vacuous. The same value ships beside the document as `connector-conformance-v1.json.sha256`
 * in `shasum -a 256 -c` format, so a platform can verify the file it fetched with stock tools and never
 * has to run this package at all.
 */
export const CONNECTOR_CONFORMANCE_V1_SHA256 =
  "feebda1eac16b5f25ce1150612b5c099a62706077b5b13d6332635dcef46e521";

/** What a connector must do with a vector's request. */
export type ConformanceOutcome = "accept" | "reject";

/** The reason a refusal must give. ⛔ The order the four checks run in is part of the contract. */
export type ConformanceRejection =
  | "malformed-header"
  | "stale-timestamp"
  | "bad-signature"
  | "operation-mismatch";

/** One vector: a request, the clock it is judged against, and the answer the contract requires. */
export interface ConformanceVector {
  /** Stable across versions of the document; a platform reports failures by this name. */
  readonly id: string;
  /** Why this case exists, in one sentence, for whoever is reading a red. */
  readonly why: string;
  /** ⚠️ A PUBLISHED conformance secret — fixed so the signature is reproducible. Never a credential. */
  readonly secret: string;
  /** The operation of the endpoint the request arrived on, which is not always what the envelope claims. */
  readonly endpointOperation: string;
  /** ⛔ The bytes that were signed. Signed as received: never parsed and re-serialised. */
  readonly rawBody: string;
  /** The `t=…,v1=…` header as sent, including the shapes that do not parse. */
  readonly signatureHeader: string;
  /** The instant the connector is to believe it is, in Unix seconds. */
  readonly nowSeconds: number;
  /** The skew the connector is to allow, in seconds, in both directions. */
  readonly toleranceSeconds: number;
  /** What the contract requires. */
  readonly expect: ConformanceOutcome;
  /** The reason, when `expect` is `reject`; `null` when it is `accept`. */
  readonly rejection: ConformanceRejection | null;
}

/** The document as published. */
export interface ConformanceDocument {
  readonly conformanceVersion: number;
  readonly contractVersion: number;
  /** The signing string the HMAC is computed over, as a shape rather than an example. */
  readonly signingStringShape: string;
  /** The label each operation binds inside the HMAC, keyed by operation. */
  readonly labels: Readonly<Record<string, string>>;
  /** What the vectors were derived from, so a reader can see what is and is not covered. */
  readonly derivedFrom: {
    readonly groups: readonly string[];
    readonly operations: readonly string[];
    readonly seams: readonly string[];
  };
  /** ⛔ Stated in the document AND checked against `vectors.length` by the drive beside this file. */
  readonly count: number;
  readonly vectors: readonly ConformanceVector[];
}

/**
 * The absolute path of the published vector document.
 *
 * ⭐ `../src/` RESOLVES CORRECTLY FROM BOTH HALVES OF THE TARBALL, and that is why it is spelled this way
 * rather than `./`. `dist/` and `src/` are siblings at the same depth, so `../src/<name>` names the same
 * file whether this module is loaded as built JavaScript from `dist/` or as TypeScript from `src/` — which
 * the drive beside this file does.
 */
export function vectorsPath(): string {
  return fileURLToPath(
    new URL("../src/connector-conformance-v1.json", import.meta.url),
  );
}

/**
 * The path of the digest sidecar, in `shasum -a 256 -c` format.
 *
 * ⛔ IT IS REACHED BY PATH AND NOT BY A SUBPATH EXPORT, AND THAT IS NOT AN OVERSIGHT. `exports` once
 * declared `./connector-conformance-v1.json.sha256`, and `attw --pack` refused it on every resolution
 * mode — `.sha256` is not an extension Node's resolver can load, so the entry was a promise the resolver
 * cannot keep. ⚠️ `pnpm verify` does not run `attw`; the CI `verify` job does, which is where it was
 * caught. The vector document itself IS a subpath export, because JSON resolves.
 */
export function digestPath(): string {
  return fileURLToPath(
    new URL("../src/connector-conformance-v1.json.sha256", import.meta.url),
  );
}

/** The document's bytes, exactly as published. ⛔ Bytes, because the digest is over bytes. */
export function readVectorBytes(): Buffer {
  return readFileSync(vectorsPath());
}

/** The SHA-256 of whatever bytes are on disk — which is not the same claim as the pinned constant. */
export function digestOf(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * The document, parsed — after checking that the bytes are the bytes this package pins.
 *
 * ⛔ IT THROWS RATHER THAN WARNING. A vector document that is not the one the digest names is not a
 * weaker version of the artifact; it is a different artifact, and a conformance run over it says nothing.
 *
 * ⭐ `path` IS A SEAM AND NOT A FEATURE. Nothing outside the drive beside this file should pass it: it
 * exists so the refusal above can be EXERCISED against a document that really is different, rather than
 * asserted about. A refusal nothing has ever driven is a branch, not a guarantee.
 */
export function loadVectors(path: string = vectorsPath()): ConformanceDocument {
  const bytes = readFileSync(path);
  const actual = digestOf(bytes);
  if (actual !== CONNECTOR_CONFORMANCE_V1_SHA256)
    throw new Error(
      `connector-conformance: ${path} hashes to ${actual}, and this package pins ` +
        `${CONNECTOR_CONFORMANCE_V1_SHA256}. Refusing to load a vector document that is not the one ` +
        "this version publishes — a conformance verdict over unknown bytes is not a verdict.",
    );
  return JSON.parse(bytes.toString("utf8")) as ConformanceDocument;
}
