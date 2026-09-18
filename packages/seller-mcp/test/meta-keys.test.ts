/**
 * ⛔⛔ THE `_meta` KEYS THIS ADAPTER EMITS, HELD AGAINST MCP'S PUBLISHED GRAMMAR.
 *
 * A conformance pass asked whether `x402/payment` should be reverse-DNS. The answer is recorded in
 * `mcp.ts` — it is x402's key, it is conformant, and the reverse-DNS rule is a SHOULD binding the party
 * that chooses the prefix. What that answer must not be is *prose*: a comment asserting a check is not a
 * check, and a published package carries its comments to strangers who cannot re-derive them.
 *
 * ⇒ The grammar is transcribed here from MCP's own published text and DRIVEN over whatever this module
 * exports, so the claim "these keys are conformant" is a measurement rather than an assertion.
 *
 * ⚠️ **Scoped to this module on purpose.** `_meta` is MCP's field and this is the MCP adapter, so this is
 * the only place that reads or writes one. A wider scan would have to grep source text for a field name,
 * which is the shape of gate that ends up satisfied by a comment.
 *
 * ⭐⭐ **AND SINCE v1.1 OF THE EXTENSION SPECIFICATION THE SUBJECT SET HAS A SECOND HALF, READ FROM THE
 * DOCUMENT.** That specification's rule is that a `com.integraledger/` key **MUST** be specified there
 * before it is emitted, so the document — not this file, and not any module's exports — is where the
 * spelling of an LCP key is decided. This drive therefore PARSES the seven keys out of the document's own
 * table and runs the same published grammar over them. Two consequences, both deliberate:
 *
 *   1. A key added to the specification is checked without anybody remembering to list it here, exactly as
 *      the adapter's exported keys already are.
 *   2. The spellings are ALSO pinned as literals below, because a table this file derives its subject set
 *      from could be misspelled in the document and agree with itself forever. Derivation catches an
 *      omission; the pin catches a rewrite. Neither alone is the check.
 *
 * ⚠️ **This package does not export the seven, and that is not an oversight.** They are the wire contract
 * of a door built elsewhere; the constants live with the door that emits them. What lives here is the
 * grammar and the document, which is what a stranger reading the published specification has.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as adapter from "../src/index.js";

/**
 * One label of a `_meta` prefix, per the published text: *"Labels MUST start with a letter and end with a
 * letter or digit; interior characters can be letters, digits, or hyphens."*
 */
const LABEL = /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

/**
 * The name segment: *"Unless empty, MUST begin and end with an alphanumeric character. MAY contain hyphens,
 * underscores, dots, and alphanumerics in between."*
 */
const NAME = /^(?:[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)?$/;

interface KeyFault {
  readonly key: string;
  readonly why: string;
}

/** Every fault the published grammar finds in one key — empty means conformant. */
function faults(key: string): readonly KeyFault[] {
  const found: KeyFault[] = [];
  const slash = key.indexOf("/");
  // A key with no prefix is legal; one with more than one slash is not a prefix + name pair.
  if (slash !== key.lastIndexOf("/"))
    found.push({
      key,
      why: "more than one `/` — a key is a prefix and a name",
    });
  const prefix = slash === -1 ? "" : key.slice(0, slash);
  const name = slash === -1 ? key : key.slice(slash + 1);

  if (!NAME.test(name))
    found.push({ key, why: `name "${name}" is not alphanumeric-bounded` });

  if (prefix !== "") {
    const labels = prefix.split(".");
    for (const label of labels)
      if (!LABEL.test(label))
        found.push({ key, why: `label "${label}" is malformed` });
    // *"Any prefix where the SECOND label is `modelcontextprotocol` or `mcp` is reserved for MCP use."*
    if (labels[1] === "modelcontextprotocol" || labels[1] === "mcp")
      found.push({ key, why: `prefix "${prefix}/" is reserved for MCP` });
    // ⭐ THE HALF THAT BINDS US. The reverse-DNS SHOULD applies to whoever chooses the prefix; where that is
    // Integra, forward notation is the failure to catch — `integraledger.com/` rather than
    // `com.integraledger/`. A prefix naming us must not lead with us.
    if (labels.includes("integraledger") && labels[0] === "integraledger")
      found.push({
        key,
        why: `prefix "${prefix}/" is forward DNS — a namespace Integra owns is written reverse (com.integraledger/…)`,
      });
  }
  return found;
}

/** Namespaced string constants this module publishes — derived, never listed. */
const emitted = Object.entries(adapter).flatMap(([name, value]) =>
  typeof value === "string" && value.includes("/") ? [{ name, value }] : [],
);

/**
 * The extension specification, read from the tree rather than restated. A missing file THROWS — a drive
 * that cannot find its subject must not report clean, which is the failure mode every blind gate in this
 * repository has taken.
 */
const SPEC_PATH = new URL(
  "../../../docs/2026-08-25-lcp-mcp-extension-specification.md",
  import.meta.url,
);

/**
 * The keys §4.1 of that document specifies: the first column of its table, whatever it says.
 *
 * ⛔ **Scoped to §4.1, not to the whole document**, and the scope is the load-bearing part: §2 names
 * `com.integraledger/legal-context`, which is the extension IDENTIFIER and not a `_meta` key at all, and
 * §4.5 names it again to say so. A document-wide scan would sweep it into the subject set and then assert
 * that an identifier conforms to a key grammar — a true sentence about the wrong thing.
 *
 * ⛔⛔ **AND THE MATCH IS POSITIONAL, NOT BY PREFIX, WHICH IS THE WHOLE POINT.** The first form of this
 * function matched code spans against `com\.integraledger\/…`. Driven with `com.4integraledger/http-status`
 * planted in the table, the malformed key **dropped out of the subject set** and the grammar never saw it —
 * the count below caught the plant, and the grammar sweep this file exists for stayed green on a key it was
 * supposed to refuse. A subject set filtered by the property under test can only ever contain keys that
 * already have it. Reading the column by position admits whatever is written there, so a misspelled prefix
 * arrives at the grammar rather than vanishing before it.
 */
function specifiedKeys(): readonly string[] {
  const spec = readFileSync(SPEC_PATH, "utf8");
  const start = spec.indexOf("### 4.1 ");
  if (start === -1)
    throw new Error(
      `no §4.1 heading in ${SPEC_PATH.pathname} — the specification moved and this drive is reading nothing`,
    );
  const rest = spec.slice(start);
  const end = rest.indexOf("\n### ", 1);
  const section = end === -1 ? rest : rest.slice(0, end);
  const keys: string[] = [];
  for (const line of section.split("\n")) {
    if (!line.startsWith("|")) continue;
    const first = line.split("|")[1]?.trim() ?? "";
    const span = /^`([^`]+)`$/.exec(first);
    if (span?.[1] !== undefined) keys.push(span[1]);
  }
  return keys;
}

/**
 * ⛔ The spellings, pinned. See the file header: the derived list catches a key the document gained and
 * this file did not; this list catches a key the document RENAMED, which a derivation agrees with by
 * construction. `relay-stage` is the seventh and the only one not carried from a header — it exists for
 * the result on which no HTTP response arrived at all, where there is no header to carry.
 */
const SPECIFIED = [
  "com.integraledger/atr-hash",
  "com.integraledger/payment-identifier",
  "com.integraledger/receipt",
  "com.integraledger/refusal",
  "com.integraledger/http-status",
  "com.integraledger/relay-stage",
  "com.integraledger/intake",
] as const;

/** The two x402 defines. Literals, because they are x402's spelling and not ours to re-derive. */
const X402 = ["x402/payment", "x402/payment-response"] as const;

/**
 * ⛔⛔ **THE GRAMMAR IS DRIVEN OVER THE DOCUMENT'S OWN KEYS, NOT ONLY OVER THE PINNED LIST, AND THE
 * DIFFERENCE IS THE WHOLE VALUE OF THE PARSE.** Driven with `com.4integraledger/http-status` planted in
 * §4.1, a sweep over `SPECIFIED` alone stayed GREEN on every grammar case and only the comparison below
 * reddened — because a list of literals is a list of keys somebody already checked. The published claim is
 * about what the SPECIFICATION says, so the specification's spellings are what the grammar must meet.
 * Read at module scope on purpose: a missing or moved document throws here, before a single case is
 * collected, rather than leaving an empty subject set to report clean.
 */
const IN_DOCUMENT = specifiedKeys();

/** Every key either side of this file is entitled to hold, each driven once. */
const ALL_KEYS = [...new Set([...IN_DOCUMENT, ...SPECIFIED, ...X402])];

describe("⛔ every `_meta` key this adapter publishes is a valid MCP key name", () => {
  it("⛔ the subject set is non-empty and holds the two keys x402 defines", () => {
    // ⛔ TWO WAYS THIS GATE PASSES FOR THE WRONG REASON, and the second is the one that shipped. A grammar
    // driven over nothing asserts nothing — and a grammar driven over whatever the export happens to say
    // accepts whatever the export happens to say: rename `x402/payment` to anything without a `/` and it
    // drops OUT of the derived set, leaving the remaining key to pass on its own. The set stays DERIVED, so
    // a key added later is checked without anyone remembering to list it; the two spellings a counterparty
    // is entitled to are pinned as literals, because they are x402's and not ours to re-spell.
    expect(emitted.length).toBeGreaterThan(0);
    expect(emitted.map((e) => e.value)).toEqual(
      expect.arrayContaining([...X402]),
    );
  });

  it("⛔ the specification names exactly seven keys, and exactly these", () => {
    // ⛔ The sorted comparison is the check: it catches a key the document gained, lost, renamed or
    // duplicated. The length assertion above it is NOT independent of that — stated plainly, because a
    // second assertion dressed as a second control is how a suite comes to look stronger than it is. It
    // is here because `7` is the number the document's own prose states, so its failure reads as "the
    // table no longer has seven rows" rather than as a diff a reader has to count.
    const parsed = specifiedKeys();
    expect(parsed).toHaveLength(7);
    expect([...parsed].sort()).toEqual([...SPECIFIED].sort());
  });

  it.each(ALL_KEYS.map((key) => [key] as const))(
    "%s is conformant, unreserved, and correctly namespaced",
    (key) => {
      expect(faults(key)).toEqual([]);
    },
  );

  /**
   * ⛔⛔ **THE RESERVATION CLAIM, READ A SECOND WAY, AND THE SECOND WAY IS THE POINT.** The published
   * specification makes this claim in prose — *"none sits under the reserved `io.modelcontextprotocol/`
   * prefix"* — so it gets a drive rather than a share of someone else's.
   *
   * ⚠️ **The first form of this test could not red on its own, and that was a defect.** It asked
   * `faults(key)` for the reserved sentence, which is a SUBSET of the sweep above asserting `faults(key)`
   * empty — measured: under the reserved-prefix plant it failed only in company, and had `faults` lost its
   * reservation branch it would have gone green alongside everything else. A second assertion over the
   * same predicate is not a second reading; it is the same reading written twice, which is exactly what
   * the length assertion above is careful to admit about itself.
   *
   * ⇒ It now reads the prefix's second label DIRECTLY, from the published rule, without calling `faults`
   * at all. Two independent instruments on one claim: delete the reservation branch from `faults` and this
   * still refuses a reserved key; break this and `faults` still does. Driven both ways.
   */
  it.each(ALL_KEYS.map((key) => [key] as const))(
    "%s does not sit under a prefix MCP reserves for itself",
    (key) => {
      const slash = key.indexOf("/");
      const labels = slash === -1 ? [] : key.slice(0, slash).split(".");
      expect(labels[1]).not.toBe("modelcontextprotocol");
      expect(labels[1]).not.toBe("mcp");
    },
  );

  it.each(emitted.map((e) => [e.name, e.value] as const))(
    "%s = %s is conformant, unreserved, and correctly namespaced",
    (_name, value) => {
      expect(faults(value)).toEqual([]);
    },
  );

  /**
   * ⛔ THE CONTROL. Every rule above must be capable of REFUSING, or the cases above pass for the wrong
   * reason — a validator that accepts everything is the vacuous gate this repository has shipped before.
   */
  it("⭐ and the grammar refuses each way a key can be wrong", () => {
    expect(faults("4x02/payment")[0]?.why).toMatch(/label .* is malformed/);
    expect(faults("io.modelcontextprotocol/payment")[0]?.why).toMatch(
      /reserved for MCP/,
    );
    // ⭐ The reservation attaches to the PREFIX, not to the one name already controlled above. A key named
    // after one of ours under that prefix must be refused for the prefix, which is what a door emitting
    // `receipt` would reach for if it ever mistook the reserved namespace for a neutral one.
    expect(faults("io.modelcontextprotocol/receipt")[0]?.why).toMatch(
      /reserved for MCP/,
    );
    // ⛔ AND THE SECOND HALF OF THE SAME PREDICATE, WHICH HAD NO CONTROL. The published rule reserves a
    // prefix whose second label is `modelcontextprotocol` OR `mcp`; every control here drove the first
    // spelling only, so deleting the `mcp` branch left the suite green.
    expect(faults("com.mcp/receipt")[0]?.why).toMatch(/reserved for MCP/);
    expect(faults("x402/-payment")[0]?.why).toMatch(/alphanumeric-bounded/);
    // ⛔ AND THE OTHER DIRECTION. The published rule is that a name begins AND ends with an alphanumeric;
    // a control on the leading character alone passes against a regex anchored only at the start, which is
    // half a grammar reported as a whole one.
    expect(faults("x402/payment-")[0]?.why).toMatch(/alphanumeric-bounded/);
    expect(faults("x402/a/b")[0]?.why).toMatch(/more than one/);
    expect(faults("integraledger.com/legal-context")[0]?.why).toMatch(
      /forward DNS/,
    );
    // ⭐ And it ADMITS the shapes the spec admits: our own reverse-DNS namespace, and a bare name with no
    // prefix at all (`progressToken` is exactly that, and reserved by the spec itself).
    expect(faults("com.integraledger/legal-context")).toEqual([]);
    expect(faults("progressToken")).toEqual([]);
  });
});
