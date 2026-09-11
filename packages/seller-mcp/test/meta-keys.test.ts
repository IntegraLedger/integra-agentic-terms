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
 */

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
      expect.arrayContaining(["x402/payment", "x402/payment-response"]),
    );
  });

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
    expect(faults("x402/-payment")[0]?.why).toMatch(/alphanumeric-bounded/);
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
