import type { Assurance } from "@integraledger/lcp-authority";
import type { LegalContextJson } from "@integraledger/lcp-discovery";
import type { Disposition } from "./decision.js";

/**
 * The buyer's stated policy.
 *
 * **`onNotAttempted` is the only gap disposition here, and its absent sibling is the point.** An earlier
 * shape also required `onIndeterminate`, which `evaluate` never read — and could not have, because no step
 * it runs yields `indeterminate`: the fingerprint proves or fails, and the record parses or does not. A
 * required field promising a disposition the gate cannot reach is worse than no field, because a buyer
 * reads it as a control. Consumers folding their own step ladders use `decideOutcome`, which carries its
 * own four-valued gaps shape and does handle `indeterminate`.
 */
export interface BuyerPolicy {
  readonly requiredLevel: 1 | 2 | 3 | 4;
  readonly acceptableJurisdictions: readonly string[] | "any";
  readonly acceptableDisputeMethods: readonly string[] | "any";
  readonly maxCommitment: Readonly<Record<string, string>>;
  readonly forbiddenClauseCategories: readonly string[];
  readonly requiredAssurance: Assurance | "any";
  readonly onNotAttempted: Disposition;
}
export type PolicyResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly detail: string };

const accepts = (
  allow: readonly string[] | "any",
  v: string | undefined,
): boolean => (allow === "any" ? true : v !== undefined && allow.includes(v));

/** Evaluate the buyer policy on the TYPED legal-context envelope + the typed offer — NEVER on prose (LCP §12.7).
 *  Every check reads a structured field; the function's inputs cannot carry the natural-language body. */
export function evaluatePolicy(
  policy: BuyerPolicy,
  terms: LegalContextJson,
  offer: { amount: string; unit: string },
): PolicyResult {
  // NARROWED, not cast — the same treatment `clauseCategories` gets below, and for the same reason. The
  // cast that stood here asserted `{ jurisdiction?: string; method?: string }` about a value the discovery
  // parser never checked, which made the two fields policy actually reads the two the type system was not
  // checking. It failed closed, so this was never a bypass: a seller publishing `"disputeResolution":
  // "arbitration"` yielded `undefined` for both members and declined. It declined for the WRONG REASON —
  // "jurisdiction (none) not acceptable" tells a seller its jurisdiction is unacceptable when its actual
  // defect is that the field is a string. A gate whose refusals misdescribe the defect cannot be acted on,
  // and being right by accident is not the same as being right.
  const rawDr = (terms as { disputeResolution?: unknown }).disputeResolution;
  if (
    rawDr !== undefined &&
    (typeof rawDr !== "object" || rawDr === null || Array.isArray(rawDr))
  )
    return {
      ok: false,
      code: "policy/malformed-dispute-resolution",
      detail: `seller's disputeResolution is ${Array.isArray(rawDr) ? "an array" : rawDr === null ? "null" : typeof rawDr}, not an object`,
    };
  const drRecord = (rawDr ?? {}) as Readonly<Record<string, unknown>>;
  // A member that is present and not a string is the seller's defect too, named rather than silently read
  // as absent. Absent stays absent: that is the ordinary "no jurisdiction declared" path, and it is the
  // buyer's stated policy that decides whether absence is acceptable.
  for (const member of ["jurisdiction", "method"] as const) {
    const v = drRecord[member];
    if (v !== undefined && typeof v !== "string")
      return {
        ok: false,
        code: "policy/malformed-dispute-resolution",
        detail: `seller's disputeResolution.${member} is ${typeof v}, not a string`,
      };
  }
  // NOT optionally chained, and the narrowing above is why. The cast that stood here produced a possibly
  // absent object, so every read was `dr?.member`; the loop has now proved both members are a string or
  // absent, so the object is always there and `?.` could never short-circuit. Mutation testing is what
  // surfaced it — four optional-chaining mutants survived because no input could reach the branch they
  // removed, which is the signature of a branch that cannot happen.
  const jurisdiction = drRecord["jurisdiction"] as string | undefined;
  const method = drRecord["method"] as string | undefined;
  if (!accepts(policy.acceptableJurisdictions, jurisdiction))
    return {
      ok: false,
      code: "policy/jurisdiction",
      detail: `jurisdiction ${jurisdiction ?? "(none)"} not acceptable`,
    };
  if (!accepts(policy.acceptableDisputeMethods, method))
    return {
      ok: false,
      code: "policy/dispute-method",
      detail: `dispute method ${method ?? "(none)"} not acceptable`,
    };
  // `Object.hasOwn`, never a bare index read. `offer.unit` is SELLER-DERIVED — on the ACP path it is the
  // session's `currency`, an unconstrained string — so a bare read answers from `Object.prototype` for
  // `constructor`, `toString`, `valueOf`, `hasOwnProperty` or `__proto__`. Each returns a non-undefined
  // non-string, slips past the `undefined` check below, and reaches `BigInt()`, which throws a SyntaxError
  // out of `evaluate` naming nothing a buyer can act on. An own-property read makes every one of them the
  // ordinary "no cap declared" decline.
  const cap = Object.hasOwn(policy.maxCommitment, offer.unit)
    ? policy.maxCommitment[offer.unit]
    : undefined;
  if (typeof cap !== "string")
    return {
      ok: false,
      code: "policy/unit",
      detail: `no cap declared for unit ${offer.unit}`,
    };
  if (BigInt(offer.amount) > BigInt(cap))
    return {
      ok: false,
      code: "policy/over-cap",
      detail: `offer ${offer.amount} exceeds cap ${cap} (${offer.unit})`,
    };
  // NARROWED, not cast. `clauseCategories` is not in the discovery schema at all — it arrives through the
  // record's loose index signature as `unknown`, so it is whatever the SELLER wrote. A cast asserting
  // `readonly string[]` was a claim about a hostile value: a seller publishing `"clauseCategories":
  // "arbitration"` made `cats.find` a TypeError that escaped `evaluate` entirely, past its contract to
  // RETURN a GateDecision. A malformed field is now the seller's defect, named as such and declined.
  const raw = (terms as { clauseCategories?: unknown }).clauseCategories;
  if (raw !== undefined && !Array.isArray(raw))
    return {
      ok: false,
      code: "policy/malformed-clause-categories",
      detail: `seller's clauseCategories is ${typeof raw}, not an array of category strings`,
    };
  const cats: readonly unknown[] = raw ?? [];
  const forbidden = cats.find(
    (c): c is string =>
      typeof c === "string" && policy.forbiddenClauseCategories.includes(c),
  );
  if (forbidden !== undefined)
    return {
      ok: false,
      code: "policy/forbidden-clause",
      detail: `forbidden clause category: ${forbidden}`,
    };
  return { ok: true };
}
