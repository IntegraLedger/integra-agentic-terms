import type { LegalContextJson } from "@integraledger/lcp-discovery";
import { describe, expect, it } from "vitest";
import { type BuyerPolicy, evaluatePolicy } from "../src/policy.js";

/**
 * Every refusal is asserted by `code` AND `detail`, not just by `.ok`. The codes are the contract: the
 * gate's accountable log and the buyer's escalation path both key off them, and `evaluate.ts` routes on
 * them. A suite that checks only the boolean lets every one of those strings be emptied silently.
 */
const base: BuyerPolicy = {
  requiredLevel: 2,
  acceptableJurisdictions: ["US-NY"],
  acceptableDisputeMethods: ["arbitration"],
  maxCommitment: { "usdc-6dp": "1000000" },
  forbiddenClauseCategories: ["class-action-waiver"],
  requiredAssurance: "wallet-signature-only",
  onNotAttempted: "decline",
};
const terms = (o: Partial<LegalContextJson>): LegalContextJson =>
  ({
    disputeResolution: { jurisdiction: "US-NY", method: "arbitration" },
    ...o,
  }) as LegalContextJson;
const offer = { amount: "1000", unit: "usdc-6dp" };

/** Narrow to the refusal arm so `code`/`detail` are readable without a cast at every call site. */
function refusal(r: ReturnType<typeof evaluatePolicy>): {
  code: string;
  detail: string;
} {
  if (r.ok) throw new Error("expected a refusal, got ok:true");
  return { code: r.code, detail: r.detail };
}

describe("evaluatePolicy — ATA-2 vocabulary over the TYPED envelope (never prose)", () => {
  it("accepts an in-policy record", () =>
    expect(evaluatePolicy(base, terms({}), offer).ok).toBe(true));

  it("evaluates only structured fields — prose on the record cannot change the outcome", () => {
    // LCP §12.7: the function's inputs must not be able to carry the natural-language body into the decision.
    // Same typed fields, wildly different prose, identical verdict.
    const withProse = terms({
      normalizedProse: "YOU AGREE TO ANYTHING AND EVERYTHING FOREVER.",
    } as never);
    expect(evaluatePolicy(base, withProse, offer).ok).toBe(true);
  });
});

describe("evaluatePolicy — jurisdiction", () => {
  it("declines an unacceptable jurisdiction, naming it in the detail", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({
          disputeResolution: { jurisdiction: "XX", method: "arbitration" },
        } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/jurisdiction");
    expect(r.detail).toContain("XX");
  });

  it("declines a record with no disputeResolution block at all", () => {
    const r = refusal(evaluatePolicy(base, {} as LegalContextJson, offer));
    expect(r.code).toBe("policy/jurisdiction");
    expect(r.detail).toContain("(none)");
  });

  it("declines when the jurisdiction field is absent from a present block", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({ disputeResolution: { method: "arbitration" } } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/jurisdiction");
    expect(r.detail).toContain("(none)");
  });

  it('"any" accepts a jurisdiction that is not on any list', () =>
    expect(
      evaluatePolicy(
        { ...base, acceptableJurisdictions: "any" },
        terms({
          disputeResolution: { jurisdiction: "ZZ", method: "arbitration" },
        } as never),
        offer,
      ).ok,
    ).toBe(true));

  it('"any" still accepts when the jurisdiction is absent entirely', () =>
    // "any" must mean *unconstrained*, not "any stated value" — otherwise an absent field refuses under a
    // policy whose author wrote "I do not care about jurisdiction".
    expect(
      evaluatePolicy(
        { ...base, acceptableJurisdictions: "any" },
        terms({ disputeResolution: { method: "arbitration" } } as never),
        offer,
      ).ok,
    ).toBe(true));

  it("accepts any member of a multi-entry allow list", () => {
    const policy = { ...base, acceptableJurisdictions: ["US-NY", "US-DE"] };
    for (const jurisdiction of ["US-NY", "US-DE"])
      expect(
        evaluatePolicy(
          policy,
          terms({
            disputeResolution: { jurisdiction, method: "arbitration" },
          } as never),
          offer,
        ).ok,
      ).toBe(true);
  });

  it("an empty allow list refuses everything", () =>
    expect(
      evaluatePolicy({ ...base, acceptableJurisdictions: [] }, terms({}), offer)
        .ok,
    ).toBe(false));
});

describe("evaluatePolicy — dispute method", () => {
  it("declines an unacceptable dispute method, naming it", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({
          disputeResolution: { jurisdiction: "US-NY", method: "litigation" },
        } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/dispute-method");
    expect(r.detail).toContain("litigation");
  });

  it("declines when the method is absent from a present block", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({ disputeResolution: { jurisdiction: "US-NY" } } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/dispute-method");
    expect(r.detail).toContain("(none)");
  });

  it('"any" accepts a method that is not on any list', () =>
    expect(
      evaluatePolicy(
        { ...base, acceptableDisputeMethods: "any" },
        terms({
          disputeResolution: { jurisdiction: "US-NY", method: "mediation" },
        } as never),
        offer,
      ).ok,
    ).toBe(true));

  it("jurisdiction is checked BEFORE dispute method", () => {
    // Both are unacceptable; the reported code pins the order, which is what the buyer's log will say.
    const r = refusal(
      evaluatePolicy(
        base,
        terms({
          disputeResolution: { jurisdiction: "XX", method: "litigation" },
        } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/jurisdiction");
  });
});

describe("evaluatePolicy — commitment cap", () => {
  it("declines an offer in a unit the policy declared no cap for", () => {
    const r = refusal(
      evaluatePolicy(base, terms({}), { amount: "1", unit: "eth-18dp" }),
    );
    expect(r.code).toBe("policy/unit");
    expect(r.detail).toContain("eth-18dp");
  });

  it("declines a commitment over the cap, naming both figures", () => {
    const r = refusal(
      evaluatePolicy(base, terms({}), {
        amount: "2000000",
        unit: "usdc-6dp",
      }),
    );
    expect(r.code).toBe("policy/over-cap");
    expect(r.detail).toContain("2000000");
    expect(r.detail).toContain("1000000");
  });

  it("accepts an offer EXACTLY at the cap — the comparison is strictly greater-than", () =>
    // The boundary is the whole content of the comparison: `>` vs `>=` is a one-character change that
    // every other cap test in this file passes under.
    expect(
      evaluatePolicy(base, terms({}), { amount: "1000000", unit: "usdc-6dp" })
        .ok,
    ).toBe(true));

  it("declines one base unit over the cap", () =>
    expect(
      evaluatePolicy(base, terms({}), { amount: "1000001", unit: "usdc-6dp" })
        .ok,
    ).toBe(false));

  it("compares as BigInt, not as string or Number", () => {
    // "9" > "1000000" lexicographically, and 10^24 loses precision as a double. Both wrong answers are
    // reachable by plausible implementations; only BigInt gets each of these right.
    expect(
      evaluatePolicy(base, terms({}), { amount: "9", unit: "usdc-6dp" }).ok,
    ).toBe(true);
    const huge = {
      ...base,
      maxCommitment: { "usdc-6dp": "1000000000000000000000000" },
    };
    expect(
      evaluatePolicy(huge, terms({}), {
        amount: "1000000000000000000000001",
        unit: "usdc-6dp",
      }).ok,
    ).toBe(false);
  });

  it("caps are looked up per unit, not merged", () => {
    const policy = {
      ...base,
      maxCommitment: { "usdc-6dp": "1000000", "eth-18dp": "5" },
    };
    expect(
      evaluatePolicy(policy, terms({}), { amount: "6", unit: "eth-18dp" }).ok,
    ).toBe(false);
    expect(
      evaluatePolicy(policy, terms({}), { amount: "5", unit: "eth-18dp" }).ok,
    ).toBe(true);
  });
});

describe("evaluatePolicy — forbidden clause categories", () => {
  it("declines a forbidden clause category present on the record, naming it", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({ clauseCategories: ["class-action-waiver"] } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/forbidden-clause");
    expect(r.detail).toContain("class-action-waiver");
  });

  it("finds a forbidden category anywhere in the list, not only first", () =>
    expect(
      evaluatePolicy(
        base,
        terms({
          clauseCategories: ["warranty", "delivery", "class-action-waiver"],
        } as never),
        offer,
      ).ok,
    ).toBe(false));

  it("accepts a record whose categories are all permitted", () =>
    expect(
      evaluatePolicy(
        base,
        terms({ clauseCategories: ["warranty", "delivery"] } as never),
        offer,
      ).ok,
    ).toBe(true));

  it("accepts a record carrying no clauseCategories field (defaults to empty, not to refusal)", () =>
    expect(evaluatePolicy(base, terms({}), offer).ok).toBe(true));

  it("accepts a record with an explicitly empty category list", () =>
    expect(
      evaluatePolicy(base, terms({ clauseCategories: [] } as never), offer).ok,
    ).toBe(true));

  it("a policy forbidding nothing accepts every category", () =>
    expect(
      evaluatePolicy(
        { ...base, forbiddenClauseCategories: [] },
        terms({ clauseCategories: ["class-action-waiver"] } as never),
        offer,
      ).ok,
    ).toBe(true));

  it("the cap check runs BEFORE the clause check", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({ clauseCategories: ["class-action-waiver"] } as never),
        { amount: "2000000", unit: "usdc-6dp" },
      ),
    );
    expect(r.code).toBe("policy/over-cap");
  });
});

/**
 * Both fields policy reads off the record cross a trust boundary the TYPE system does not police, and both
 * used to reach a raw operation that threw straight out of `evaluate` — past its contract to RETURN a
 * `GateDecision`. Fail-closed is not the same as fail-well: a buyer cannot act on a TypeError, and an
 * uncaught throw skips the accountable log entirely.
 *
 * These are the cases the suite could not previously catch, so they are asserted by `code` like every other
 * refusal here.
 */
describe("hostile values from the counterparty are declines, never throws", () => {
  it.each([
    ["string", "arbitration"],
    ["an array", ["arbitration"]],
    ["null", null],
    ["number", 42],
  ])(
    "refuses a disputeResolution that is %s, naming the shape rather than the jurisdiction",
    (shape, value) => {
      const r = refusal(
        evaluatePolicy(
          base,
          terms({ disputeResolution: value } as never),
          offer,
        ),
      );
      // The point of the fix, and the reason this asserts `detail` too: the old cast declined these with
      // `policy/jurisdiction` and "(none) not acceptable", which describes a jurisdiction the seller does
      // not have rather than the field shape it got wrong. The SHAPE is asserted per case — a detail that
      // said the same word for every one of them would name the defect no better than the old message did.
      expect(r.code).toBe("policy/malformed-dispute-resolution");
      expect(r.detail).toContain("disputeResolution");
      expect(r.detail).toContain(shape);
      expect(r.detail).not.toContain("not acceptable");
    },
  );

  it.each([
    ["jurisdiction", { jurisdiction: 42, method: "arbitration" }],
    ["method", { jurisdiction: "US-NY", method: ["arbitration"] }],
  ])(
    "refuses a disputeResolution whose %s is present but not a string",
    (member, value) => {
      const r = refusal(
        evaluatePolicy(
          base,
          terms({ disputeResolution: value } as never),
          offer,
        ),
      );
      expect(r.code).toBe("policy/malformed-dispute-resolution");
      expect(r.detail).toContain(member);
    },
  );

  it("leaves ABSENT alone — that is the ordinary jurisdiction decline, not a malformed field", () => {
    // Absence is the buyer's policy to judge, not the seller's defect to name. A policy of "any" accepts it.
    // `terms()` DEFAULTS a valid disputeResolution, so absence has to be stated explicitly — passing `{}`
    // tests the default, not the absent case.
    const absent = terms({ disputeResolution: undefined } as never);
    const r = refusal(evaluatePolicy(base, absent, offer));
    expect(r.code).toBe("policy/jurisdiction");
    expect(
      evaluatePolicy(
        {
          ...base,
          acceptableJurisdictions: "any",
          acceptableDisputeMethods: "any",
        },
        absent,
        offer,
      ).ok,
    ).toBe(true);
  });

  it("refuses a clauseCategories that is a string, naming it as the seller's defect", () => {
    const r = refusal(
      evaluatePolicy(
        base,
        terms({ clauseCategories: "arbitration" } as never),
        offer,
      ),
    );
    expect(r.code).toBe("policy/malformed-clause-categories");
    expect(r.detail).toContain("string");
  });

  it.each([
    ["a number", 42],
    ["an object", { a: 1 }],
    ["a boolean", true],
  ])("refuses a clauseCategories that is %s", (_label, value) =>
    expect(
      refusal(
        evaluatePolicy(
          base,
          terms({ clauseCategories: value } as never),
          offer,
        ),
      ).code,
    ).toBe("policy/malformed-clause-categories"),
  );

  it("still reads a well-formed clauseCategories array", () =>
    expect(
      refusal(
        evaluatePolicy(
          base,
          terms({ clauseCategories: ["class-action-waiver"] } as never),
          offer,
        ),
      ).code,
    ).toBe("policy/forbidden-clause"));

  it("ignores non-string members rather than throwing on them", () =>
    expect(
      evaluatePolicy(
        base,
        terms({ clauseCategories: [null, 7, "harmless"] } as never),
        offer,
      ).ok,
    ).toBe(true));

  /**
   * `offer.unit` is SELLER-derived — on the ACP path it is the session's `currency`, an unconstrained
   * string. A bare index read answered from `Object.prototype` for each of these and handed a function to
   * `BigInt()`, which threw a SyntaxError out of the gate.
   */
  it.each([
    "constructor",
    "toString",
    "valueOf",
    "hasOwnProperty",
    "__proto__",
    "isPrototypeOf",
  ])(
    "treats a unit named %s as an undeclared cap, not a prototype hit",
    (unit) =>
      expect(
        refusal(evaluatePolicy(base, terms({}), { amount: "1", unit })).code,
      ).toBe("policy/unit"),
  );

  it("a cap declared on the prototype chain is not a declared cap", () => {
    const inherited = Object.create({ "usdc-6dp": "999999999" }) as Record<
      string,
      string
    >;
    expect(
      refusal(
        evaluatePolicy({ ...base, maxCommitment: inherited }, terms({}), offer),
      ).code,
    ).toBe("policy/unit");
  });
});
