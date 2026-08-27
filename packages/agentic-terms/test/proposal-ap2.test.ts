import type { Assurance } from "@integraledger/lcp-authority";
import { hashAtr } from "@integraledger/lcp-kernel";
import { describe, expect, it } from "vitest";
import { evaluate } from "../src/evaluate.js";
import type { FetchedTerms, TermsFetcher } from "../src/fetch.js";
import type { BuyerPolicy } from "../src/policy.js";
import {
  AP2_HALT_POINT,
  type Ap2Step,
  assertBeforeAp2HaltPoint,
  isAp2SigningStep,
  parseProposalFromAp2Envelope,
} from "../src/proposal-ap2.js";
import { type GatedSigner, transact } from "../src/transact.js";

// `Assurance` is a closed union in `@integraledger/lcp-authority` — there is no "self-asserted".
const ctx = {
  level: 2 as const,
  sellerAssurance: "domain-controlled" as Assurance,
  legalContextUrl: "https://seller.example/terms/ap2-1",
  offer: { amount: "19900", unit: "usd-2dp" },
  step: "mandate-content-built" as Ap2Step,
};

const ATR =
  "0x3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed";

/**
 * An A2A `Message` carrying an AP2 mandate, written out as it appears on the wire rather than produced by
 * calling `ap2Placement.place` — a fixture derived from the implementation certifies nothing. The mandate
 * rides a DataPart keyed `ap2.mandates.CheckoutMandateSdJwt` beside a `risk_data` sibling, exactly as AP2
 * v0.2's reference samples build it, and `metadata` is A2A's own free-form map, which AP2 never writes.
 *
 * The carrier is the §8.1 `reference-object` at `metadata.legalContext` — the field `AP2_PLACEMENT`
 * declares, spelled here by hand so a manifest change that moved the field would fail this test.
 */
function envelope(
  metadata: Record<string, unknown> = {
    traceId: "t-1",
    legalContext: { type: "sha256", value: ATR },
  },
): unknown {
  return {
    kind: "message",
    messageId: "0f2a1c9e4b7d4a3f8c1e5b6a7d8f9012",
    role: "agent",
    parts: [
      {
        kind: "data",
        data: {
          "ap2.mandates.CheckoutMandateSdJwt":
            "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK3NkLWp3dCJ9.eyJfc2RfYWxnIjoic2hhLTI1NiJ9.<signature>~WyJ4Il0~",
        },
      },
      { kind: "data", data: { risk_data: "" } },
    ],
    metadata,
  };
}

describe("parseProposalFromAp2Envelope", () => {
  it("produces the same protocol-neutral GateProposal every other wire produces", () => {
    const p = parseProposalFromAp2Envelope(envelope(), ctx);
    expect(p.advertisedAtrHash).toBe(ATR);
    expect(p.legalContextUrl).toBe("https://seller.example/terms/ap2-1");
    expect(p.offer.amount).toBe("19900");
    expect(p.offer.unit).toBe("usd-2dp");
    expect(p.level).toBe(2);
    expect(p.sellerAssurance).toBe("domain-controlled");
  });

  it("reads the manifest's DECLARED snake_case alias, and no undeclared spelling", () => {
    // `metadata.legal_context` is on AP2_PLACEMENT.readAlso — AP2's own claim names are snake_case.
    const p = parseProposalFromAp2Envelope(
      envelope({ legal_context: { type: "sha256", value: ATR } }),
      ctx,
    );
    expect(p.advertisedAtrHash).toBe(ATR);
    // A spelling nobody declared is not a carrier. If this ever passes, the parser has grown a heuristic.
    expect(() =>
      parseProposalFromAp2Envelope(
        envelope({ "legal-context": { type: "sha256", value: ATR } }),
        ctx,
      ),
    ).toThrow(/no readable LCP reference/);
  });

  it("is blind to the Tier B shape — a reference inside the mandate is not a carrier", () => {
    // A Tier B integration could put the reference inside the mandate instead. A shipped
    // package cannot: writing our own mandate claims asks every AP2 counterparty to accept them. The
    // buyer inherits that blindness, so it can never be walked into blessing a placement nothing emits.
    const tierB = {
      kind: "message",
      parts: [
        {
          kind: "data",
          data: {
            "ap2.mandates.CheckoutMandateSdJwt": {
              credentialSubject: {
                legalContext: { type: "sha256", value: ATR },
              },
            },
          },
        },
      ],
      metadata: { traceId: "t-1" },
    };
    expect(() => parseProposalFromAp2Envelope(tierB, ctx)).toThrow(
      /no readable LCP reference/,
    );
  });

  it("refuses a locator carrier — the gate compares hashes, and a URL commits to nothing", () => {
    expect(() =>
      parseProposalFromAp2Envelope(
        envelope({
          legalContext: { type: "url", value: "https://seller.example/terms" },
        }),
        ctx,
      ),
    ).toThrow(/must be a sha256 carrier/);
  });

  it("refuses a non-HTTPS terms URL and a non-base-unit amount", () => {
    expect(() =>
      parseProposalFromAp2Envelope(envelope(), {
        ...ctx,
        legalContextUrl: "http://seller.example/terms",
      }),
    ).toThrow(/must be HTTPS/);
    for (const amount of ["", "19.9", "-1", "1e5"])
      expect(() =>
        parseProposalFromAp2Envelope(envelope(), {
          ...ctx,
          offer: { ...ctx.offer, amount },
        }),
      ).toThrow(/base-unit integer/);
  });
});

describe("AP2_HALT_POINT — the named sign moment", () => {
  it("names AP2's flow steps exactly — the declaration IS the deliverable, so it is pinned", () => {
    // These tokens are AP2 flow vocabulary, not phrasing. `AP2_HALT_POINT` is the unit's named artifact
    // and an integrator reads these values to decide where to call the gate; a build that quietly renamed
    // one would move the halt point without moving anything a coherence check could notice.
    expect(AP2_HALT_POINT.lastSafeStep).toBe("mandate-content-built");
    expect(AP2_HALT_POINT.haltBefore).toBe("trusted-surface-authorization");
    expect(AP2_HALT_POINT.signingSteps).toEqual([
      "trusted-surface-authorization",
      "agent-key-signing",
      "key-binding-presentation",
    ]);
  });

  it("halts strictly before the FIRST signing step, and the last safe step signs nothing", () => {
    expect(AP2_HALT_POINT.haltBefore).toBe(AP2_HALT_POINT.signingSteps[0]);
    expect(isAp2SigningStep(AP2_HALT_POINT.lastSafeStep)).toBe(false);
    expect(isAp2SigningStep(AP2_HALT_POINT.haltBefore)).toBe(true);
    // The defence is a fact about AP2, not about this package: it must cite the host's own text,
    // and the rationale must name the MECHANISM that makes this the first key — not merely assert it.
    expect(AP2_HALT_POINT.specRef).toMatch(/AP2 v0\.2/);
    expect(AP2_HALT_POINT.rationale).toMatch(/Trusted Surface/);
  });

  it("refuses at EVERY signing step, and refuses before it reads anything", () => {
    for (const step of AP2_HALT_POINT.signingSteps) {
      expect(() => assertBeforeAp2HaltPoint(step)).toThrow(
        /at or after the halt point/,
      );
      // The envelope here is garbage. If the parser read first, the throw would name the reference; that
      // it names the halt point is what proves the order — a gate that parses and THEN discovers it was
      // too late has already spent the buyer's time pretending a decision was available.
      expect(() =>
        parseProposalFromAp2Envelope({ nonsense: true }, { ...ctx, step }),
      ).toThrow(/at or after the halt point/);
    }
  });

  it("permits every step before the halt point", () => {
    for (const step of [
      "checkout-jwt-received",
      "mandate-content-built",
    ] satisfies Ap2Step[])
      expect(() => assertBeforeAp2HaltPoint(step)).not.toThrow();
  });
});

// ── The verify-before-sign proof ─────────────────────────────────────────────────────────────────────
//
// The plan's rule: ship a test that proves the signer is NOT called before the halt point — not a test
// that it is called after. So the assertion below is a zero, and the check that the zero is not vacuous
// is a SEPARATE test: a zero from an unreachable signer would prove nothing at all.

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const TERMS = JSON.stringify({
  terms: "https://seller.example/body",
  disputeResolution: { jurisdiction: "US-NY", method: "arbitration" },
});
function fixedFetcher(bytes: Uint8Array): TermsFetcher {
  return {
    async fetch(_u: string): Promise<FetchedTerms> {
      return { bytes, format: "application/json", fetchedAt: "t" };
    },
  };
}
const policy: BuyerPolicy = {
  requiredLevel: 2,
  acceptableJurisdictions: ["US-NY"],
  acceptableDisputeMethods: ["arbitration"],
  maxCommitment: { "usd-2dp": "1000000" },
  forbiddenClauseCategories: [],
  requiredAssurance: "domain-controlled",
  onNotAttempted: "decline",
};
const now = (): string => "t";
const PRE_HALT_STEPS = [
  "checkout-jwt-received",
  "mandate-content-built",
] satisfies Ap2Step[];

/** A signer that FAILS THE TEST if it is reached. The assertion is its silence, not its return value. */
function unreachableSigner(): GatedSigner {
  return {
    async sign(_h: `0x${string}`) {
      throw new Error(
        "the signing key was invoked before AP2's halt point — verify-before-sign is broken",
      );
    },
  };
}

describe("verify-before-sign at AP2's halt point", () => {
  it("never reaches the signer at any pre-halt step, on EITHER gate outcome", async () => {
    const bytes = enc(TERMS);
    const atrHash = await hashAtr(bytes);
    const live = envelope({ legalContext: { type: "sha256", value: atrHash } });

    for (const step of PRE_HALT_STEPS) {
      // Outcome 1 — PROCEED. The served terms hash to the advertised value and satisfy the policy, so the
      // gate says yes. It says yes through `evaluate`, which takes NO signer argument at all: at every step
      // before the halt point the key is not merely unused, it is unreachable from anything that runs.
      const proceed = await evaluate(
        parseProposalFromAp2Envelope(live, { ...ctx, step }),
        policy,
        { fetcher: fixedFetcher(bytes), now },
      );
      expect(proceed.kind).toBe("proceed");

      // Outcome 2 — DECLINE. The seller serves TAMPERED bytes, so the fingerprint check halts (LCP §5.3).
      // This arm runs through `transact`, which does hold the key — and the signer throws if touched.
      const declined = await transact(
        parseProposalFromAp2Envelope(live, { ...ctx, step }),
        policy,
        { fetcher: fixedFetcher(enc(`TAMPERED ${TERMS}`)), now },
        unreachableSigner(),
      );
      expect(declined.kind).toBe("halted");
    }
  });

  it("is not vacuous — a live signer IS reached once the gate has proceeded", async () => {
    // Kept separate, because a zero from a signer nothing could ever call proves nothing. This shows the
    // same composition CAN reach a key, which is what makes the silence above a fact rather than a shape.
    let signCalls = 0;
    const signer: GatedSigner = {
      async sign(_h: `0x${string}`) {
        signCalls++;
        return { signature: "0xsig" as const };
      },
    };
    const bytes = enc(TERMS);
    const atrHash = await hashAtr(bytes);
    const result = await transact(
      parseProposalFromAp2Envelope(
        envelope({ legalContext: { type: "sha256", value: atrHash } }),
        { ...ctx, step: AP2_HALT_POINT.lastSafeStep },
      ),
      policy,
      { fetcher: fixedFetcher(bytes), now },
      signer,
    );
    expect(result.kind).toBe("signed");
    expect(signCalls).toBe(1);
  });
});
