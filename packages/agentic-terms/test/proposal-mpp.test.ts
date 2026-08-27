import { describe, expect, it } from "vitest";
import { evaluate } from "../src/evaluate.js";
import { InMemoryOrc4Log } from "../src/log.js";
import { parseProposalFromMppRequest } from "../src/proposal-mpp.js";

// `Assurance` is a closed union in `@integraledger/lcp-authority`.
const ctx = {
  level: 2 as const,
  sellerAssurance: "domain-controlled" as const,
};

const ATR =
  "0x3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed";

// The MPP `request` body as the specification shows it (draft-payment-intent-charge-00 §5.1.2): `amount`
// and `currency` REQUIRED strings, `methodDetails` OPTIONAL and owned by the payment method. The extra
// members here — `description`, `externalId`, and the method's own `networkId` — are present precisely
// because a real body carries them and the parser must ignore them.
const request = {
  amount: "5000",
  currency: "usd",
  description: "Premium API access",
  externalId: "order_12345",
  methodDetails: {
    networkId: "profile_1MqDcVKA5fEO2tZvKQm9g8Yj",
    atrHash: ATR,
    legalContextUrl: "https://seller.example/terms/abc",
  },
};

describe("parseProposalFromMppRequest", () => {
  it("parses a conformant request body into the one typed proposal", () => {
    expect(parseProposalFromMppRequest(request, ctx)).toEqual({
      advertisedAtrHash: ATR,
      legalContextUrl: "https://seller.example/terms/abc",
      level: 2,
      offer: { amount: "5000", unit: "usd" },
      sellerAssurance: "domain-controlled",
    });
  });

  it("carries `currency` verbatim as the unit across the family, never interpreting it", () => {
    // Table 2 calls `currency` a "Currency or asset identifier"; the specification's own examples span an
    // ISO 4217 code, a token address and `sat`. The gate compares units for equality and nothing else, so
    // each must survive unaltered.
    for (const currency of [
      "usd",
      "0x20c0000000000000000000000000000000000000",
      "sat",
    ]) {
      const parsed = parseProposalFromMppRequest({ ...request, currency }, ctx);
      expect(parsed.offer.unit).toBe(currency);
    }
  });

  it("takes level and assurance from the context, which the wire does not carry", () => {
    const parsed = parseProposalFromMppRequest(request, {
      level: 4,
      sellerAssurance: "legal-party",
    });
    expect(parsed.level).toBe(4);
    expect(parsed.sellerAssurance).toBe("legal-party");
  });

  describe("absence is a refusal, and each absence is named", () => {
    it("refuses a body with no methodDetails — conformant MPP, no reference", () => {
      const { methodDetails: _omitted, ...without } = request;
      expect(() => parseProposalFromMppRequest(without, ctx)).toThrow(
        /carries no `methodDetails`/,
      );
    });

    it("refuses methodDetails that advertises no atrHash", () => {
      expect(() =>
        parseProposalFromMppRequest(
          { ...request, methodDetails: { networkId: "p_1" } },
          ctx,
        ),
      ).toThrow(/advertises no `methodDetails.atrHash`/);
    });

    it("refuses methodDetails that advertises no legalContextUrl", () => {
      expect(() =>
        parseProposalFromMppRequest(
          { ...request, methodDetails: { atrHash: ATR } },
          ctx,
        ),
      ).toThrow(/advertises no `methodDetails.legalContextUrl`/);
    });
  });

  describe("the carrier is bare-value, so the parser validates it itself", () => {
    it("refuses a hash that is not 0x-prefixed 32-byte hex", () => {
      for (const bad of [
        ATR.slice(2), // conformant hex, missing the 0x — must NOT be silently re-prefixed
        `${ATR}ff`, // too long
        ATR.slice(0, -2), // too short
        "0xZZ86850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed",
      ]) {
        expect(() =>
          parseProposalFromMppRequest(
            {
              ...request,
              methodDetails: { ...request.methodDetails, atrHash: bad },
            },
            ctx,
          ),
        ).toThrow(/not a 0x-prefixed 32-byte hex/);
      }
    });

    it("accepts upper-case hex, because hex is case-insensitive", () => {
      const upper = `0x${ATR.slice(2).toUpperCase()}`;
      expect(
        parseProposalFromMppRequest(
          {
            ...request,
            methodDetails: { ...request.methodDetails, atrHash: upper },
          },
          ctx,
        ).advertisedAtrHash,
      ).toBe(upper);
    });

    it("refuses a non-HTTPS terms URL", () => {
      expect(() =>
        parseProposalFromMppRequest(
          {
            ...request,
            methodDetails: {
              ...request.methodDetails,
              legalContextUrl: "http://seller.example/terms/abc",
            },
          },
          ctx,
        ),
      ).toThrow(/must be HTTPS/);
    });
  });

  describe("the amount is a base-unit integer, and that is load-bearing", () => {
    it("refuses a decimal amount rather than letting BigInt throw inside the gate", async () => {
      // THE REASON THIS CHECK EXISTS. `policy.ts` compares with `BigInt(offer.amount)`, and
      // `BigInt("50.00")` throws a SyntaxError — which would escape `evaluate`'s contract to RETURN a
      // GateDecision. Proven, not asserted: the raw value blows up where the gate would have used it.
      expect(() => BigInt("50.00")).toThrow();
      expect(() =>
        parseProposalFromMppRequest({ ...request, amount: "50.00" }, ctx),
      ).toThrow(/base-unit integer string/);
    });

    it("refuses empty, signed and non-numeric amounts", () => {
      for (const bad of ["", "-1", "1e3", " 5000", "5_000"]) {
        expect(() =>
          parseProposalFromMppRequest({ ...request, amount: bad }, ctx),
        ).toThrow(/base-unit integer string/);
      }
    });

    it("accepts a large base-unit amount without precision loss", () => {
      // Token base units exceed Number.MAX_SAFE_INTEGER routinely; the amount stays a string end to end.
      const big = "123456789012345678901234567890";
      expect(
        parseProposalFromMppRequest({ ...request, amount: big }, ctx).offer
          .amount,
      ).toBe(big);
      expect(BigInt(big)).toBe(BigInt(big));
    });
  });

  it("produces a proposal the gate can actually decide on", async () => {
    // The parser's output is only worth what `evaluate` can do with it. A fingerprint mismatch is the
    // cheapest end-to-end proof that the shape composes: the gate fetches, recomputes and HALTS.
    const proposal = parseProposalFromMppRequest(request, ctx);
    const log = new InMemoryOrc4Log();
    const decision = await evaluate(
      proposal,
      {
        requiredLevel: 1,
        acceptableJurisdictions: "any",
        acceptableDisputeMethods: "any",
        // Deliberately generous: this case proves the SHAPE composes end to end, so nothing but the
        // fingerprint should be able to decline it. A tighter policy here would pass for the wrong reason.
        maxCommitment: { usd: "100000" },
        forbiddenClauseCategories: [],
        requiredAssurance: "any",
        onNotAttempted: "decline",
      },
      {
        fetcher: {
          fetch: async () => ({
            bytes: new TextEncoder().encode("terms that do not match"),
            format: "application/json",
            fetchedAt: "2026-08-12T00:00:00.000Z",
          }),
        },
        now: () => "2026-08-12T00:00:00.000Z",
        log,
      },
    );
    expect(decision.kind).toBe("decline");
    if (decision.kind === "decline")
      expect(decision.code).toBe("gate/fingerprint-mismatch");
    // And the entry names its SUBJECT, not just its verdict — the halt is only actionable by the seller if
    // the record says which document disagreed. On a mismatch the advertised hash cannot serve as that
    // handle, because it is not the hash of what was served.
    expect(log.entries[0]?.legalContextUrl).toBe(
      "https://seller.example/terms/abc",
    );
  });
});
