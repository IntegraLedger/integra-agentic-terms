import { assemble } from "@integraledger/lcp-kernel";
import { ACP_PLACEMENT, acpPlacement } from "@integraledger/lcp-placement-acp";
import { referencePlacementStep } from "@integraledger/lcp-verify";
import { describe, expect, it } from "vitest";
import { parseProposalFromAcpCheckout } from "../src/proposal-acp.js";

/** ACP declares a terms-URL slot, so an integrity-bearing advertisement must carry a locator: a hash no
 *  counterparty can resolve is unverifiable to anyone who does not already hold the terms. */
const TERMS_URL = "https://seller.example/terms/abc";

/**
 * The Phase-B exit: `place → extract → referencePlacementStep → parseProposalFromAcpCheckout`, on ONE
 * document, across BOTH repos.
 *
 * The parser is in the round-trip deliberately. A round-trip that stops at the verify step cannot catch a
 * placement and a parser that disagree about which fields the wire carries — which is exactly how this
 * seam first failed: the writer placed one field while the reader's schema required two, and each half
 * passed its own tests. The placement is consumed here as a PUBLISHED version from the private registry
 * (`@integraledger/lcp-placement-acp@0.1.0`), never linked, so this also proves the seam a consumer sees.
 *
 * The atrHash is not a fixture constant: it is assembled from a real ATR by the kernel, so the value that
 * rides the ACP session is the record's own fingerprint rather than a number chosen to agree with itself.
 */
const ctx = {
  level: 2 as const,
  sellerAssurance: "domain-controlled" as const,
};

describe("ACP Phase-B exit round-trip", () => {
  it("carries a real atrHash from an assembled ATR out through the buyer's parser", async () => {
    const { atrHash } = await assemble([
      { slot: "id", value: "urn:integra:atr:acp-round-trip-1" },
      {
        slot: "terms",
        value: "1500 usd, delivered immediately, refundable for 14 days.",
      },
      {
        slot: "parties",
        value: { seller: "seller.example", buyer: "agent.example" },
      },
    ]);

    // A checkout session as ACP puts it on the wire (stable 2026-04-17): top-level, `totals` an array of
    // typed rows, `currency` a top-level ISO 4217 code. It arrives carrying the seller's own metadata and
    // the terms URL, and NO reference — the reference is what this round-trip places.
    const session = {
      id: "checkout_session_rt",
      status: "ready_for_payment",
      currency: "usd",
      totals: [
        { type: "items_base_amount", display_text: "Items", amount: 1400 },
        { type: "tax", display_text: "Tax", amount: 100 },
        { type: "total", display_text: "Total", amount: 1500 },
      ],
      metadata: {
        merchant_order_ref: "order-4417",
        legal_context_url: "https://seller.example/terms/abc",
      },
    };

    // 1 — PLACE. The seller welds the record's fingerprint into the session.
    const placed = acpPlacement.place(
      { ref: { type: "sha256", value: atrHash }, termsUrl: TERMS_URL },
      session,
    );
    if ("refused" in placed) throw new Error(`place refused: ${placed.code}`);
    const doc = placed.value as Record<string, unknown>;
    const metadata = doc["metadata"] as Record<string, unknown>;
    expect(metadata["legal_context"]).toBe(`lcp:sha256:${atrHash}`);
    // The seller's own keys survived, and the field the manifest declares is the field that was written.
    expect(metadata["merchant_order_ref"]).toBe("order-4417");
    expect(ACP_PLACEMENT.field).toBe("metadata.legal_context");

    // 2 — EXTRACT. A stranger recovers the reference from the same document.
    const extracted = acpPlacement.extract(doc);
    if ("refused" in extracted)
      throw new Error(`extract refused: ${extracted.code}`);
    // `extract` answers with the whole advertisement: the reference, and what this session says about
    // where its terms live. ACP declares a slot, and this session leaves it empty.
    expect(extracted.value).toEqual({
      ref: { type: "sha256", value: atrHash },
      termsUrl: { kind: "read", url: TERMS_URL },
    });

    // 3 — VERIFY. The recovered reference names THIS record, and the step proves it.
    const step = referencePlacementStep(
      { extracted: extracted.value },
      atrHash,
    );
    expect(step.status).toBe("proved");

    // 4 — PARSE. The buyer's gate reads the same document into a typed proposal. This is the step that
    // catches a placement and a parser that disagree: the parser REQUIRES the terms URL, and it is a slot
    // the manifest declares (`termsUrlFields`) rather than one the two halves happened to share.
    const proposal = parseProposalFromAcpCheckout(doc, ctx);
    expect(proposal.advertisedAtrHash).toBe(atrHash);
    expect(proposal.legalContextUrl).toBe("https://seller.example/terms/abc");
    expect(proposal.offer.amount).toBe("1500");
    expect(proposal.offer.unit).toBe("usd");
    expect(ACP_PLACEMENT.termsUrlFields).toEqual([
      "metadata.legal_context_url",
    ]);
  });

  it("impeaches when the session carries a reference to a DIFFERENT record", async () => {
    // The round-trip must be able to fail for the right reason, or its green says nothing. A session
    // welded to one record and verified against another is caught at the verify step, not by the parser:
    // the parser's job is to read the wire, and the step's job is to rule on whether it names this record.
    const { atrHash } = await assemble([
      { slot: "id", value: "urn:integra:atr:acp-round-trip-2" },
      { slot: "terms", value: "1500 usd, delivered immediately." },
    ]);
    const { atrHash: otherAtrHash } = await assemble([
      { slot: "id", value: "urn:integra:atr:acp-round-trip-3" },
      { slot: "terms", value: "9900 usd, delivered immediately." },
    ]);
    expect(otherAtrHash).not.toBe(atrHash);

    const placed = acpPlacement.place(
      { ref: { type: "sha256", value: otherAtrHash }, termsUrl: TERMS_URL },
      { id: "checkout_session_rt2", metadata: {} },
    );
    if ("refused" in placed) throw new Error(`place refused: ${placed.code}`);
    const extracted = acpPlacement.extract(placed.value);
    if ("refused" in extracted)
      throw new Error(`extract refused: ${extracted.code}`);

    const step = referencePlacementStep(
      { extracted: extracted.value },
      atrHash,
    );
    // Narrowed, not asserted: `haltClass` lives only on the `failed` arm of `StepOutcome`, so reading it
    // off the union is a compile error — which is the type system doing the same job the assertion does.
    if (step.status !== "failed")
      throw new Error(`expected an impeachment, got ${step.status}`);
    expect(step.haltClass).toBe("verification-failure");
  });
});
