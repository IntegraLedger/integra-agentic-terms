import { describe, expect, it } from "vitest";
import { parseProposalFromAcpCheckout } from "../src/proposal-acp.js";

// `Assurance` is a closed union in `@integraledger/lcp-authority` (`src/composition.ts:18-22`):
// "wallet-signature-only" | "domain-controlled" | "attested" | "legal-party". There is no "self-asserted".
const ctx = {
  level: 2 as const,
  sellerAssurance: "domain-controlled" as const,
};

// The ACP checkout session as it actually appears on the wire (stable 2026-04-17): TOP-LEVEL, with
// `totals` an ARRAY of total objects — there is no `checkout` wrapper and no `total` string. `currency` IS
// a top-level required field (ISO 4217 settlement code), and `Total.amount` is an integer in minor
// currency units.
const session = {
  id: "checkout_session_1",
  currency: "usd",
  status: "ready_for_payment",
  totals: [
    { type: "items_base_amount", display_text: "Items", amount: 1400 },
    { type: "tax", display_text: "Tax", amount: 100 },
    { type: "total", display_text: "Total", amount: 1500 },
  ],
  metadata: {
    legal_context:
      "lcp:sha256:0x3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed",
    legal_context_url: "https://seller.example/terms/abc",
  },
};

describe("parseProposalFromAcpCheckout", () => {
  it("produces the same protocol-neutral GateProposal the x402 parser produces", () => {
    const p = parseProposalFromAcpCheckout(session, ctx);
    expect(p.advertisedAtrHash).toBe(
      "0x3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed",
    );
    expect(p.legalContextUrl).toBe("https://seller.example/terms/abc");
    expect(p.offer.amount).toBe("1500");
    expect(p.offer.unit).toBe("usd");
    expect(p.level).toBe(2);
  });

  it("reads the `total` row, not the first row or the sum", () => {
    // The rows are deliberately ordered so that taking `totals[0]` or summing every row both give a
    // WRONG answer that still looks plausible — 1400 and 3000 respectively.
    const p = parseProposalFromAcpCheckout(session, ctx);
    expect(p.offer.amount).toBe("1500");
  });

  it("throws when no row is typed `total` — it never falls back to another row", () => {
    const bad = structuredClone(session);
    bad.totals = bad.totals.filter((t) => t.type !== "total");
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow(/total/);
  });

  it("throws on a non-HTTPS terms URL — the trust boundary is fail-fast", () => {
    const bad = structuredClone(session);
    bad.metadata.legal_context_url = "http://seller.example/terms/abc";
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow(/HTTPS/);
  });

  it("throws on a non-integer minor-unit amount", () => {
    const bad = structuredClone(session);
    const total = bad.totals.find((t) => t.type === "total");
    if (total === undefined) throw new Error("fixture lost its total row");
    total.amount = 15.5;
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow(/minor-unit/);
  });

  it("throws on a bare-digits sha256 — the canonical carrier form is 0x-prefixed", () => {
    const bad = structuredClone(session);
    bad.metadata.legal_context =
      "lcp:sha256:3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed";
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow();
  });

  it("throws when the session carries no legal context at all", () => {
    expect(() =>
      parseProposalFromAcpCheckout({ id: "checkout_session_2" }, ctx),
    ).toThrow();
  });

  it("throws on a legal_context that is not an lcp: reference at all", () => {
    // Distinct from the malformed-carrier case: the codec returns `undefined` (no `lcp:` prefix) rather
    // than throwing, so this is the arm that catches a seller who put a bare URL in the field.
    const bad = structuredClone(session);
    bad.metadata.legal_context = "https://seller.example/terms/abc";
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow(/parseable/);
  });

  it("throws on a non-sha256 carrier — the proposal needs the record's fingerprint", () => {
    // `url` is a carrier type the ACP placement PERMITS, so this decodes cleanly and is refused one layer
    // later: a terms URL is not something the gate can compare against a recomputed record hash.
    const bad = structuredClone(session);
    bad.metadata.legal_context = "lcp:url:https://seller.example/terms/abc";
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow(/sha256/);
  });

  it("throws on a negative amount", () => {
    const bad = structuredClone(session);
    const total = bad.totals.find((t) => t.type === "total");
    if (total === undefined) throw new Error("fixture lost its total row");
    total.amount = -1;
    expect(() => parseProposalFromAcpCheckout(bad, ctx)).toThrow(/minor-unit/);
  });

  it("ACCEPTS a zero total — the boundary is negative, not falsy", () => {
    // A fully-discounted order totals 0, and it is a real transaction to gate. Pinned so the guard cannot
    // quietly become `<= 0`, which would reject it while still passing every other test here.
    const free = structuredClone(session);
    const total = free.totals.find((t) => t.type === "total");
    if (total === undefined) throw new Error("fixture lost its total row");
    total.amount = 0;
    expect(parseProposalFromAcpCheckout(free, ctx).offer.amount).toBe("0");
  });
});
