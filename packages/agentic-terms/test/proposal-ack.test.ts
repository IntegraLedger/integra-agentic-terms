import { describe, expect, it } from "vitest";
import {
  ACK_DID_METHODS,
  ackReceiptContribution,
  parseAckReceipt,
} from "../src/proposal-ack.js";

const ATR =
  "0x3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed";

/**
 * A signed ACK-Pay `PaymentReceiptCredential`, written out as ACK's own code emits it rather than produced
 * by calling the placement — a fixture derived from the implementation certifies nothing. Cut from
 * `agentcommercekit/ack @ main` read 2026-07-30: `createPaymentReceipt` builds
 * `{ paymentRequestToken, paymentOptionId }` and adds `metadata` when given, `createCredential` spreads
 * that under `credentialSubject` beside the payer `id` and sets `issuer: { id }`, and a credential that has
 * been through `signCredential` carries `proof`.
 *
 * The sibling keys are ACK's own documented audit-trail example — `policyRef`, `mandateRef`, `executionRef`,
 * `settlementNetwork`, `settlementReference` — which is what makes this map a shared one we are a guest in.
 */
function receipt(
  over: {
    metadata?: Record<string, unknown>;
    credentialSubject?: Record<string, unknown>;
    top?: Record<string, unknown>;
    /** Return the credential as `createCredential` leaves it — before `signCredential` ever runs. */
    unissued?: true;
  } = {},
): Record<string, unknown> {
  const proof =
    over.unissued === true
      ? {}
      : { proof: { type: "JwtProof2020", jwt: "eyJ...<sig>" } };
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "PaymentReceiptCredential"],
    issuer: { id: "did:web:receipts.acme.example" },
    credentialSubject: {
      id: "did:web:buyer.example",
      paymentRequestToken: "eyJhbGciOiJFUzI1NiJ9.eyJpZCI6InJlcS0xIn0.<sig>",
      paymentOptionId: "opt-usdc-base",
      metadata: over.metadata ?? {
        legalContext: { type: "sha256", value: ATR },
        policyRef: "p-1",
        mandateRef: "m-1",
        executionRef: "e-1",
        settlementNetwork: "eip155:8453",
        settlementReference: "0xdeadbeef",
      },
      ...over.credentialSubject,
    },
    ...proof,
    ...over.top,
  };
}

describe("parseAckReceipt", () => {
  it("reads the reference and every fact ACK's own receipt carries", () => {
    const f = parseAckReceipt(receipt());
    expect(f.atrHash).toBe(ATR);
    expect(f.paymentRequestToken).toBe(
      "eyJhbGciOiJFUzI1NiJ9.eyJpZCI6InJlcS0xIn0.<sig>",
    );
    expect(f.paymentOptionId).toBe("opt-usdc-base");
    expect(f.payerDid).toBe("did:web:buyer.example");
    expect(f.payerDidMethod).toBe("web");
    expect(f.issuerDid).toBe("did:web:receipts.acme.example");
  });

  it("reports the sibling keys and owns none of them — LCP's own key and its declared alias are excluded", () => {
    // Both spellings present at once: the map is ACK's, we read exactly one key out of it, and neither
    // spelling of OUR key may be reported back as somebody else's cross-reference.
    const f = parseAckReceipt(
      receipt({
        metadata: {
          legalContext: { type: "sha256", value: ATR },
          legal_context: { type: "sha256", value: ATR },
          policyRef: "p-1",
          settlementReference: "0xdeadbeef",
        },
      }),
    );
    expect(f.siblingRefKeys).toEqual(["policyRef", "settlementReference"]);
  });

  it("reads the manifest's DECLARED snake_case alias when it is the only carrier", () => {
    const f = parseAckReceipt(
      receipt({ metadata: { legal_context: { type: "sha256", value: ATR } } }),
    );
    expect(f.atrHash).toBe(ATR);
    expect(f.siblingRefKeys).toEqual([]);
  });

  it("refuses an UNISSUED receipt — the mirror of the placement's already-issued refusal", () => {
    // `placement-ack.place` refuses a credential that already carries a proof; this refuses one that does
    // not yet. Between the two, the reference can only ever ride a receipt the issuer signed over.
    expect(() => parseAckReceipt(receipt({ unissued: true }))).toThrow(
      /receipt-not-issued/,
    );
    // ACK's own `isDecodedCredential` accepts iff `"proof" in value && value.proof != null`, so a NULL
    // proof is unissued by the host's rule. Mirrored, not re-decided.
    expect(() => parseAckReceipt(receipt({ top: { proof: null } }))).toThrow(
      /receipt-not-issued/,
    );
  });

  it("refuses a payer DID in a method ACK's own resolver does not register", () => {
    for (const did of [
      "did:ion:EiA_1",
      "did:ethr:0x1",
      "https://buyer.example",
      "did:",
      // A NON-`did` scheme carrying a method ACK does resolve. This is the case that needs the scheme
      // check on its own: drop it and `urn:web:acme.example` reads as a resolvable `did:web` identity,
      // which is a URI ACK's resolver would never have been handed.
      "urn:web:acme.example",
      "http:key:z6Mk",
    ])
      expect(() =>
        parseAckReceipt(receipt({ credentialSubject: { id: did } })),
      ).toThrow(/did method ACK resolves/);
    // …and accepts every method it does register. `did:jwks` is in this list because it is in ACK's
    // `getDidResolver` today; earlier surveys had it as pending, and ACK's own code is the spec.
    expect([...ACK_DID_METHODS]).toEqual(["key", "web", "jwks", "pkh"]);
    for (const method of ACK_DID_METHODS)
      expect(
        parseAckReceipt(
          receipt({ credentialSubject: { id: `did:${method}:holder` } }),
        ).payerDidMethod,
      ).toBe(method);
  });

  it("refuses a bare-string issuer — ACK's createCredential emits `issuer: { id }`", () => {
    expect(() =>
      parseAckReceipt(
        receipt({ top: { issuer: "did:web:receipts.acme.example" } }),
      ),
    ).toThrow(/issuer\.id/);
  });

  it("refuses a receipt missing either half of ACK's own join — and names WHICH half", () => {
    // Absent and PRESENT-BUT-EMPTY are both refused: an empty `paymentRequestToken` would join the record
    // to no payment request at all while satisfying a bare `typeof === "string"` check. The message names
    // the field, because a fail-loud that does not say what is missing costs an integrator the debug.
    for (const key of ["paymentRequestToken", "paymentOptionId", "id"] as const)
      for (const bad of [undefined, ""])
        expect(() =>
          parseAckReceipt(receipt({ credentialSubject: { [key]: bad } })),
        ).toThrow(key === "id" ? /credentialSubject\.id/ : new RegExp(key));
  });

  it("refuses a locator carrier and a receipt carrying no reference at all", () => {
    expect(() =>
      parseAckReceipt(
        receipt({
          metadata: {
            legalContext: { type: "url", value: "https://s.example/t" },
          },
        }),
      ),
    ).toThrow(/must be a sha256 carrier/);
    expect(() =>
      parseAckReceipt(receipt({ metadata: { policyRef: "p-1" } })),
    ).toThrow(/no readable LCP reference/);
  });
});

describe("ackReceiptContribution — which rung each half of the receipt feeds", () => {
  it("files the receipt BYTES verbatim under the `settlement` role, not a re-serialization", () => {
    const bytes = new TextEncoder().encode("the exact credential as received");
    const c = ackReceiptContribution(receipt(), bytes);
    expect(c.artifact.role).toBe("settlement");
    expect(c.artifact.bytes).toBe(bytes); // identity, not equality — what the issuer signed, unaltered
  });

  it("answers the ACK receipt's dual role: it is BOTH a placement input and an identity input", () => {
    const c = ackReceiptContribution(receipt(), new Uint8Array([1]));
    expect(c.placement.extracted).toEqual({ type: "sha256", value: ATR });
    expect(c.payerDid).toBe("did:web:buyer.example");
    expect(c.issuerDid).toBe("did:web:receipts.acme.example");
    expect(c.paymentRequestToken).toContain("eyJ");
  });

  it("stops at the DID METHOD and states no assurance — the record's assurance is seller-authored", () => {
    // ACK's second edge. The method→`authority.Assurance` mapping lives ONCE, on the seller side.
    // A buyer restating it would be a second authority on a fact the record already states.
    const c = ackReceiptContribution(receipt(), new Uint8Array([1]));
    expect(c.payerDidMethod).toBe("web");
    expect(Object.keys(c)).not.toContain("assurance");
  });
});
