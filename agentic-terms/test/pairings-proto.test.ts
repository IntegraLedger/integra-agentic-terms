// B2, B6, B10 and B16 for the protocol-group pairings: card, AP2, UCP, ACP and ACK. Every expected request, answer
// and bound hash is the vector files' (card.json, ap2-checkout-mandate.json, ucp.json, acp-checkout.json,
// ack-payment-request.json). The card documents are the vectors' own and advertise H = SHA-256("abc"); the AP2, UCP and
// ACP documents advertise the vectors' own H, over the vectors' own ATR bytes.
import { createHash, createPublicKey, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Refusal } from "@integraledger/lcp";
import { binding as a2aBinding } from "@integraledger/lcp/a2a";
import { paymentRequest } from "@integraledger/lcp/ack";
import { delegated, undelegated } from "@integraledger/lcp/acp";
import { checkoutMandate } from "@integraledger/lcp/ap2";
import { sellerReference, viAutonomous, viImmediate, visaTap } from "@integraledger/lcp/card";
import { ap2Mandate, bookingAp2Mandate, bookingUnsigned, unsigned } from "@integraledger/lcp/ucp";
import { check, confirm, finish, transact, type Binding, type Presented, type Signature, type SigningRequest } from "../src/index.js";
import { PIECES } from "../src/pairings/index.js";
import type { BuyerPiece, Chosen, Read } from "../src/types.js";
import { ABC, ABD, code, counting, H, isDeclined, isPublicProof, LINK, offered, receiptFor, serving, vectors, type Pairing } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type V = any;
const CARD: V = vectors("card.json");
const AP2: V = vectors("ap2-checkout-mandate.json");
const UCP: V = vectors("ucp.json");
const ACP: V = vectors("acp-checkout.json");
const ACK: V = vectors("ack-payment-request.json");

const BUYER = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const enc = new TextEncoder();
const b64u = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const sha256b64u = (s: string): string => createHash("sha256").update(Buffer.from(s, "ascii")).digest("base64url");
const never = async (): Promise<never> => {
  throw new Error("the signer was called");
};

/**
 * B6 over the given ATR and its hash: `confirm` gives the request `inspect` checks; `finish` with the test signer's
 * answer returns a payment bound to `h`; `transact` signs once; `check` confirms the payment against the ATR and
 * declines it against other bytes.
 */
async function signsOver(
  p: Pairing,
  atr: Uint8Array,
  h: string,
  inspect: (r: SigningRequest) => void | Promise<void>,
): Promise<Presented> {
  const confirmed = await confirm(p.doc, offered(p.binding), p.account, serving(atr), p.inputs);
  if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
  expect(confirmed.h).toBe(h);
  expect(confirmed.bytes).toEqual(atr);
  if (confirmed.request === null) throw new Error("nothing to sign");
  await inspect(confirmed.request);

  const answer = await p.answer(confirmed.request);
  const done = await finish(atr, JSON.parse(JSON.stringify(confirmed.chosen)), answer, p.binding);
  if (isDeclined(done)) throw new Error(`${done.decline.code}: ${done.decline.detail}`);
  if ("next" in done) throw new Error("the piece asked for a second signature");
  expect(done.h).toBe(h);

  const signer = counting(p.account, p.answer);
  const whole = await transact(p.doc, offered(p.binding), signer, serving(atr), { inputs: p.inputs ?? {} });
  if (isDeclined(whole)) throw new Error(`${whole.decline.code}: ${whole.decline.detail}`);
  if ("approve" in whole) throw new Error("an agreement payment to approve");
  expect(signer.requests.length).toBe(1);
  expect(whole.signed).toEqual(done.signed);
  expect(whole.bytes).toEqual(atr);
  expect(whole.agreement).toEqual(isPublicProof(p.binding) ? undefined : receiptFor(h));

  expect(await check(atr, done.signed, p.binding)).toEqual({ h });
  expect(code(await check(ABD, done.signed, p.binding))).toBe("signed-not-bound");
  return done.signed;
}

/** B6 for a confirm-only pairing: `confirm` gives no request and the hash; `transact` gives no payment, unsigned. */
async function confirmsOnly(p: Pairing, atr: Uint8Array, h: string): Promise<Chosen> {
  const confirmed = await confirm(p.doc, offered(p.binding), p.account, serving(atr), p.inputs);
  if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
  expect(confirmed.request).toBeNull();
  expect(confirmed.h).toBe(h);
  expect(confirmed.bytes).toEqual(atr);
  expect(JSON.parse(JSON.stringify(confirmed.chosen))).toEqual(confirmed.chosen);

  const signer = counting(p.account, never);
  const whole = await transact(p.doc, offered(p.binding), signer, serving(atr), { inputs: p.inputs ?? {} });
  expect(whole).toEqual({ signed: null, bytes: atr, h, ...(isPublicProof(p.binding) ? {} : { agreement: receiptFor(h) }) });
  expect(signer.requests.length).toBe(0);
  return confirmed.chosen;
}

/** B10: a document whose link is `http://` is `offer-unreadable` with the pairing's code, before any fetch. */
async function httpLink(p: Pairing, httpDoc: unknown, detail: string): Promise<void> {
  const f = serving(ABC);
  const out = await confirm(httpDoc, p.binding, p.account, f, p.inputs);
  expect(out).toEqual({ decline: { code: "offer-unreadable", detail } });
  const signer = counting(p.account, never);
  expect(code(await transact(httpDoc, p.binding, signer, f, { inputs: p.inputs ?? {} }))).toBe("offer-unreadable");
  expect(f.calls).toBe(0);
  expect(signer.requests.length).toBe(0);
}

/** B16: each account is declined `no-payable-option` before any fetch. */
async function unpayable(p: Pairing, accounts: readonly string[]): Promise<void> {
  for (const account of accounts) {
    const f = serving(ABC);
    const out = await confirm(p.doc, p.binding, account, f, p.inputs);
    expect(code(out)).toBe("no-payable-option");
    expect(f.calls).toBe(0);
  }
}

/** Accounts that name no buyer: the pairings whose offer has no network take any CAIP-10 account. */
const UNNAMED = ["not-an-account", "eip155:84532", ""];

// ── card ──

const tapDoc = CARD.C2.build.doc;
const CJ: string = CARD.vi.CJ;
const [cjHeader, cjPayload, cjSignature] = CJ.split(".") as [string, string, string];
const httpLinkOf = (lc: Record<string, unknown>) => ({ ...lc, legalContextUrl: CARD.C1.httpLink.link });
const cjHttp = (() => {
  const payload = JSON.parse(Buffer.from(cjPayload, "base64url").toString("utf8"));
  payload.legalContext = httpLinkOf(payload.legalContext);
  return `${cjHeader}.${b64u(JSON.stringify(payload))}.${cjSignature}`;
})();
const tapHttp = { legalContext: httpLinkOf(tapDoc.legalContext) };

/** The agent's RFC 9421 signer, as the vectors publish it: sig2 over a base that carries the `lcp-hash` line. */
async function tapAnswer(r: SigningRequest) {
  expect(r).toEqual({ kind: "tap-field", ...CARD.C2.build.expect });
  if (r.kind !== "tap-field") throw new Error(r.kind);
  const base: string = CARD.C2.sig2Base;
  expect(base.split("\n")).toContain(`"lcp-hash": ${r.value}`);
  expect(createHash("sha256").update(base).digest("hex")).toBe(CARD.C2.expectSig2BaseSha256);
  const sig2 = /sig2=:([^:]+):/.exec(CARD.C2.request.signature)![1]!;
  const key = createPublicKey({ key: Buffer.from(CARD.C2.testKeyEd25519Spki, "base64"), format: "der", type: "spki" });
  expect(verify(null, Buffer.from(base), key, Buffer.from(sig2, "base64"))).toBe(true);
  return { signatureInput: CARD.C2.request.signatureInput, signature: CARD.C2.request.signature, lcpHash: CARD.C2.request.lcpHash };
}

const viRequest = { kind: "vi-checkout-mandate", ...CARD.C5.build.expect };
const card = {
  tap: { binding: visaTap, doc: tapDoc, account: BUYER, answer: tapAnswer } as Pairing,
  immediate: {
    binding: viImmediate,
    doc: CJ,
    account: BUYER,
    answer: async (r: SigningRequest) => {
      expect(r).toEqual(viRequest);
      return { l2: CARD.C6.bound.presented.l2 };
    },
  } as Pairing,
  autonomous: {
    binding: viAutonomous,
    doc: CJ,
    account: BUYER,
    answer: async (r: SigningRequest) => {
      expect(r).toEqual(viRequest);
      return { ...CARD.C7.bound.presented };
    },
  } as Pairing,
  sellerReference: { binding: sellerReference, doc: tapDoc, account: BUYER, answer: never } as Pairing,
};

/** Whether the gate hands `choose` the document: the card pieces build from it. */
const probe = await confirm(tapDoc, visaTap, BUYER, serving(ABC));
const gatePassesDoc = !(isDeclined(probe) && probe.decline.detail === "card/document-missing");

describe("card: the pieces over the vectors' requests and answers", () => {
  const read: Read = { h: H, link: LINK };
  const piece = (id: string): BuyerPiece => PIECES.get(id)!;
  const through = async (p: Pairing, doc: unknown) => {
    const pc = piece(p.binding.id);
    const chosen = (pc.choose as (...a: unknown[]) => Chosen | Refusal)(read, BUYER, {}, 1790000000, "r".repeat(32), doc);
    if ("refused" in chosen) throw new Error(chosen.code);
    const revived = pc.choice(JSON.parse(JSON.stringify(chosen)), ABC);
    const u = await (p.binding as unknown as { build(d: unknown, h: string): Promise<unknown> }).build(revived, H);
    return { pc, chosen, u };
  };

  for (const p of [card.tap, card.immediate, card.autonomous]) {
    it(`${p.binding.id}: choose keeps the document; the request and answer complete a payment bound to H`, async () => {
      const { pc, chosen, u } = await through(p, p.doc);
      expect(chosen.choice).toEqual({ doc: p.doc });
      const request = pc.request(u);
      if (request === null || "refused" in request) throw new Error("no request");
      const signed = await pc.complete(u, await p.answer(request as SigningRequest), chosen);
      if ((signed as Refusal).refused === true) throw new Error((signed as Refusal).code);
      expect(await check(ABC, signed, p.binding)).toEqual({ h: H });
      expect(code(await check(ABD, signed, p.binding))).toBe("signed-not-bound");
    });
  }

  it("card/visa-tap: the payment carries the lcp-hash lines the signer sent: C2's repeated field is refused, an upper-case line is read, another hash is not bound", async () => {
    const { pc, chosen, u } = await through(card.tap, tapDoc);
    const answer = { signatureInput: CARD.C2.request.signatureInput, signature: CARD.C2.request.signature };
    const completed = async (lcpHash: unknown) => pc.complete(u, { ...answer, lcpHash } as Signature, chosen);
    const repeated = await completed(CARD.C2.repeatedField.lcpHash);
    expect(await visaTap.bound(repeated)).toEqual({ refused: true, code: CARD.C2.repeatedField.expect });
    expect(code(await check(ABC, repeated, card.tap.binding))).toBe("signed-not-bound");
    expect(await check(ABC, await completed(CARD.C2.upperCaseField.lcpHash), card.tap.binding)).toEqual({ h: CARD.C2.upperCaseField.expectBound });
    const other = await completed([`0x${"11".repeat(32)}`]);
    expect(code(await check(ABC, other, card.tap.binding))).toBe("signed-not-bound");
    expect(await pc.complete(u, answer as Signature, chosen)).toEqual({ refused: true, code: "card/signature-malformed" });

    const signer = counting(BUYER, async () => ({ ...answer, lcpHash: CARD.C2.repeatedField.lcpHash }));
    const out = await finish(ABC, chosen, await signer.sign((pc.request(u) as SigningRequest)), card.tap.binding);
    expect(isDeclined(out) && out.decline).toEqual({ code: "signed-not-bound", detail: "What was signed does not carry the hash of these bytes." });
  });

  it("card/visa-tap: the payment carries the one lcp-hash line the build gave, and the signer's two fields", async () => {
    const { pc, chosen, u } = await through(card.tap, tapDoc);
    const signed = await pc.complete(u, await tapAnswer(pc.request(u) as SigningRequest), chosen);
    expect(signed).toEqual({
      signatureInput: CARD.C2.request.signatureInput,
      signature: CARD.C2.request.signature,
      lcpHash: CARD.C2.request.lcpHash,
    });
  });

  it("card/seller-reference: build refuses card/no-signed-place, so the piece hands nothing to a signer", async () => {
    const { pc, u } = await through(card.sellerReference, tapDoc);
    expect(u).toEqual({ refused: true, code: CARD.C8.expect });
    expect("refused" in (pc.request(u) as object)).toBe(true);
  });

  it("an account that is not CAIP-10 is card/no-payable-option", () => {
    for (const account of UNNAMED) {
      const choose = piece("card/visa-tap").choose as (...a: unknown[]) => Chosen | Refusal;
      expect(choose(read, account, {}, 0, "r", tapDoc)).toEqual({
        refused: true,
        code: "card/no-payable-option",
      });
    }
  });

  it("B10: an http link is offer-unreadable, card/link-not-https, with no fetch", async () => {
    await httpLink(card.tap, tapHttp, "card/link-not-https");
    await httpLink(card.sellerReference, tapHttp, "card/link-not-https");
    await httpLink(card.immediate, cjHttp, "card/link-not-https");
    await httpLink(card.autonomous, cjHttp, "card/link-not-https");
  });
});

describe.skipIf(!gatePassesDoc)("card: through the gate", () => {
  for (const p of [card.tap, card.immediate, card.autonomous, card.sellerReference]) {
    it(`${p.binding.id} B16: an account that names no buyer is no-payable-option, with no fetch`, () =>
      unpayable(p, UNNAMED));
  }
  it("card/visa-tap B6: the TAP field the vectors give, and sig2 over it, complete a payment bound to H", async () => {
    await signsOver(card.tap, ABC, H, () => undefined);
  });
  it("card/mastercard-vi/immediate B6: the checkout mandate the vectors give; the user's L2 is bound to H", async () => {
    await signsOver(card.immediate, ABC, H, (r) => expect(r).toEqual(viRequest));
  });
  it("card/mastercard-vi/autonomous B6: the same mandate; the agent's L3b chain is bound to H", async () => {
    await signsOver(card.autonomous, ABC, H, (r) => expect(r).toEqual(viRequest));
  });
  it("card/seller-reference B6: confirm-only; no request, no payment, the signer never called", async () => {
    expect(await confirmsOnly(card.sellerReference, ABC, H)).toMatchObject({ choice: { doc: tapDoc } });
  });
});

// ── AP2 ──

describe("ap2/checkout-mandate", () => {
  const F = AP2.fixed;
  const J: string = AP2.built.J;
  const p: Pairing = {
    binding: checkoutMandate,
    doc: J,
    account: BUYER,
    answer: async (r) => {
      expect(r).toEqual({
        kind: "ap2-checkout-mandate",
        content: { vct: AP2.V4.expectVct, checkout_jwt: J, checkout_hash: AP2.V4.expectCheckoutHash },
      });
      return AP2.built.M;
    },
  };

  it("the document is the merchant's checkout_jwt over the payload advertise gives", () => {
    const a = AP2.V2.advertise;
    const payload = JSON.parse(Buffer.from(J.split(".")[1]!, "base64url").toString("utf8"));
    expect(payload).toEqual(checkoutMandate.advertise(a.payload, a.h, a.link, a.offer));
  });
  it("B6: the closed mandate's claims are V4's; the vectors' mandate completes a payment bound to H", async () => {
    const signed = await signsOver(p, enc.encode(F.A), F.H, () => undefined);
    expect(signed).toEqual({ checkout_mandate: AP2.built.M, checkout_jwt: J });
    expect(await checkoutMandate.bound(signed as never)).toBe(AP2.V5.expectBound);
  });
  it("B10: an http link is offer-unreadable, ap2/link-not-https, with no fetch", async () => {
    const row = AP2.implementation.find((r: V) => r.name === "read-http-link");
    await httpLink(p, row.input.doc, "ap2/link-not-https");
  });
  it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
});

// ── UCP ──

describe("ucp", () => {
  const F = UCP.fixed;
  const atr = enc.encode(F.A);
  const signedBy = (c: V) => ({ ...c, ap2: { merchant_authorization: F.merchantAuthorization } });
  const checkout = signedBy(UCP.V2.expectCheckout);
  const booking = signedBy(UCP.V2b.expectBooking);

  /** The fixed recipe for J, D and M over a checkout the mandate discloses. */
  function mandateOver(c: V): { J: string; M: string } {
    const J = `${b64u(F.jwtHeader)}.${b64u(JSON.stringify(c))}.${F.signature}`;
    const D = b64u(F.disclosureTemplate.replace("<J>", J));
    const payload = (F.mandatePayload as string)
      .replace(UCP.V4.expectCheckoutHash, sha256b64u(J))
      .replace(UCP.V4.expectDisclosureDigest, sha256b64u(D));
    return { J, M: `${b64u(F.mandateHeader)}.${b64u(payload)}.${F.signature}~${D}~` };
  }
  const ucpHttp = (c: V) => ({
    ...c,
    links: c.links.map((l: V) => (l.type === "legal_context" ? { ...l, url: l.url.replace("https://", "http://") } : l)),
  });

  it("the recipe reproduces the vectors' J and M; the documents are advertise's", () => {
    expect(mandateOver(UCP.V2.expectCheckout)).toEqual({ J: UCP.built.J, M: UCP.built.M });
    const a = UCP.V2.advertise;
    expect(ap2Mandate.advertise(a.doc, a.h, a.link, a.offer)).toEqual(UCP.V2.expectCheckout);
    const b = UCP.V2b.advertise;
    expect(bookingAp2Mandate.advertise(UCP.V2b.B0, b.h, b.link, b.offer)).toEqual(UCP.V2b.expectBooking);
  });

  const mandates: [string, Binding, V, V][] = [
    ["ucp/checkout/ap2-mandate", ap2Mandate, checkout, UCP.V2.expectCheckout],
    ["ucp/booking/ap2-mandate", bookingAp2Mandate, booking, UCP.V2b.expectBooking],
  ];
  describe.each(mandates)("%s", (_id, binding, doc, payload) => {
    const { J, M } = mandateOver(payload);
    const p: Pairing = {
      binding,
      doc,
      account: BUYER,
      answer: async (r) => {
        expect(r).toEqual({ kind: "ucp-checkout", checkout: doc });
        return M;
      },
    };
    it("B6: the signed checkout goes to the issuer unchanged; its mandate completes a payment bound to H", async () => {
      const signed = await signsOver(p, atr, F.H, () => undefined);
      expect(signed).toEqual({ checkout_mandate: M, checkout_jwt: J });
      expect(await (binding as typeof ap2Mandate).bound(signed as never)).toBe(UCP.V4.expectBound);
    });
    it("B10: an http link is offer-unreadable, ucp/link-not-https, with no fetch", () =>
      httpLink(p, ucpHttp(doc), "ucp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });

  const confirmOnly: [string, Binding, V][] = [
    ["ucp/checkout/unsigned", unsigned, UCP.V2.expectCheckout],
    ["ucp/booking/unsigned", bookingUnsigned, UCP.V2b.expectBooking],
  ];
  describe.each(confirmOnly)("%s", (_id, binding, doc) => {
    const p: Pairing = { binding, doc, account: BUYER, answer: never };
    it("B6: confirm-only; build refuses V4's code, so no request, no payment, the signer never called", async () => {
      expect(await (binding as typeof unsigned).build({ checkout: doc }, F.H)).toEqual(UCP.V4.expectUnsignedBuild);
      await confirmsOnly(p, atr, F.H);
    });
    it("B10: an http link is offer-unreadable, ucp/link-not-https, with no fetch", () =>
      httpLink(p, ucpHttp(doc), "ucp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });
});

// ── ACP ──

describe("acp", () => {
  const F = ACP.fixed;
  const atr = enc.encode(F.A);
  const session = ACP.V2.expectSession;
  const { session: _s, ...values } = ACP.V4.choice;
  const acpHttp = {
    ...session,
    metadata: {
      ...session.metadata,
      legal_context: { ...session.metadata.legal_context, legal_context_url: F.L.replace("https://", "http://") },
    },
  };

  it("the session is advertise's", () => {
    const a = ACP.V2.advertise;
    expect(delegated.advertise(a.doc, a.h, a.link, a.offer)).toEqual(session);
  });

  describe("acp/checkout/delegated", () => {
    const p: Pairing = {
      binding: delegated,
      doc: session,
      account: BUYER,
      inputs: values,
      answer: async (r) => {
        expect(r).toEqual({ kind: "acp-allowance", allowance: ACP.V4.expectAllowance });
        if (r.kind !== "acp-allowance") throw new Error(r.kind);
        return { allowance: r.allowance };
      },
    };
    it("B6: the allowance is V4's, from the buyer's inputs; the signed request is bound to H", async () => {
      const signed = await signsOver(p, atr, F.H, () => undefined);
      expect(await delegated.bound(signed as never)).toBe(ACP.V4.expectBound);
    });
    it("a missing allowance input is no-payable-option, acp/input-missing, with no fetch", async () => {
      for (const k of Object.keys(values)) {
        const f = serving(atr);
        const { [k]: _gone, ...rest } = values;
        expect(await confirm(session, delegated, BUYER, f, rest)).toEqual({
          decline: { code: "no-payable-option", detail: "acp/input-missing" },
        });
        expect(f.calls).toBe(0);
      }
    });
    it("B10: an http link is offer-unreadable, acp/link-not-https, with no fetch", () =>
      httpLink(p, acpHttp, "acp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });

  describe("acp/checkout/undelegated", () => {
    const p: Pairing = { binding: undelegated, doc: ACP.V5.session, account: BUYER, answer: never };
    it("B6: confirm-only; build refuses V5's code, so no request, no payment, the signer never called", async () => {
      expect(await undelegated.build({} as never, F.H)).toEqual(ACP.V5.expectBuild);
      await confirmsOnly(p, atr, F.H);
    });
    it("B10: an http link is offer-unreadable, acp/link-not-https, with no fetch", () =>
      httpLink(p, acpHttp, "acp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });
});

// ── ACK ──

describe("ack/payment-request", () => {
  const O = ACK.fixed.O;
  const body = ACK.K2.body;
  const p: Pairing = { binding: paymentRequest, doc: body, account: `${O.network}:${BUYER.split(":")[2]}`, answer: never };
  const ackHttp = { ...body, legalContext: { ...body.legalContext, legalContextUrl: ACK.fixed.L.replace("https://", "http://") } };
  it("B6: confirm-only; the option on the account's network is K1's O; no request, no payment", async () => {
    expect(await paymentRequest.build({}, H)).toEqual(ACK.K5.expect);
    const chosen = await confirmsOnly(p, ABC, ACK.fixed.H);
    expect(chosen.choice).toEqual({ option: O });
  });
  it("B10: an http link is offer-unreadable, ack/link-not-https, with no fetch", () =>
    httpLink(p, ackHttp, "ack/link-not-https"));
  it("B16: an account on another network, or of another namespace, is no-payable-option, with no fetch", () =>
    unpayable(p, [`eip155:1:${BUYER.split(":")[2]}`, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", ...UNNAMED]));
});

// ── A2A ──

describe("a2a", () => {
  it("is a carrier, not a pairing: its binding is the refusal a2a/no-signed-place, and the gate has no piece", async () => {
    expect(a2aBinding).toEqual({ refused: true, code: "a2a/no-signed-place" });
    expect([...PIECES.keys()].filter((k) => k.startsWith("a2a/"))).toEqual([]);
    const f = serving(ABC);
    expect(code(await confirm({}, a2aBinding as never, BUYER, f))).toBe("pairing-not-supported");
    expect(f.calls).toBe(0);
  });
});
