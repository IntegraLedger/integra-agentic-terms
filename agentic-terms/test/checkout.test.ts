// The checkout pieces and summaries, each over the protocol package's own rows. ap2/checkout-mandate/x402 and
// ucp/checkout/agent-signed by their own steps: the request handed to the signer is the protocol package's build over
// the file's checkout, and the file's payment, given as the signer's answer, completes a payment bound to the file's H.
// AP2's push funding: a payment the payer's side already sent is kept as `moved` when the gate declines it. The
// summaries of the checkout requests, summary-checkout.json's rows, which the Python tests run too; each payment moves
// on no ledger, so each is shown with no network. The x402 route is also paid through the gate, its approver shown that
// summary.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { finish, transact, type Binding, type SigningRequest, type ToSign } from "../src/index.js";
import { SUMMARIES } from "../src/summary.js";
import { counting, fromHex, GATE, isDeclined, offered, pieceConfirm, receiptFor, unpaidReceiptFor, serving, vectors } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type V = any;
const AP2: V = vectors("ap2-checkout-mandate.json");
const AP2_X402: V = vectors("ap2-checkout-mandate-x402.json");
const AGENT: V = vectors("ucp-checkout-agent-signed.json");
const BROADCASTER: V = vectors("broadcaster.json");

const bindingOf = (id: string): Binding => BINDINGS.find((b) => b.id === id) as unknown as Binding;
const row = (file: V, pairing: string, name: string): V =>
  file.buyer.rows.find((r: V) => r.pairing === pairing && r.name === name);
const ACCOUNT = row(AP2_X402, "ap2/checkout-mandate/x402", "B2").input.account as string;
const NO_END = { notBefore: null, notAfter: null, unit: "seconds" };

/** The request for the file's checkout and the payment the file presents, completed by `finish` with the file's ATR. */
async function bySteps(id: string, doc: unknown, atr: Uint8Array, answer: unknown) {
  const binding = bindingOf(id);
  const confirmed = await pieceConfirm(doc, offered(binding), ACCOUNT, {}, atr);
  if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
  const done = await finish(atr, JSON.parse(JSON.stringify(confirmed.chosen)), answer as never, binding);
  return { request: confirmed.request, h: confirmed.h, done };
}

describe("the checkout pieces by their own steps", () => {
  it("ap2/checkout-mandate/x402: the mandate's claims are V4's; B6's mandate and AP2's x402 bundle complete B6's payment", async () => {
    const b6 = row(AP2_X402, "ap2/checkout-mandate/x402", "B6");
    const presented = b6.input.presented;
    const atr = fromHex(b6.input.check[0].bytesHex);
    const { request, h, done } = await bySteps("ap2/checkout-mandate/x402", presented.checkout_jwt, atr, {
      checkout_mandate: presented.checkout_mandate,
      payment: presented.payment,
    });
    expect(request).toEqual({
      kind: "ap2-checkout-mandate",
      content: { vct: AP2.V4.expectVct, checkout_jwt: presented.checkout_jwt, checkout_hash: AP2.V4.expectCheckoutHash },
    });
    expect([h, done]).toEqual([b6.expect[0].h, { signed: presented, h: b6.expect[0].h }]);

    // Through the gate over the same ATR, one JSON text: the approver is shown the checkout's charge, and the request
    // names no expiry, so the payment signs no end (profile buyer-gate.md, rule 8) and the caller raises the ceiling.
    const shown: ToSign[] = [];
    const signer = counting(ACCOUNT, async () => ({ checkout_mandate: presented.checkout_mandate, payment: presented.payment }));
    const whole = await transact(presented.checkout_jwt, offered(bindingOf("ap2/checkout-mandate/x402")), signer, serving(atr), {
      ...GATE,
      approver: (t) => (shown.push(t), true),
      ceilings: { "ap2/checkout-mandate/x402": "no-end" },
    });
    expect(whole).toEqual({ signed: presented, bytes: atr, h, agreement: unpaidReceiptFor(h) });
    expect([signer.requests, shown.map((t) => [t.act, t.request, t.summary])]).toEqual([
      [request],
      [["payment", request, { amount: "19900", payees: [], asset: "USD", network: null, validity: NO_END, atr }]],
    ]);
  });

  it("ucp/checkout/agent-signed: the build row's member beside the checkout; bound row 1's request completes a payment bound to H", async () => {
    const doc = row(AGENT, "ucp/checkout/agent-signed", "B2").input.doc;
    const answer = AGENT.bound[0].presented;
    const { request, h, done } = await bySteps("ucp/checkout/agent-signed", doc, new TextEncoder().encode("abc"), answer);
    expect(request).toEqual({ kind: "ucp-legal-context", checkout: doc, legal_context: AGENT.build[0].expect.legal_context });
    expect([h, done]).toEqual([AGENT.fixed.H, { signed: answer, h: AGENT.fixed.H }]);
  });
});

describe("ap2/checkout-mandate: push funding", () => {
  const b6 = row(AP2, "ap2/checkout-mandate", "B6");
  const atr = fromHex(b6.input.check[0].bytesHex);
  const receipt = BROADCASTER.kinds.find((k: V) => k.pairing === "ap2/checkout-mandate" && k.expect === "payer")
    .presented.payment_receipt;

  it("B6's mandate with broadcaster.json's Payment Receipt completes the push presentation, bound to H", async () => {
    const answer = { checkout_mandate: b6.input.presented.checkout_mandate, payment_receipt: receipt };
    const { done } = await bySteps("ap2/checkout-mandate", b6.input.presented.checkout_jwt, atr, answer);
    expect(done).toEqual({ signed: { ...b6.input.presented, payment_receipt: receipt }, h: b6.expect[0].h });
  });

  it("a pushed payment whose mandate commits to another checkout (V6's) is declined with the payment kept as moved", async () => {
    const answer = { checkout_mandate: AP2.V6.token, payment_receipt: receipt };
    const { done } = await bySteps("ap2/checkout-mandate", b6.input.presented.checkout_jwt, atr, answer);
    expect(done).toEqual({
      decline: { code: "signed-not-bound", detail: expect.any(String) },
      moved: {
        signed: { checkout_mandate: AP2.V6.token, checkout_jwt: b6.input.presented.checkout_jwt, payment_receipt: receipt },
        bytes: atr,
        h: b6.expect[0].h,
      },
    });
  });
});

const SHARED: V = JSON.parse(readFileSync(new URL("./summary-checkout.json", import.meta.url), "utf8"));

/** A row's request, each `{"$ref": pointer}` replaced by the value at that JSON Pointer (RFC 6901) in `file`. */
function resolved(v: V, file: V): V {
  if (Array.isArray(v)) return v.map((x) => resolved(x, file));
  if (typeof v !== "object" || v === null) return v;
  if (typeof v.$ref === "string") {
    return v.$ref.split("/").slice(1).reduce((at: V, k: string) => at[k.replaceAll("~1", "/").replaceAll("~0", "~")], file);
  }
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolved(x, file)]));
}

describe("the checkout summaries, summary-checkout.json's rows", () => {
  for (const r of SHARED.rows as V[]) {
    it(`${r.pairing}: ${r.file} ${r.from}`, async () => {
      const show = SUMMARIES.get(r.pairing)!.show as (request: SigningRequest, network: string) => unknown;
      expect(await show(resolved(r.request, vectors(r.file)), r.network)).toEqual(r.expect);
    });
  }
});
