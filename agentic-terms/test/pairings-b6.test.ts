// B2 and B6 for the Casper, Concordium and MPP Lightning pairings. Expected values are their vector files'; the signer
// answers with the values those files publish.
import { describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { exactCasper } from "@integraledger/lcp/casper";
import { exactCcd } from "@integraledger/lcp/ccd";
import { chargeLightning, sessionLightning } from "@integraledger/lcp/lightning";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { confirm, type Binding } from "../src/index.js";
import { buildAndSign, code, H, LINK, serving, vectors, type Pairing } from "./support.js";

import { CONFIRMING } from "./support.js";
const NOW = 1_790_000_000;
async function at<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => NOW * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

type Advertises = { advertise(doc: unknown, h: string, link: string, offer: unknown, ...rest: unknown[]): unknown };
/** `rest` is what the pairing's `advertise` takes after the offer: on MPP the challenge's position. */
function placed<T>(binding: Binding, doc: unknown, offer: unknown, h: AtrHash = H, link = LINK, ...rest: unknown[]): T {
  const out = (binding as unknown as Advertises).advertise(doc, h, link, offer, ...rest);
  if (typeof out === "object" && out !== null && "refused" in out) throw new Error(JSON.stringify(out));
  return out as T;
}
const x402Doc = (binding: Binding, resource: object, option: PaymentRequirements, h: AtrHash = H, link = LINK) =>
  placed<PaymentRequired>(binding, { x402Version: 2, resource, accepts: [option] }, option, h, link);

describe("x402/exact/casper", () => {
  const V = vectors<{
    fixed: { O: PaymentRequirements; from: string; resource: object; publicKey: string; signature: string; H: AtrHash };
    C1: { expectDomain: object; expectMessage: Record<string, unknown> };
    C2: { expectPayload: { payload: object } };
    refusals: { rows: { case: string; fn: string; choice?: unknown; expect: object }[] };
  }>("x402-exact-casper.json");
  const f = V.fixed;
  const p: Pairing = {
    binding: exactCasper,
    doc: x402Doc(exactCasper, f.resource, f.O),
    placed: (h) => x402Doc(exactCasper, f.resource, f.O, h),
    account: `${f.O.network}:${f.from}`,
    answer: async () => ({ publicKey: f.publicKey, signature: f.signature }),
  };
  it("B6: C1's typed data; the answer completes C2's payload, bound to H", () =>
    at(async () => {
      const { signed } = await buildAndSign(p, (r) => {
        if (r.kind !== "casper-eip712") throw new Error(r.kind);
        expect(r.typedData.domain).toEqual(V.C1.expectDomain);
        for (const [k, v] of Object.entries(V.C1.expectMessage)) expect(String((r.typedData.message as Record<string, unknown>)[k])).toBe(String(v));
      });
      expect((signed as { payload: object }).payload).toEqual(V.C2.expectPayload.payload);
    }));
  it("refusals: each build row with a choice of its own gives the row's refusal", async () => {
    const rows = V.refusals.rows.filter((r) => r.fn === "build" && "choice" in r);
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(await exactCasper.build(r.choice as never, f.H), r.case).toEqual(r.expect);
  });
});

describe("x402/exact/ccd", () => {
  const V = vectors<{
    fixed: { O: PaymentRequirements; payer: string; resource: object; sponsor: string; payee: string };
    D1: { expectCcdMemo: string };
    D3: { ccd: { payment: { payload: { signedTransaction: object } } } };
    stockOptions: { rows: { option: PaymentRequirements; expectRequest: { expiresBy: number } }[] };
  }>("x402-exact-ccd.json");
  const f = V.fixed;
  const p: Pairing = {
    binding: exactCcd,
    doc: x402Doc(exactCcd, f.resource, f.O),
    // No `placed`: the answer is D3's signed transaction, bound to H, which no signer here makes for another H, so the
    // gate's half over A cannot be signed; the steps by themselves hold the pairing.
    account: `${f.O.network}:${f.payer}`,
    answer: async () => V.D3.ccd.payment.payload.signedTransaction as never,
  };
  it("B6: the transfer carries D1's memo; D3's signed transaction is bound to H", () =>
    at(async () => {
      await buildAndSign(p, (r) => {
        if (r.kind !== "ccd-transfer") throw new Error(r.kind);
        expect(Buffer.from(r.memo).toString("hex")).toBe(V.D1.expectCcdMemo);
        expect(r.sponsor).toBe(f.sponsor);
        expect(r.toAddress).toBe(f.payee);
        // The stock client signs now plus maxTimeoutSeconds less its margin: the expiresBy of the vector file's expected
        // request for O's amount at the file's now.
        const row = V.stockOptions.rows.find((x) => x.option.amount === f.O.amount)!;
        expect(r.expiresBy).toBe(row.expectRequest.expiresBy);
      });
    }));
});

const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
type LnMpp = { challenge: Omit<MppChallenge, "request">; request: object };
function lnChallenges(binding: Binding, row: LnMpp, h: AtrHash = H): MppChallenge[] {
  const issued = { ...row.challenge, request: b64u(JSON.stringify(row.request)) } as MppChallenge;
  return placed<MppChallenge[]>(binding, [issued], issued, h, LINK, 0);
}

describe("mpp/charge/lightning and mpp/session/lightning", () => {
  const C = vectors<{ fixed: { preimage: string; payee: string }; L3: LnMpp & { request: { methodDetails: { invoice: string } } } }>(
    "mpp-charge-lightning.json",
  );
  const S = vectors<{ fixed: { preimage: string; returnInvoice: string }; S1: LnMpp & { request: { depositInvoice: string } } }>(
    "mpp-session-lightning.json",
  );
  const account = `lnbtc:000000000019d6689c085ae165831e93:${C.fixed.payee}`;
  const charge: Pairing = {
    binding: chargeLightning,
    doc: lnChallenges(chargeLightning, C.L3),
    account,
    answer: async () => C.fixed.preimage,
  };
  const session: Pairing = {
    binding: sessionLightning,
    doc: lnChallenges(sessionLightning, S.S1),
    account,
    inputs: { returnInvoice: S.fixed.returnInvoice },
    answer: async () => S.fixed.preimage,
  };
  it("B6 (charge): the node pays L3's invoice; the preimage completes a credential bound to H", () =>
    at(async () => {
      await buildAndSign(charge, (r) => expect(r).toEqual({ kind: "bolt11-pay", invoice: C.L3.request.methodDetails.invoice }));
    }));
  it("B6 (session): the deposit invoice; the return invoice is the buyer's input, carried in the open", () =>
    at(async () => {
      const { signed } = await buildAndSign(session, (r) =>
        expect(r).toEqual({ kind: "bolt11-pay", invoice: S.S1.request.depositInvoice }),
      );
      expect((signed as { payload: object }).payload).toEqual({
        action: "open",
        preimage: S.fixed.preimage,
        returnInvoice: S.fixed.returnInvoice,
      });
    }));
  it("B16: without the return invoice, or with another namespace, no-payable-option before any fetch", () =>
    at(async () => {
      const fetch = serving(new TextEncoder().encode("abc"));
      expect(code(await confirm(session.doc, sessionLightning, account, fetch, CONFIRMING))).toBe("no-payable-option");
      expect(code(await confirm(charge.doc, chargeLightning, "eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", fetch, CONFIRMING))).toBe(
        "no-payable-option",
      );
      expect(fetch.calls).toBe(0);
    }));
});
