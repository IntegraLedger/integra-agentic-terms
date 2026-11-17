// The card pieces of card/visa-vic, card/mastercard-agent-pay and Verifiable Intent's Immediate checkout payload, and
// the VI signer's rule. Every request, answer and hash is a vector file's: card.json's (T6, T7, V10, C2, C5, C6 and the
// VI strings), buyer.json's ATR A, and vi-signer.json's rows, computed by Python's json module.
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { Json } from "@integraledger/lcp";
import { agentPay, viImmediate, visaVic } from "@integraledger/lcp/card";
import { check, finish, transact, viJson, type Binding, type SigningRequest, type ToSign } from "../src/index.js";
import { summaryOf } from "../src/summary.js";
import { A, ABC, ABD, code, counting, GATE, H, HA, isDeclined, LINK, offered, pieceConfirm, receiptFor, serving, vectors } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type V = any;
const CARD: V = vectors("card.json");
const RULE: { rows: { case: string; json: string; expect: string }[] } = JSON.parse(
  readFileSync(new URL("../vectors/vi-signer.json", import.meta.url), "utf8"),
);
const BUYER = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const CJ: string = CARD.vi.CJ;
const CJ_PAYLOAD = JSON.parse(Buffer.from(CJ.split(".")[1]!, "base64url").toString("utf8"));
const SHOWN = { legalContext: CJ_PAYLOAD.legalContext };
const nothingNamed = { payees: [], asset: "", network: null, validity: { notBefore: null, notAfter: null, unit: "seconds" } };

/** Runs `run` with every 32-byte draw of the platform's random source answering C2's random bytes, so TAP's build gives C2's nonce. */
async function withC2Random<T>(run: () => Promise<T>): Promise<T> {
  const real = crypto.getRandomValues.bind(crypto);
  const random = Buffer.from(CARD.C2.random as string, "hex");
  const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation(<B extends ArrayBufferView | null>(a: B): B => {
    if (a instanceof Uint8Array && a.length === 32) a.set(random);
    else real(a as never);
    return a;
  });
  try {
    return await run();
  } finally {
    spy.mockRestore();
  }
}

/** The pairing's own steps over `abc` with no gate: the request handed to the signer, and the choice it was built from. */
async function built(binding: Binding, doc: unknown, inputs = {}) {
  const out = await pieceConfirm(doc, offered(binding), BUYER, inputs);
  if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
  expect(out.h).toBe(H);
  return out;
}

describe("the VI signer's rule: vi-signer.json, Python's json.dumps", () => {
  for (const row of RULE.rows) {
    it(`${row.case}`, () => expect(viJson(JSON.parse(row.json))).toBe(row.expect));
  }
});

describe("card/visa-vic", () => {
  it("T7: the request is the build's transaction reference; the reference as the credential returns it completes a payment bound to H", async () => {
    const { chosen, request } = await built(visaVic, SHOWN);
    expect(request).toEqual({ kind: "vic-reference", ...CARD.T7.build.expect });
    const done = await finish(ABC, JSON.parse(JSON.stringify(chosen)), { ...CARD.T7.bound.presented }, visaVic);
    expect(done).toEqual({ signed: CARD.T7.bound.presented, h: CARD.T7.bound.expect });
    expect(code(await finish(ABD, JSON.parse(JSON.stringify(chosen)), { ...CARD.T7.bound.presented }, visaVic))).toBe("signed-not-bound");
  });

  it("through the gate over buyer.json's ATR A: no-end until the caller lifts the ceiling, then paid after the agreement", async () => {
    const doc = { legalContext: (visaVic.advertise({}, HA, LINK, { scheme: "visa-vic", checkout: "chk_1001" }) as { legalContext: Json }).legalContext };
    const echo = counting(BUYER, async (r: SigningRequest) => ({ transactionReferenceId: (r as { transactionReferenceId: string }).transactionReferenceId }));
    expect(code(await transact(doc, offered(visaVic), echo, serving(A), GATE))).toBe("no-end");
    expect(echo.requests.length).toBe(0);
    const shown: ToSign[] = [];
    const approver = (t: ToSign) => (shown.push(t), true);
    const out = await transact(doc, offered(visaVic), echo, serving(A), { ...GATE, approver, ceilings: { "card/visa-vic": "no-end" } });
    if (isDeclined(out) || "approve" in out) throw new Error(JSON.stringify(out));
    expect([echo.requests.length, out.agreement]).toEqual([1, receiptFor(HA)]);
    expect(shown.map((t) => [t.act, t.request.kind, { ...t.summary, atr: undefined }])).toEqual([["payment", "vic-reference", { ...nothingNamed, atr: undefined }]]);
    expect(await check(A, out.signed, visaVic)).toEqual({ h: HA });
  });
});

describe("card/mastercard-agent-pay", () => {
  it("T6: C2's nonce, the hash then C2's random bytes, and Agent Pay's signature over it complete a payment bound to H", () =>
    withC2Random(async () => {
      const { chosen, request } = await built(agentPay, SHOWN);
      expect(request).toEqual({ kind: "tap-field", nonce: CARD.C2.nonce });
      for (const row of CARD.T6.rows.filter((r: V) => r.expect === H)) {
        expect(row.signatureInput).toContain(`nonce="${CARD.C2.nonce}"`);
        const answer = { signatureInput: row.signatureInput, signature: row.signature };
        expect(await finish(ABC, JSON.parse(JSON.stringify(chosen)), answer, agentPay)).toEqual({ signed: answer, h: H });
      }
    }));
});

describe("card/mastercard-vi/immediate: the agent's checkout payload", () => {
  it("V10: the agent's payload with the shown legalContext written into it is the request", async () => {
    const { choice } = CARD.V10.immediateBuild;
    const { request } = await built(viImmediate, choice.shown, { checkout: choice.checkout });
    expect(request).toEqual({ kind: "vi-checkout", ...CARD.V10.immediateBuild.expect });
  });

  it("CJ: the payload is CJ's, so CJ signs it; the mandate over CJ is C5's, and C6's L2 completes a payment bound to H", async () => {
    const { legalContext: _lc, ...checkout } = CJ_PAYLOAD;
    const { chosen, request } = await built(viImmediate, SHOWN, { checkout });
    expect(viJson((request as { checkout: Json }).checkout)).toBe(Buffer.from(CJ.split(".")[1]!, "base64url").toString("utf8"));
    const kept = JSON.parse(JSON.stringify(chosen));
    // The mandate, the later step, is held to its ceiling: the request names no end, so the caller lifts it.
    expect(code(await finish(ABC, kept, { checkout_jwt: CJ }, viImmediate))).toBe("no-end");
    const ceilings = { "card/mastercard-vi/immediate": "no-end" } as const;
    const step = await finish(ABC, kept, { checkout_jwt: CJ }, viImmediate, { ceilings });
    if (!("next" in step)) throw new Error(JSON.stringify(step));
    expect([step.next, step.h]).toEqual([{ kind: "vi-checkout-mandate", ...CARD.C5.build.expect }, H]);
    expect({ ...step.summary, atr: undefined }).toEqual({ ...nothingNamed, grant: CJ_PAYLOAD, atr: undefined });
    const done = await finish(ABC, kept, [{ checkout_jwt: CJ }, { l2: CARD.C6.bound.presented.l2 }], viImmediate);
    expect(done).toEqual({ signed: { l2: CARD.C6.bound.presented.l2 }, h: H });
  });

  // On the JSON the seller showed, the payment takes two signings: the agent's payload, then the mandate over its
  // checkout_jwt (V10; CJ, C5, C6). Through the gate over buyer.json's ATR A, its document placed for A's hash by the
  // pairing's own advertise with C1's mastercard-vi option, the approver is told the first is one of two signings.
  it("through the gate over buyer.json's ATR A: the agent's payload is asked as the first of two signings", async () => {
    const option = CARD.C1.digestJson.find((r: V) => r.option.scheme === "mastercard-vi").option;
    const doc = { legalContext: (viImmediate.advertise({}, HA, LINK, option) as { legalContext: Json }).legalContext };
    const agent = counting(BUYER, async () => {
      throw new Error("the approver declines the first signing");
    });
    const asked: ToSign[] = [];
    const out = await transact(doc, offered(viImmediate), agent, serving(A), {
      ...GATE,
      approver: (t) => (asked.push(t), false),
      inputs: { checkout: CARD.V10.immediateBuild.choice.checkout },
      ceilings: { "card/mastercard-vi/immediate": "no-end" },
    });
    expect(code(out)).toBe("not-approved");
    expect([asked.map((t) => [t.act, t.request.kind, t.step]), agent.requests.length]).toEqual([[["payment", "vi-checkout", { index: 0, count: 2 }]], 0]);
  });

  it("a checkout_jwt whose payload is not the payload handed completes nothing: V10's payload answered with CJ", async () => {
    const { choice } = CARD.V10.immediateBuild;
    const { chosen } = await built(viImmediate, choice.shown, { checkout: choice.checkout });
    const out = await finish(ABC, JSON.parse(JSON.stringify(chosen)), { checkout_jwt: CJ }, viImmediate);
    expect(out).toEqual({ decline: { code: "signed-not-bound", detail: "card/signature-malformed" } });
  });
});

describe("the card summaries, of the requests lcp's build vectors give", () => {
  const atr = ABC;
  const shown = async (pairing: string, request: unknown) => {
    const s = await summaryOf(pairing, request as SigningRequest, atr);
    return s === undefined ? undefined : { ...s, atr: Buffer.from(s.atr).toString() };
  };
  it("tap-field (C2), vic-reference (T7): no amount, payee or currency named, no ledger, and no end signed", async () => {
    expect(await shown("card/visa-tap", { kind: "tap-field", nonce: CARD.C2.nonce })).toEqual({ ...nothingNamed, atr: "abc" });
    expect(await shown("card/mastercard-agent-pay", { kind: "tap-field", nonce: CARD.C2.nonce })).toEqual({ ...nothingNamed, atr: "abc" });
    expect(await shown("card/visa-vic", { kind: "vic-reference", ...CARD.T7.build.expect })).toEqual({ ...nothingNamed, atr: "abc" });
  });
  it("vi-checkout (V10) grants the payload; vi-checkout-mandate (C5) grants the payload of the checkout_jwt it names", async () => {
    const payload = CARD.V10.immediateBuild.expect.checkout;
    expect(await shown("card/mastercard-vi/immediate", { kind: "vi-checkout", checkout: payload })).toEqual({ ...nothingNamed, grant: payload, atr: "abc" });
    const mandate = { kind: "vi-checkout-mandate", ...CARD.C5.build.expect };
    for (const pairing of ["card/mastercard-vi/immediate", "card/mastercard-vi/autonomous"]) {
      expect(await shown(pairing, mandate)).toEqual({ ...nothingNamed, grant: CJ_PAYLOAD, atr: "abc" });
    }
  });
});

