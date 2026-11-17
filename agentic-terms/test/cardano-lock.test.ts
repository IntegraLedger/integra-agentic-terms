// x402/exact/cardano/lock's buyer piece over the protocol package's x402-exact-cardano.json, the file of both Cardano
// pairings. The lock's document is the file's B2 document for the lock, the `script` method's option fixed.OLock
// advertising H; the wallet answers with V2's transaction, whose body commits to V1's auxiliary data, and fixed.nonce,
// the input it spends. Every expected value, and every input, is the file's.
import { describe, expect, it } from "vitest";
import { exactCardanoLock } from "@integraledger/lcp/cardano";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import type { Binding, Presented, SigningRequest } from "../src/index.js";
import { buildAndSign, code, counting, piecePay, toHex, vectors, type Pairing } from "./support.js";

interface BuyerRow {
  name: string;
  pairing: string;
  input: { doc?: PaymentRequired; account?: string; now?: number; presented?: Presented };
}
const ADA = vectors<{
  fixed: { OLock: PaymentRequirements; nonce: string; resource: { url: string } };
  V1: { auxiliaryDataHex: string };
  V2: { transactionBase64: string };
  V6: { case: string; transactionBase64: string; expectLock: string };
  buyer: { rows: BuyerRow[] };
}>("x402-exact-cardano.json");

const LOCK = "x402/exact/cardano/lock";
const row = (name: string): BuyerRow => {
  const found = ADA.buyer.rows.find((r) => r.name === name && r.pairing === LOCK);
  if (found === undefined) throw new Error(`x402-exact-cardano.json holds no buyer row ${name} for ${LOCK}`);
  return found;
};
const B2 = row("B2");
const B6 = row("B6");
const binding = exactCardanoLock as unknown as Binding;

/** The request the lock's build hands the wallet: the file's lock option and V1's auxiliary data, which carry H. */
function checkRequest(r: SigningRequest): void {
  if (r.kind !== "cardano-transaction") throw new Error(r.kind);
  expect(r.accepted).toEqual(ADA.fixed.OLock);
  expect(toHex(r.auxiliaryData).slice(2)).toBe(ADA.V1.auxiliaryDataHex);
}

/** Freezes the clock at the B2 row's `now`, in seconds, and restores it. */
async function atNow<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => B2.input.now! * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

const lock: Pairing = {
  binding,
  doc: B2.input.doc,
  // No `placed`: the answer is the vectors' payment, bound to H, which no signer here makes for another H, so the gate's
  // half over A cannot be signed; the steps by themselves hold the pairing.
  account: B2.input.account!,
  answer: async (r) => {
    checkRequest(r);
    return { transaction: ADA.V2.transactionBase64, nonce: ADA.fixed.nonce };
  },
};

describe("x402/exact/cardano/lock", () => {
  it("B6: the request is the file's; the wallet's answer completes the B6 row's payment, bound to H", () =>
    atNow(async () => {
      const { signed } = await buildAndSign(lock, checkRequest);
      const { x402Version, accepted, payload } = signed as unknown as Record<string, unknown>;
      expect({ x402Version, accepted, payload }).toEqual(B6.input.presented);
    }));

  it(`V6: ${ADA.V6.case}: the lock completes no payment (${ADA.V6.expectLock})`, () =>
    atNow(async () => {
      const signer = counting(lock.account, async (r) => {
        checkRequest(r);
        return { transaction: ADA.V6.transactionBase64, nonce: ADA.fixed.nonce };
      });
      const out = await piecePay(lock.doc, binding, signer);
      expect(signer.requests.length).toBe(1);
      const detail = "decline" in out ? out.decline.detail : undefined;
      expect([code(out), detail]).toEqual(["signed-not-bound", "x402/signed-not-bound"]);
    }));
});
