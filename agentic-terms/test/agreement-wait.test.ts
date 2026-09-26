// The agreement resource, paid, runs `/verify` then `/settle`, reads the transaction at the network's declared finality,
// and answers 200 once the agreement is recorded; the buyer waits for that 200 receipt. The seller bounds that one paid
// request by `/verify` ≤ 10 s, `/settle` ≤ 60 s and an exchange deadline of now + min(`accepted.maxTimeoutSeconds`,
// 120) s; the agreement option here has `maxTimeoutSeconds` 60 (buyer.json). A paid request answered 200 after 15 s is
// inside those bounds, so the buyer's agreement step receives the receipt and the full payment follows. Inputs are
// buyer.json's.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedDataDefinition } from "viem";
import { exactEip3009, type PaymentRequired } from "@integraledger/lcp/x402";
import { transact, type Binding, type Fetch, type SigningRequest } from "../src/index.js";
import { vectors } from "./support.js";

const B = vectors<{
  fixed: {
    A: string;
    D: PaymentRequired;
    account: string;
    payerKey: `0x${string}`;
    now: number;
    agreement: { url: string; required: unknown; receipt: unknown };
  };
}>("buyer.json");
const A = Uint8Array.from(Buffer.from(B.fixed.A, "hex"));
const AG = B.fixed.agreement;
const key = privateKeyToAccount(B.fixed.payerKey);
const PAID_ANSWER_MS = 15_000;

function withAgreement(): Binding {
  const real = exactEip3009.read(B.fixed.D);
  if ("refused" in real) throw new Error(real.code);
  return { ...exactEip3009, pattern: { ...exactEip3009.pattern, publicProof: false }, read: () => ({ ...real, agreement: AG.url }) };
}

/** The ATR at its link; the agreement URL: 402 unpaid, and, paid, 200 with the receipt after 15 s. */
function seller(): Fetch & { paid: number } {
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    if (url !== AG.url) return new Response(new Uint8Array(A), { status: 200 });
    if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
      const header = Buffer.from(JSON.stringify(AG.required), "utf8").toString("base64");
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }
    f.paid++;
    return new Promise<Response>((resolve) =>
      setTimeout(() => resolve(new Response(JSON.stringify(AG.receipt), { status: 200 })), PAID_ANSWER_MS),
    );
  }) as Fetch & { paid: number };
  f.paid = 0;
  return f;
}

/** Runs `p` under the fake clock, moving it to each next timer until `p` settles. */
async function drive<T>(p: Promise<T>): Promise<T> {
  let done = false;
  let value: T | undefined;
  void p.then((v) => {
    done = true;
    value = v;
  });
  for (;;) {
    while (!done && vi.getTimerCount() === 0) await new Promise((resolve) => setImmediate(resolve));
    if (done) return value as T;
    await vi.advanceTimersToNextTimerAsync();
  }
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  vi.setSystemTime(B.fixed.now * 1000);
});
afterEach(() => vi.useRealTimers());

describe("a paid agreement request answered within the seller's bounds is waited for", () => {
  it("200 with the receipt after 15 s: the receipt, then the full payment", async () => {
    const kinds: string[] = [];
    const signer = {
      account: B.fixed.account,
      async sign(r: SigningRequest) {
        kinds.push(r.kind);
        if (r.kind !== "eip712") throw new Error(r.kind);
        return key.signTypedData(r.typedData as unknown as TypedDataDefinition);
      },
    };
    const fetch = seller();
    const out = await drive(transact(B.fixed.D, withAgreement(), signer, fetch));
    expect(fetch.paid).toBe(1);
    expect(out).not.toHaveProperty("decline");
    expect(out).toMatchObject({ agreement: AG.receipt });
    expect(kinds.length).toBe(2);
  });
});
