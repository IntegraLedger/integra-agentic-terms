// For `mpp/charge/evm/transaction` and `mpp/charge/evm/hash`, `complete` returns `{challenge, source, payload: {type:
// "transaction", signature: <signed tx>}}`, or, for `hash`, `{…, payload: {type: "hash", hash: <tx hash>}}`; the gate
// calls the signer only after its comparison and after the agreement's 200; `bound` returns `mpp/no-signed-place`,
// because nothing the payer signed carries H, and the gate relies on the agreement transaction instead. So with the
// agreement recorded, `transact` returns the credential the signer completed, with the receipt. The raw transaction's
// SHA-256 and the transaction hash are MV11's and MV12's (viem 2.56.8 and eth-account 0.14.0, which agree).
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedDataDefinition } from "viem";
import { evmHash, evmTransaction, type MppChallenge } from "@integraledger/lcp/mpp";
import { exactEip3009, type PaymentRequirements } from "@integraledger/lcp/x402";
import { transact, type Binding, type Fetch, type SigningRequest } from "../src/index.js";
import { ABC, H, LINK, transactApproved, vectors } from "./support.js";

const MC = vectors<{ fixed: { realm: string; expires: string } }>("mpp-challenge.json");
const X = vectors<{
  fixed: { payerKey: `0x${string}`; payer: `0x${string}`; now: number; R_ENoTypes: string };
  MV11: {
    transaction: { chainId: number; nonce: number; maxPriorityFeePerGas: string; maxFeePerGas: string; gas: number };
    expectRawSha256: string;
  };
}>("mpp-charge-evm-transaction.json");
const MV12 = vectors<{ MV12: { hash: `0x${string}` } }>("mpp-charge-evm-hash.json").MV12;
const AG = vectors<{ fixed: { agreement: { option: PaymentRequirements } } }>("buyer.json").fixed.agreement;

const AGREEMENT_URL = `https://pay.seller.example/agreement/${H}`;
const RECEIPT = { atrHash: H, agreed: true, network: "eip155:84532", transaction: `0x${"cd".repeat(32)}` };
const ACCOUNT = `eip155:84532:${X.fixed.payer}`;
const payer = privateKeyToAccount(X.fixed.payerKey);

const challenge = {
  realm: MC.fixed.realm,
  method: "evm",
  intent: "charge",
  request: Buffer.from(X.fixed.R_ENoTypes, "utf8").toString("base64url"),
  expires: MC.fixed.expires,
} as MppChallenge;

/** The seller: the ATR at LINK; the agreement URL answers 402 unpaid and 200 with the receipt once paid. */
function seller(): Fetch {
  const required = exactEip3009.advertise(
    { x402Version: 2, resource: { url: AGREEMENT_URL }, accepts: [AG.option] },
    H,
    LINK,
    AG.option,
  );
  const header = Buffer.from(JSON.stringify(required), "utf8").toString("base64");
  return async (url, init) => {
    if (url === LINK) return new Response(new Uint8Array(ABC), { status: 200 });
    if (url !== AGREEMENT_URL) return new Response(null, { status: 404 });
    if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }
    return new Response(JSON.stringify(RECEIPT), { status: 200 });
  };
}

async function signedTx(r: SigningRequest): Promise<`0x${string}`> {
  if (r.kind !== "evm-call") throw new Error(r.kind);
  const t = X.MV11.transaction;
  return payer.signTransaction({
    type: "eip1559",
    chainId: t.chainId,
    nonce: t.nonce,
    maxPriorityFeePerGas: BigInt(t.maxPriorityFeePerGas),
    maxFeePerGas: BigInt(t.maxFeePerGas),
    gas: BigInt(t.gas),
    to: r.call.to,
    data: r.call.data,
  });
}

async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

const rows: [string, unknown, (r: SigningRequest) => Promise<`0x${string}`>, (raw: `0x${string}`) => object][] = [
  ["mpp/charge/evm/transaction", evmTransaction, signedTx, (raw) => ({ type: "transaction", signature: raw })],
  ["mpp/charge/evm/hash", evmHash, async () => MV12.hash, () => ({ type: "hash", hash: MV12.hash })],
];

describe("an EVM transfer the signer completed after the agreement's 200 is returned, not dropped", () => {
  it.each(rows)("%s", (_id, binding, answer, payload) =>
    at(X.fixed.now, async () => {
      const doc = (binding as { advertise(d: unknown, h: string, l: string, o: unknown, a: string): unknown }).advertise(
        [challenge],
        H,
        LINK,
        challenge,
        AGREEMENT_URL,
      );
      const answers: `0x${string}`[] = [];
      const kinds: string[] = [];
      const signer = {
        account: ACCOUNT,
        async sign(r: SigningRequest) {
          kinds.push(r.kind);
          if (r.kind === "eip712") return payer.signTypedData(r.typedData as unknown as TypedDataDefinition);
          const a = await answer(r);
          answers.push(a);
          return a;
        },
      };
      const out = await transactApproved(doc, binding as Binding, signer, seller());
      expect(kinds).toEqual(["eip712", "evm-call"]);
      if (answers[0] !== undefined && _id.endsWith("transaction")) {
        expect(`0x${createHash("sha256").update(Buffer.from(answers[0].slice(2), "hex")).digest("hex")}`).toBe(
          X.MV11.expectRawSha256,
        );
      }
      expect(out).not.toHaveProperty("decline");
      expect(out).toMatchObject({ agreement: RECEIPT, h: H });
      expect((out as { signed: { payload: unknown } }).signed.payload).toEqual(payload(answers[0]!));
    }),
  );
});
