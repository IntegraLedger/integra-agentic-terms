// x402-exact-ccd.json's D3.wireForm, through the gate: the signer's answer for `x402/exact/ccd` is the signed
// transaction in x402's wire form, `JSON.parse(Transaction.toJSONString(tx))`. The SDK's object before serialization,
// whose header holds bigints (the rows' `bigints` paths), is declined signed-not-bound with the protocol package's
// ccd/transaction-malformed, and the gate does not throw. Every expected value, and every input, is the file's.
import { describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { exactCcd } from "@integraledger/lcp/ccd";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { transact, type Binding } from "../src/index.js";
import { ABC, counting, H, LINK, serving, vectors } from "./support.js";

interface Row {
  case: string;
  base: "ccd" | "plt";
  bigints?: string[];
  asText?: boolean;
  expect: { refused: true; code: string };
}
const V = vectors<{
  fixed: { O: PaymentRequirements; OPlt: PaymentRequirements; payer: string; resource: object; now: number };
  D3: { ccd: { payment: { payload: { signedTransaction: object } } }; wireForm: { rows: Row[] } };
}>("x402-exact-ccd.json");
const f = V.fixed;

type Advertises = { advertise(doc: unknown, h: AtrHash, link: string, offer: unknown): PaymentRequired };
const doc = (exactCcd as unknown as Advertises).advertise(
  { x402Version: 2, resource: f.resource, accepts: [f.O] },
  H,
  LINK,
  f.O,
);

/** The signed transaction with each named member, a JSON number there, as a bigint. */
function withBigints(paths: readonly string[]): Record<string, unknown> {
  const tx = structuredClone(V.D3.ccd.payment.payload.signedTransaction) as Record<string, unknown>;
  for (const path of paths) {
    const keys = path.replace(/^payload\.signedTransaction\./, "").split(".");
    let at = tx;
    for (const k of keys.slice(0, -1)) at = at[k] as Record<string, unknown>;
    at[keys.at(-1)!] = BigInt(at[keys.at(-1)!] as number);
  }
  return tx;
}

describe("x402/exact/ccd: the signer's answer in x402's wire form", () => {
  const rows = V.D3.wireForm.rows.filter((r) => r.base === "ccd" && r.bigints !== undefined);

  it("the file names the SDK object's bigint members", () => {
    expect(rows.length).toBeGreaterThan(0);
  });

  for (const row of rows) {
    it(`${row.case}: declined signed-not-bound, ${row.expect.code}`, async () => {
      const real = Date.now;
      Date.now = () => f.now * 1000;
      try {
        const signer = counting(`${f.O.network}:${f.payer}`, async () => withBigints(row.bigints!) as never);
        const out = await transact(structuredClone(doc), exactCcd as unknown as Binding, signer, serving(ABC));
        expect("decline" in out && [out.decline.code, out.decline.detail]).toEqual(["signed-not-bound", row.expect.code]);
        expect(signer.requests.length).toBe(1);
      } finally {
        Date.now = real;
      }
    });
  }

  it("the wire form itself is paid", async () => {
    const real = Date.now;
    Date.now = () => f.now * 1000;
    try {
      const answer = structuredClone(V.D3.ccd.payment.payload.signedTransaction);
      const signer = counting(`${f.O.network}:${f.payer}`, async () => answer as never);
      const out = await transact(structuredClone(doc), exactCcd as unknown as Binding, signer, serving(ABC));
      expect("signed" in out && (out.signed as { payload: unknown }).payload).toEqual({ signedTransaction: answer });
    } finally {
      Date.now = real;
    }
  });
});
