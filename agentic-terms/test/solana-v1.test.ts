// The transactionV1 sections of @integraledger/lcp's x402-exact-solana.json, x402-upto-solana.json and
// x402-batch-settlement.json: version-1 transactions (SIMD-0385) as the stock @x402/svm 2.31.0 client writes them.
// The gate's check reads each as H, and each changed member is answered by the pairing's bound as the file's row says:
// the file's code, or H for a row within every rule of the version-1 decoder.
// Every expected value is the file's.
import { describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { check, type Binding, type Presented } from "../src/index.js";
import { vectors } from "./support.js";

interface Payload {
  transaction?: string;
  openTransaction?: string;
  deposit?: { amount: string; transaction: string };
}
interface V1 {
  presented: { x402Version: 2; accepted: { network: string }; payload: Payload };
  expectBound: string;
  changed: { case: string; wireBase64: string; expect: string | { refused: true; code: string } }[];
}

const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};
const ABC = new TextEncoder().encode("abc");

// x402-exact-solana.json's changed rows hold each rule of the version-1 decoder as well.
const cases: { file: string; pairing: string; changedRows: number; withWire: (p: Payload, w: string) => Payload }[] = [
  { file: "x402-exact-solana.json", pairing: "x402/exact/solana", changedRows: 26, withWire: (p, transaction) => ({ ...p, transaction }) },
  { file: "x402-upto-solana.json", pairing: "x402/upto/solana", changedRows: 3, withWire: (p, openTransaction) => ({ ...p, openTransaction }) },
  {
    file: "x402-batch-settlement.json",
    pairing: "x402/batch-settlement/solana",
    changedRows: 3,
    withWire: (p, transaction) => ({ ...p, deposit: { ...p.deposit!, transaction } }),
  },
];

describe.each(cases)("$file transactionV1", ({ file, pairing, changedRows, withWire }) => {
  const v = vectors<{ transactionV1: V1 }>(file).transactionV1;
  const binding = bindingOf(pairing);

  it("check gives H for the stock client's version-1 payment", async () => {
    const out = await check(ABC, structuredClone(v.presented) as unknown as Presented, binding);
    expect(out).toEqual({ h: v.expectBound });
  });

  it("each changed member is answered with its row's code or H", async () => {
    expect(v.changed.length).toBe(changedRows);
    for (const row of v.changed) {
      const presented = { ...v.presented, payload: withWire(structuredClone(v.presented.payload), row.wireBase64) };
      expect(await (binding as unknown as { bound(p: unknown): Promise<unknown> }).bound(presented), row.case).toEqual(row.expect);
    }
  });
});
