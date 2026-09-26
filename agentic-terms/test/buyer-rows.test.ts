// Every vector file's `buyer` group, run through the gate. B2, the plant: `transact` with a counting signer over the
// row's document, account, inputs and clock, the link serving the planted ATR, declines hash-mismatch and never calls
// the signer; `confirm` declines the same and returns no request. B6: `check` over the file's signed payment gives H
// for the ATR and declines signed-not-bound for the planted ATR. Every expected value, and every input, is the row's.
import { readdirSync, readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { check, confirm, transact, type Binding, type Fetch, type Inputs } from "../src/index.js";
import { counting } from "./support.js";

interface Row {
  name: string;
  pairing: string;
  input: {
    doc?: unknown;
    servesHex?: string;
    account?: string;
    inputs?: Inputs;
    now?: number;
    presented?: unknown;
    check?: { bytesHex: string }[];
  };
  expect: unknown;
}

const dir = new URL("../node_modules/@integraledger/lcp/vectors/", import.meta.url);
const rows: { file: string; row: Row }[] = readdirSync(dir)
  .filter((n) => n.endsWith(".json"))
  .sort()
  .flatMap((file) => {
    const data = JSON.parse(readFileSync(new URL(file, dir), "utf8")) as { buyer?: { rows: Row[] } };
    return (data.buyer?.rows ?? []).map((row) => ({ file, row }));
  });
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));
const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};

/** A fetch that serves `bytes` for every URL and counts its calls. */
function serving(bytes: Uint8Array): Fetch & { calls: number } {
  const f = (async () => {
    f.calls++;
    return new Response(new Uint8Array(bytes), { status: 200 });
  }) as unknown as Fetch & { calls: number };
  f.calls = 0;
  return f;
}

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

describe("every vector file's buyer rows, through the gate", () => {
  it("the files hold a B2 for every pairing the protocol package serves", () => {
    const b2 = new Set(rows.filter(({ row }) => row.name === "B2").map(({ row }) => row.pairing));
    expect([...b2].sort()).toEqual(BINDINGS.map((b) => b.id as string).sort());
  });

  for (const { file, row } of rows.filter(({ row }) => row.name === "B2")) {
    it(`${file} B2 ${row.pairing}: hash-mismatch, and the signer is never called`, async () => {
      if (row.input.now !== undefined) {
        const now = row.input.now;
        Date.now = () => now * 1000;
      }
      const binding = bindingOf(row.pairing);
      const inputs = row.input.inputs ?? {};
      const signer = counting(row.input.account!, async () => {
        throw new Error("the signer is never called on a plant");
      });
      const served = fromHex(row.input.servesHex!);
      const out = await transact(structuredClone(row.input.doc), binding, signer, serving(served), { inputs });
      const expected = row.expect as { decline: string; signCalls: number };
      expect("decline" in out ? out.decline.code : "signed").toBe(expected.decline);
      expect(signer.requests.length).toBe(expected.signCalls);
      const fetch = serving(served);
      const confirmed = await confirm(structuredClone(row.input.doc), binding, row.input.account!, fetch, inputs);
      expect("decline" in confirmed ? confirmed.decline.code : "confirmed").toBe(expected.decline);
      expect(confirmed).not.toHaveProperty("request");
      expect(fetch.calls).toBe(1);
    });
  }

  for (const { file, row } of rows.filter(({ row }) => row.name === "B6")) {
    it(`${file} B6 ${row.pairing}: check gives H for the ATR, and signed-not-bound for the planted ATR`, async () => {
      const binding = bindingOf(row.pairing);
      const got = [];
      for (const c of row.input.check!) {
        const out = await check(fromHex(c.bytesHex), structuredClone(row.input.presented), binding);
        got.push("decline" in out ? { decline: out.decline.code } : out);
      }
      expect(got).toEqual(row.expect);
    });
  }
});
