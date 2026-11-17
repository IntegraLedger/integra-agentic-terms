// The approval summary of the EVM requests (profile buyer-gate.md, rule 13), over summary-evm.json, which the Python
// tests run too. Each row's request is built by the pairing's buyer piece from the protocol package's buyer row B2 of
// the row's file, its document, account, inputs and time, the document's one option replaced by the file's value at the
// row's `accepts` where it names one, over the ATR abc; its summary is the row's expect with the ATR's bytes. Every
// expected value is read from the vectors file's row the row names.
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { MPP_BINDINGS } from "@integraledger/lcp/mpp";
import { summaryOf } from "../src/summary.js";
import type { Binding, Inputs } from "../src/index.js";
import { ABC, isDeclined, pieceConfirm, vectors } from "./support.js";

interface Row {
  pairing: string;
  file: string;
  from: string;
  accepts?: string;
  expect: Record<string, unknown>;
}
interface BuyerRow {
  name: string;
  pairing: string;
  input: { doc: unknown; account: string; inputs?: Inputs; now?: number };
}

const ROWS: Row[] = JSON.parse(readFileSync(new URL("./summary-evm.json", import.meta.url), "utf8")).rows;

const bindingOf = (id: string): Binding => {
  const b = [...BINDINGS, ...MPP_BINDINGS].find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

describe("summary-evm.json: the summary of the request each pairing's piece builds from its B2 row", () => {
  for (const row of ROWS) {
    it(`${row.pairing} (${row.file} B2, expect from ${row.from})`, async () => {
      const file = vectors<{ buyer: { rows: BuyerRow[] } }>(row.file);
      const b2 = file.buyer.rows.find((r) => r.name === "B2" && r.pairing === row.pairing);
      if (b2 === undefined) throw new Error(`${row.file} has no B2 row for ${row.pairing}`);
      const now = b2.input.now;
      if (now !== undefined) Date.now = () => now * 1000;
      const doc = structuredClone(b2.input.doc) as { accepts: unknown[] };
      if (row.accepts !== undefined) {
        const option = row.accepts.split(".").reduce<unknown>((v, k) => (v as Record<string, unknown>)[k], file);
        if (option === undefined) throw new Error(`${row.file} has no ${row.accepts}`);
        doc.accepts = [structuredClone(option)];
      }
      const built = await pieceConfirm(doc, bindingOf(row.pairing), b2.input.account, b2.input.inputs ?? {});
      if (isDeclined(built)) throw new Error(`${built.decline.code}: ${built.decline.detail}`);
      if (built.request === null) throw new Error("nothing to sign");
      expect(await summaryOf(row.pairing, built.request, ABC)).toEqual({ ...row.expect, atr: ABC });
    });
  }
});
