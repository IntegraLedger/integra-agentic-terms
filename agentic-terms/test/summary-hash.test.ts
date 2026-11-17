// The approval summary of the NEAR, Tron and TON requests, which hand the signer only a hash (profile buyer-gate.md,
// rule 13), over summary-hash.json, which the Python tests run too. Each row's request is built by the pairing's buyer
// piece from the protocol package's buyer row B2 of the row's file, its document and account, with the row's inputs and
// time, over the ATR abc; the request carries the hash the file's independent tools computed, and its summary is the
// row's expect with the ATR's bytes. Every expected value is read from the vectors file's rows the row names.
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { summaryOf } from "../src/summary.js";
import { networkOfAccount } from "../src/checks.js";
import type { Binding, Inputs } from "../src/index.js";
import { ABC, isDeclined, pieceConfirm, toHex, vectors } from "./support.js";

interface Row {
  pairing: string;
  file: string;
  from: string;
  inputs: unknown;
  now: unknown;
  requestHash: unknown;
  expect: unknown;
}
interface BuyerRow {
  name: string;
  pairing: string;
  input: { doc: unknown; account: string };
}

const ROWS: Row[] = JSON.parse(readFileSync(new URL("./summary-hash.json", import.meta.url), "utf8")).rows;

/** `v` with each `{"$ref": pointer}` replaced by the value at that JSON Pointer (RFC 6901) in `file`. */
function resolved(v: unknown, file: unknown): unknown {
  if (Array.isArray(v)) return v.map((x) => resolved(x, file));
  if (typeof v !== "object" || v === null) return v;
  const ref = (v as { $ref?: unknown }).$ref;
  if (typeof ref === "string") {
    let at: unknown = file;
    for (const k of ref.split("/").slice(1)) at = (at as Record<string, unknown>)[k.replace(/~1/g, "/").replace(/~0/g, "~")];
    if (at === undefined) throw new Error(`no value at ${ref}`);
    return at;
  }
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolved(x, file)]));
}

const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};

/** The hash a request hands the signer: `hash`, or Tron's `txid`. */
const handed = (request: unknown): Uint8Array => {
  const r = request as { hash?: Uint8Array; txid?: Uint8Array };
  return (r.hash ?? r.txid)!;
};

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

describe("summary-hash.json: the summary of the request each pairing's piece builds from its file's inputs", () => {
  for (const row of ROWS) {
    it(`${row.pairing} (${row.file} B2, expect from ${row.from})`, async () => {
      const file = vectors<{ buyer: { rows: BuyerRow[] } }>(row.file);
      const b2 = file.buyer.rows.find((r) => r.name === "B2" && r.pairing === row.pairing);
      if (b2 === undefined) throw new Error(`${row.file} has no B2 row for ${row.pairing}`);
      const now = resolved(row.now, file) as number;
      Date.now = () => now * 1000;
      const inputs = resolved(row.inputs, file) as Inputs;
      const built = await pieceConfirm(structuredClone(b2.input.doc), bindingOf(row.pairing), b2.input.account, inputs);
      if (isDeclined(built)) throw new Error(`${built.decline.code}: ${built.decline.detail}`);
      if (built.request === null) throw new Error("nothing to sign");
      expect(toHex(handed(built.request)).slice(2)).toBe(String(resolved(row.requestHash, file)).replace(/^0x/, ""));
      const summary = await summaryOf(row.pairing, built.request, ABC, networkOfAccount(b2.input.account));
      expect(summary).toEqual({ ...(resolved(row.expect, file) as object), atr: ABC });
    });
  }
});
