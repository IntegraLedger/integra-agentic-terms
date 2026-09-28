// buyer.json's rows named with a pairing (BS1, BS2, BX1), through the gate. Each case gives its own inputs (BX1: its
// own document) and its own expect: a decline with its detail and no signer call, or one signer call with the
// request's kind. A BX1 case's `refusal` is what the protocol package's checks of the placed challenge return (read
// here through `network`), which leaves the gate no challenge it can pay. The link serves `abc`, whose SHA-256
// (FIPS 180-2 B.1) is each document's H. Every expected value, and every input, is the row's.
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { network, type MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, transact, type Binding, type Inputs } from "../src/index.js";
import { counting, fromHex, serving, vectors } from "./support.js";

interface Case {
  case: string;
  inputs?: Inputs;
  doc?: unknown;
  expect: { decline?: string; detail?: string; refusal?: string; signCalls: number; signRequestKind?: string };
}
interface Row {
  name: string;
  input: { pairing: string; doc?: unknown; servesHex: string; account: string; inputs?: Inputs; now?: number; cases: Case[] };
}

const rows = vectors<{ rows: Row[] }>("buyer.json").rows.filter((r) => ["BS1", "BS2", "BX1"].includes(r.name));
const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

describe("buyer.json's build rows, through the gate", () => {
  it("the file holds BS1, BS2 and BX1", () => {
    expect(rows.map((r) => r.name)).toEqual(["BS1", "BS2", "BX1"]);
  });

  for (const row of rows) {
    for (const c of row.input.cases) {
      it(`${row.name} ${row.input.pairing}: ${c.case}`, async () => {
        if (row.input.now !== undefined) {
          const now = row.input.now;
          Date.now = () => now * 1000;
        }
        const binding = bindingOf(row.input.pairing);
        const doc = c.doc ?? row.input.doc;
        const inputs = c.inputs ?? row.input.inputs ?? {};
        const served = fromHex(row.input.servesHex);
        const signer = counting(row.input.account, async () => {
          throw new Error("the row compares only what the signer is handed");
        });
        const out = await transact(structuredClone(doc), binding, signer, serving(served), { inputs });
        expect(signer.requests.length).toBe(c.expect.signCalls);
        const confirmed = await confirm(structuredClone(doc), binding, row.input.account, serving(served), inputs);
        if (c.expect.decline !== undefined) {
          expect("decline" in out && [out.decline.code, out.decline.detail]).toEqual([c.expect.decline, c.expect.detail]);
          expect("decline" in confirmed && [confirmed.decline.code, confirmed.decline.detail]).toEqual([
            c.expect.decline,
            c.expect.detail,
          ]);
        } else {
          expect(signer.requests.map((r) => r.kind)).toEqual([c.expect.signRequestKind]);
          expect("decline" in confirmed ? confirmed.decline : confirmed.request?.kind).toBe(c.expect.signRequestKind);
        }
        if (c.expect.refusal !== undefined) {
          const challenge = (doc as MppChallenge[])[0]!;
          expect(network(challenge)).toEqual({ refused: true, code: c.expect.refusal });
        }
      });
    }
  }
});
