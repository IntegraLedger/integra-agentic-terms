// buyer.json's row named with a pairing (BX1), through the gate. Each case gives its own inputs and document and its
// own expect: a decline with its detail and no signer call, or one signer call with the
// request's kind. A BX1 case's `refusal` is what the protocol package's checks of the placed challenge return (read
// here through `network`), which leaves the gate no challenge it can pay. The link serves the row's ATR, whose SHA-256
// is each document's H. Every expected value, and every input, is the row's. A case that signs a request the gate has
// no summary of yet (SUMMARY_PENDING) is declined summary-missing with no signer call.
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { network, type MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, transact, type Binding, type Inputs } from "../src/index.js";
import { code, counting, fromHex, serving, summaryPending, vectors } from "./support.js";

import { CONFIRMING, GATE } from "./support.js";
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

const rows = vectors<{ rows: Row[] }>("buyer.json").rows.filter((r) => r.name === "BX1");
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
  it("the file holds BX1", () => {
    expect(rows.map((r) => r.name)).toEqual(["BX1"]);
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
        const out = await transact(structuredClone(doc), binding, signer, serving(served), { ...GATE, inputs });
        if (c.expect.signCalls > 0 && summaryPending(row.input.pairing)) {
          // The gate shows no request it has no summary of: until there is one, the case is declined unsigned.
          expect([code(out), signer.requests.length]).toEqual(["summary-missing", 0]);
          return;
        }
        expect(signer.requests.length).toBe(c.expect.signCalls);
        const confirmed = await confirm(structuredClone(doc), binding, row.input.account, serving(served), { ...CONFIRMING, inputs: inputs });
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
