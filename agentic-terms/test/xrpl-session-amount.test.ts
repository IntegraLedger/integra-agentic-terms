// An mpp/session/xrpl challenge's `amount` is the first claim's cumulative total in drops: a u64 written in decimal,
// with no sign, point or leading zero (the XRP Ledger's Currency Formats: an XRP amount is a string of whole drops;
// the claim signs it as a big-endian u64). @integraledger/lcp's rail check refuses any other `amount` with
// `mpp/request-malformed`, so no challenge offers the pairing and the gate declines before anything is signed. Each
// document is mpp-session-hedera-solana-xrpl.json's B2 document for this pairing with only `request.amount` replaced,
// the request re-encoded as compact JSON in unpadded base64url (RFC 4648 section 5).
import { describe, expect, it } from "vitest";
import { pairingsOf, sessionXrpl, type MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, transact, type Binding, type Declined, type Inputs } from "../src/index.js";
import { ABC, counting, serving, vectors } from "./support.js";

type Row = { name: string; pairing: string; input: { doc: MppChallenge[]; account: string; inputs: Inputs } };
const B2 = vectors<{ buyer: { rows: Row[] } }>("mpp-session-hedera-solana-xrpl.json").buyer.rows.find(
  (r) => r.name === "B2" && r.pairing === "mpp/session/xrpl",
)!.input;
const binding = sessionXrpl as unknown as Binding;

/** B2's document with `request.amount` replaced. */
function withAmount(amount: unknown): MppChallenge[] {
  const [c] = B2.doc;
  const request = JSON.parse(Buffer.from(c!.request, "base64url").toString("utf8")) as Record<string, unknown>;
  return [{ ...c!, request: Buffer.from(JSON.stringify({ ...request, amount }), "utf8").toString("base64url") }];
}
/** The challenge as issued: without the `opaque` that carries the legal context. */
function issued(doc: MppChallenge[]): MppChallenge {
  const { opaque: _placed, ...c } = doc[0]!;
  return c as MppChallenge;
}

const REFUSED: [string, unknown][] = [
  ["the JSON number 1000", 1000],
  ["the JSON number 0", 0],
  ["an empty array", []],
  ["a nested array", [[]]],
  ["true", true],
  ["a decimal fraction", "1.5"],
  ["a negative number", "-1"],
  ["a leading zero", "0100"],
  ["2^64, one above the largest u64", "18446744073709551616"],
];
const ACCEPTED: [string, string][] = [
  ["B2's own 100", "100"],
  ["2^64 - 1, the largest u64", "18446744073709551615"],
];

describe("mpp/session/xrpl: the challenge's amount is a u64 of drops", () => {
  for (const [name, amount] of REFUSED) {
    it(`${name}: the rail check refuses mpp/request-malformed; the gate declines and the signer is never called`, async () => {
      const doc = withAmount(amount);
      expect(pairingsOf(issued(doc))).toMatchObject({ refused: true, code: "mpp/request-malformed" });
      const signer = counting(B2.account, async () => {
        throw new Error("the signer is never called");
      });
      const out = await transact(doc, binding, signer, serving(ABC), { inputs: B2.inputs });
      expect((out as Declined).decline).toEqual({ code: "no-payable-option", detail: "mpp/no-payable-option" });
      expect(signer.requests.length).toBe(0);
      const confirmed = await confirm(doc, binding, B2.account, serving(ABC), B2.inputs);
      expect((confirmed as Declined).decline).toEqual({ code: "no-payable-option", detail: "mpp/no-payable-option" });
    });
  }
  for (const [name, amount] of ACCEPTED) {
    it(`${name}: offered, and the opening reaches the signer as xrpl-session-open`, async () => {
      const doc = withAmount(amount);
      expect(pairingsOf(issued(doc))).toEqual(["mpp/session/xrpl"]);
      const out = await confirm(doc, binding, B2.account, serving(ABC), B2.inputs);
      if ("decline" in out) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
      expect(out.request?.kind).toBe("xrpl-session-open");
    });
  }
});
