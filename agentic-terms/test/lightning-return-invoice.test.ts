// `mpp/session/lightning`: the buyer's return invoice is checked before the node is asked to pay the deposit invoice.
// Expected values: the session's return invoice goes in the build choice, and the open credential is `{action: "open",
// preimage, returnInvoice}` (draft-lightning-session-00); the decline codes are returned before the signer is called;
// MPP's Lightning session, *"returnInvoice: REQUIRED. BOLT11 invoice with no encoded amount"*, checked before the
// signer call. The passing case's return invoice is the vector
// file's `returnInvoice`, BOLT11's example with no amount; the refused ones are its S1 `returnInvoiceRows`. The pairing has
// no public proof, so the offer names the agreement URL.
import { describe, expect, it } from "vitest";
import { sessionLightning } from "@integraledger/lcp/lightning";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import { transact, type Binding } from "../src/index.js";
import { ABC, counting, H, isDeclined, LINK, offered, serving, vectors } from "./support.js";

const NOW = 1_790_000_000;
async function at<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => NOW * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

type LnMpp = { challenge: Omit<MppChallenge, "request">; request: object };
const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
function placed(binding: Binding, row: LnMpp): MppChallenge[] {
  const issued = { ...row.challenge, request: b64u(JSON.stringify(row.request)) } as MppChallenge;
  const out = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
    [issued],
    H,
    LINK,
    issued,
  );
  if (!Array.isArray(out)) throw new Error(JSON.stringify(out));
  return out as MppChallenge[];
}

describe("mpp/session/lightning: the return invoice is read before the node pays", () => {
  const C = vectors<{ fixed: { payee: string } }>("mpp-charge-lightning.json");
  const S = vectors<{
    fixed: { preimage: string; returnInvoice: string };
    S1: LnMpp & { returnInvoiceRows: { case: string; returnInvoice: string | null }[] };
  }>("mpp-session-lightning.json");
  const account = `lnbtc:000000000019d6689c085ae165831e93:${C.fixed.payee}`;
  const doc = placed(sessionLightning, S.S1);

  it("control: with a BOLT11 return invoice that encodes no amount, the node pays once and the open credential is returned", () =>
    at(async () => {
      const node = counting(account, async () => S.fixed.preimage);
      const out = await transact(doc, offered(sessionLightning), node, serving(ABC), { inputs: { returnInvoice: S.fixed.returnInvoice } });
      if (isDeclined(out)) throw new Error(out.decline.code);
      expect(node.requests.length).toBe(1);
    }));

  it.each(S.S1.returnInvoiceRows.filter((r) => typeof r.returnInvoice === "string").map((r) => [r.case, r.returnInvoice!]))(
    "%s: declined before the node is asked to pay",
    (_n, returnInvoice) =>
    at(async () => {
      const node = counting(account, async () => S.fixed.preimage);
      const out = await transact(doc, offered(sessionLightning), node, serving(ABC), { inputs: { returnInvoice } });
      expect(isDeclined(out) && out.decline.detail).toBe("ln/return-invoice-malformed");
      expect(node.requests.map((r) => r.kind)).toEqual([]);
    }));
});
