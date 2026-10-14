// mpp/charge/nearintents over MCP. Nothing the buyer deposits carries the ATR hash, and the buyer's own wallet makes the
// deposit (draft-nearintents-charge-01, section 5.2), so `atr_confirm` hands the wallet no signing request: without the
// agreement's receipt for H it returns no `request` at all, and with that receipt it returns `request: null`, the
// confirm-only answer. `chosen` carries the challenge the deposit pays exactly as the seller issued it, so a
// `methodDetails.depositMemo` ("Deposit memo required by some origin chains (e.g., Stellar). Absent or null when not
// required.", draft-nearintents-charge-01, Method Details) reaches the wallet as the seller wrote it. The ATR, its hash,
// the agreement URL and its receipts are buyer.json's; the request is MPP's own example in mpp-charge-nearintents.json,
// placed by the protocol package's `advertise`.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BINDINGS } from "../src/index.js";
import { at, connect } from "./stdio.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const B = vectors("buyer.json");
const N = vectors("mpp-charge-nearintents.json");
const A = Uint8Array.from(Buffer.from(B.fixed.A, "hex"));
const H: string = B.rows.find((r: { name: string }) => r.name === "B1").expect.h;
const LINK = `https://atr.seller.example/${H}`;
const AG = B.fixed.agreement;
const MD = N.fixed.request.methodDetails;
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const pairing = "mpp/charge/nearintents";

type Advertises = { advertise(d: object[], h: string, l: string, o: object, agreementUrl: string): object[] };
const binding = BINDINGS.find((b) => b.id === pairing) as unknown as Advertises;

/** The seller's challenges: MPP's example request with a depositMemo, placed for H, LINK and the agreement URL. */
function document(): object[] {
  const request = { ...N.fixed.request, methodDetails: { ...MD, depositMemo: "4120" } };
  const issued = { ...N.challenge, request: Buffer.from(JSON.stringify(request), "utf8").toString("base64url") };
  return binding.advertise([issued], H, LINK, issued, AG.url);
}

describe("atr_confirm on mpp/charge/nearintents", () => {
  it("returns request null only with the agreement's receipt for H, and chosen carries the challenge as issued", async () => {
    const doc = document();
    const c = connect({ fetch: async () => new Response(new Uint8Array(A), { status: 200 }) });
    const call = (receipt?: unknown) =>
      c.request("tools/call", {
        name: "atr_confirm",
        arguments: { pairing, document: doc, account: `${MD.originNetwork}:${MD.refundTo}`, ...(receipt ? { receipt } : {}) },
        _meta: M,
      });
    const unpaid = await call();
    const paid = await call(AG.receipt);
    const other = await call(AG.receiptOtherHash);
    await c.close();

    expect(at(unpaid, "result.isError")).toBeUndefined();
    expect(at(unpaid, "result.structuredContent")).not.toHaveProperty("request");
    expect(at(unpaid, "result.structuredContent.chosen.agreement")).toBe(AG.url);
    const challenge = at(unpaid, "result.structuredContent.chosen.choice.challenge") as { request: string };
    expect(challenge).toEqual((doc as object[])[0]);
    expect(JSON.parse(Buffer.from(challenge.request, "base64url").toString("utf8")).methodDetails.depositMemo).toBe("4120");

    expect(at(paid, "result.isError")).toBeUndefined();
    expect(at(paid, "result.structuredContent.request")).toBeNull();
    expect(at(other, "result.structuredContent.decline.code")).toBe("agreement-failed");
    expect(at(other, "result.structuredContent")).not.toHaveProperty("request");
  });
});
