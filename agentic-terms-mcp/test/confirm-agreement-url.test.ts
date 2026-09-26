// The buyer pays the agreement URL and waits for its 200 receipt before it starts the full payment. The gate's `confirm`
// returns that URL as `agreement` for a pairing whose `publicProof` is false, and each tool maps the gate's result to
// `structuredContent`. The bin serves no `atr_transact`, so `atr_confirm` then `atr_finish` is its only path to a
// payment; the agreement URL must reach the agent there, or the agent signs the full payment with no agreement. The
// pairing is `x402/exact/eip155/erc7710` (`publicProof` false); its option and the agreement URL are the lcp vector
// files'.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BINDINGS } from "../src/index.js";
import { at, connect } from "./stdio.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const B = vectors("buyer.json");
const E = vectors("x402-exact-eip155-erc7710.json");
const A = Uint8Array.from(Buffer.from(B.fixed.A, "hex"));
const H: string = B.rows.find((r: { name: string }) => r.name === "B1").expect.h;
const LINK = `https://atr.seller.example/${H}`;
const AGREEMENT_URL: string = B.fixed.agreement.url;
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };

describe("atr_confirm carries the agreement URL of a pairing with no public proof", () => {
  it("x402/exact/eip155/erc7710 with the agreement URL placed", async () => {
    const pairing = "x402/exact/eip155/erc7710";
    const binding = BINDINGS.find((b) => b.id === pairing) as unknown as {
      pattern: { publicProof: boolean };
      advertise(d: object, h: string, l: string, o: object, agreementUrl: string): object;
    };
    expect(binding.pattern.publicProof).toBe(false);
    const document = binding.advertise({ x402Version: 2, resource: E.fixed.resource, accepts: [E.fixed.option] }, H, LINK, E.fixed.option, AGREEMENT_URL);
    const c = connect({ fetch: async () => new Response(new Uint8Array(A), { status: 200 }) });
    const m = await c.request("tools/call", { name: "atr_confirm", arguments: { pairing, document, account: B.fixed.account }, _meta: M });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.agreement")).toBe(AGREEMENT_URL);
  });
});
