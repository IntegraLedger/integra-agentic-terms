// The signing request as built, and the gate's EVM account form.
import { describe, expect, it } from "vitest";
import { hash } from "@integraledger/lcp";
import { exactEip3009, type PaymentRequired } from "@integraledger/lcp/x402";
import { confirm, type Binding, type Fetch } from "../src/index.js";

// The x402 EVM vectors' option O and payer.
const O = {
  scheme: "exact", network: "eip155:84532", amount: "10000", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" },
};
const PAYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ATR = new TextEncoder().encode('{"atrVersion":"1","id":"x","x402":{},"terms":"t"}');

async function offer(): Promise<{ doc: PaymentRequired; fetch: Fetch; fetches: { n: number } }> {
  const h = await hash(ATR);
  const doc = exactEip3009.advertise(
    { x402Version: 2, resource: { url: "https://api.seller.example/v1/quote" }, accepts: [O] },
    h, `https://atr.seller.example/${h}`, O,
  ) as PaymentRequired;
  const fetches = { n: 0 };
  const fetch: Fetch = async () => { fetches.n++; return new Response(ATR, { status: 200 }); };
  return { doc, fetch, fetches };
}

describe("the request and the account form", () => {
  // Each signing request is the `request` of the pairing's `build` result, signed exactly as given; the EIP-3009 domain
  // is `{name: extra.name, version: extra.version, chainId: <the network's reference>, verifyingContract: asset}`.
  it("the signer is handed the build's typed data exactly as built (verifyingContract = asset)", async () => {
    const { doc, fetch } = await offer();
    const c = await confirm(doc, exactEip3009 as unknown as Binding, `eip155:84532:${PAYER}`, fetch);
    if ("decline" in c) throw new Error(c.decline.code);
    const typedData = (c.request as { typedData: { domain: unknown } }).typedData;
    expect(typedData.domain).toEqual({
      name: "USDC", version: "2", chainId: 84532, verifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    });
  });

  // The EVM `account` must match `^eip155:([0-9]+):(0x[0-9a-fA-F]{40})$`; no match returns `no-payable-option` before
  // any fetch.
  it("an account that does not match the gate's pattern is declined no-payable-option before any fetch", async () => {
    const { doc, fetch, fetches } = await offer();
    const account = `eip155:84532:0x%66${PAYER.slice(3)}`;
    const c = await confirm(doc, exactEip3009 as unknown as Binding, account, fetch);
    expect("decline" in c ? c.decline.code : "confirmed").toBe("no-payable-option");
    expect(fetches.n).toBe(0);
  });
});
