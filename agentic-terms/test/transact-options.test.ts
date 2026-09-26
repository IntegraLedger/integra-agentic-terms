// `transact`'s options object holds only `inputs` and `agreementSigner`. An options object
// holding any other key, or one that is not an object, is refused before any fetch or signer call, so a buyer's inputs
// are never silently dropped. The decline is the gate's closed `no-payable-option` with the namespace's
// `input-malformed` detail, the form the gate gives a malformed input. The document, the ATR and the signer are buyer.json's.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { hashTypedData } from "viem";
import { exactEip3009, type PaymentRequired } from "@integraledger/lcp/x402";
import { transact, type Fetch, type Signer, type SigningRequest } from "../src/index.js";
import { isDeclined } from "./support.js";

const B = JSON.parse(readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/buyer.json", import.meta.url), "utf8"));
const A = Uint8Array.from(Buffer.from(B.fixed.A.replace(/^0x/, ""), "hex"));
const D: PaymentRequired = B.fixed.D;

function fixture(): { fetch: Fetch & { calls: number }; signer: Signer & { calls: number } } {
  const fetch = (async () => {
    fetch.calls++;
    return new Response(new Uint8Array(A), { status: 200 });
  }) as unknown as Fetch & { calls: number };
  fetch.calls = 0;
  const key = privateKeyToAccount(B.fixed.payerKey);
  const signer = {
    account: B.fixed.account as string,
    calls: 0,
    async sign(request: SigningRequest) {
      signer.calls++;
      const r = request as unknown as { typedData: unknown };
      return key.signTypedData(r.typedData as Parameters<typeof hashTypedData>[0]);
    },
  };
  return { fetch, signer };
}

describe("transact's options object", () => {
  it.each([
    ["a bare inputs object", { recentBlockhash: "11111111111111111111111111111111" }],
    ["inputs beside an unknown key", { inputs: {}, extra: true }],
    ["an unknown key only", { agreementSinger: {} }],
    ["an array", []],
    ["null", null],
    ["a string", "inputs"],
    ["inputs that are not an object", { inputs: "recentBlockhash" }],
    ["an agreement signer with no sign function", { agreementSigner: { account: B.fixed.account } }],
  ])("%s is refused before any fetch or signer call", async (_, options) => {
    const { fetch, signer } = fixture();
    const out = await transact(D, exactEip3009, signer, fetch, options as never);
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect([fetch.calls, signer.calls]).toEqual([0, 0]);
  });

  it.each([
    ["absent", undefined],
    ["empty", {}],
    ["inputs only", { inputs: {} }],
    ["both members, each undefined", { inputs: undefined, agreementSigner: undefined }],
  ])("%s: the payment is made", async (_, options) => {
    const { fetch, signer } = fixture();
    const out = await transact(D, exactEip3009, signer, fetch, options as never);
    expect(isDeclined(out)).toBe(false);
    expect(signer.calls).toBe(1);
  });
});
