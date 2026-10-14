// `transact`'s options object holds only `inputs`, `agreementSigner`, `approved` and `signal`. An options object
// holding any other key, or one that is not an object, is refused before any fetch or signer call, so a buyer's inputs
// are never silently dropped. The decline is the gate's closed `no-payable-option` with the namespace's
// `input-malformed` detail, the form the gate gives a malformed input. `confirm` and `agree` decline inputs that are not
// an object, and `agree` an approved payment not of the agreement payment's form, the same way; `transact` and `agree`
// decline a signer whose account is not a string the same way. The document, the ATR and the signer are buyer.json's.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { hashTypedData } from "viem";
import { exactEip3009, type PaymentRequired } from "@integraledger/lcp/x402";
import { agree, check, confirm, finish, transact, type Fetch, type Signer, type SigningRequest } from "../src/index.js";
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
    ["an agreement signer with no account", { agreementSigner: { sign: async (): Promise<string> => "0x" } }],
    [
      "an agreement signer whose account is a number",
      { agreementSigner: { account: 7, sign: async (): Promise<string> => "0x" } },
    ],
    ["an approved payment that is not an object", { approved: "yes" }],
    ["a signal that is not an AbortSignal", { signal: { aborted: false } }],
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
    ["every member undefined", { inputs: undefined, agreementSigner: undefined, approved: undefined, signal: undefined }],
    ["a signal that is not aborted", { signal: new AbortController().signal }],
  ])("%s: the payment is made", async (_, options) => {
    const { fetch, signer } = fixture();
    const out = await transact(D, exactEip3009, signer, fetch, options as never);
    expect(isDeclined(out)).toBe(false);
    expect(signer.calls).toBe(1);
  });
});

describe("inputs and payments the other entry points are given", () => {
  // buyer.json's B20 (confirm) and BA16 (agree): no-payable-option with x402/input-malformed, 0 fetches and 0 signer
  // calls, as transact declines them.
  it.each([
    ["a string", "x"],
    ["a number", 5],
    ["a list", []],
    ["null", null],
  ])("inputs that are %s: confirm and agree decline before any fetch or signer call", async (_, inputs) => {
    const { fetch, signer } = fixture();
    const confirmed = await confirm(D, exactEip3009, signer.account, fetch, inputs as never);
    const agreed = await agree(A, B.fixed.agreement.url, signer, fetch, { inputs: inputs as never });
    for (const out of [confirmed, agreed]) {
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    }
    expect([fetch.calls, signer.calls]).toEqual([0, 0]);
  });

  it("an approved payment whose url is not a string: agree declines before any fetch or signer call", async () => {
    const { fetch, signer } = fixture();
    const approved = { url: 5, option: B.fixed.agreement.option, required: B.fixed.agreement.required };
    const out = await agree(A, B.fixed.agreement.url, signer, fetch, { approved: approved as never });
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect([fetch.calls, signer.calls]).toEqual([0, 0]);
  });

  // A signer whose account is not a string: transact and agree decline no-payable-option with x402/input-malformed
  // before any fetch or signer call, as they decline a malformed input. The agreement URL would answer 402 with its
  // payment request.
  it.each([
    ["no account", {}],
    ["an account that is a number", { account: 7 }],
    ["an account that is null", { account: null }],
  ])("a signer with %s: transact and agree decline before any fetch or signer call", async (_, member) => {
    const header = Buffer.from(JSON.stringify(B.fixed.agreement.required)).toString("base64");
    let fetches = 0;
    const fetch = (async () => {
      fetches++;
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }) as unknown as Fetch;
    let signs = 0;
    const signer = { ...member, sign: async () => (signs++, "0x") } as unknown as Signer;
    const transacted = await transact(D, exactEip3009, signer, fetch);
    const agreed = await agree(A, B.fixed.agreement.url, signer, fetch);
    for (const out of [transacted, agreed]) {
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    }
    expect([fetches, signs]).toEqual([0, 0]);
  });

  // @integraledger/lcp's hash rejects a value that is not a Uint8Array with TypeError, and the gate passes it on.
  it("an ATR that is not bytes: finish, check and agree reject with TypeError, and nothing is fetched or signed", async () => {
    const { fetch, signer } = fixture();
    const chosen = { pairing: exactEip3009.id, choice: {}, ref: "r" };
    await expect(finish("abc" as never, chosen, null, exactEip3009)).rejects.toThrow(TypeError);
    await expect(check("abc" as never, {}, exactEip3009)).rejects.toThrow(TypeError);
    await expect(agree("abc" as never, B.fixed.agreement.url, signer, fetch)).rejects.toThrow(TypeError);
    expect([fetch.calls, signer.calls]).toEqual([0, 0]);
  });
});
