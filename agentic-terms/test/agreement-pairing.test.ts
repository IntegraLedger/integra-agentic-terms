// The agreement is paid through any pairing whose `pattern.publicProof` is true, the one whose `advertise` placed the
// agreement option, and the build is that pairing's. So an agreement challenge placed by `x402/exact/eip155/permit2`
// (publicProof true) is paid with that pairing's build. The option is the permit2 vector file's; the rest is
// buyer.json's.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedDataDefinition } from "viem";
import { exactEip3009, exactPermit2, type PaymentRequired, type PaymentRequirements } from "@integraledger/lcp/x402";
import { transact, type Binding, type Fetch, type SigningRequest } from "../src/index.js";
import { transactApproved, vectors } from "./support.js";

const B = vectors<{
  fixed: { A: string; D: PaymentRequired; account: string; payerKey: `0x${string}`; now: number; agreement: { url: string } };
  rows: { name: string; expect: { h: string } }[];
}>("buyer.json");
const PERMIT2 = vectors<{ fixed: { option: PaymentRequirements } }>("x402-exact-eip155-permit2.json");

const A = Uint8Array.from(Buffer.from(B.fixed.A, "hex"));
const H = B.rows.find((r) => r.name === "B1")!.expect.h;
const LINK = `https://atr.seller.example/${H}`;
const URL_ = B.fixed.agreement.url;
const RECEIPT = { atrHash: H, agreed: true, network: "eip155:84532", transaction: `0x${"cd".repeat(32)}` };
const key = privateKeyToAccount(B.fixed.payerKey);

/** The x402/EVM binding as a pairing with no public proof, whose read also gives the agreement URL. */
function withAgreement(): Binding {
  const real = exactEip3009.read(B.fixed.D);
  if ("refused" in real) throw new Error(real.code);
  return { ...exactEip3009, pattern: { ...exactEip3009.pattern, publicProof: false }, read: () => ({ ...real, agreement: URL_ }) };
}

function seller(): Fetch {
  const option = PERMIT2.fixed.option;
  const required = exactPermit2.advertise({ x402Version: 2, resource: { url: URL_ }, accepts: [option] }, H as never, LINK, option);
  const header = Buffer.from(JSON.stringify(required), "utf8").toString("base64");
  return async (url, init) => {
    if (url === LINK) return new Response(new Uint8Array(A), { status: 200 });
    if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }
    return new Response(JSON.stringify(RECEIPT), { status: 200 });
  };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(B.fixed.now * 1000);
});
afterEach(() => vi.useRealTimers());

describe("an agreement placed by another public-proof x402 pairing is paid by that pairing", () => {
  it("x402/exact/eip155/permit2 as the agreement pairing", async () => {
    expect(exactPermit2.pattern.publicProof).toBe(true);
    const handed: string[] = [];
    const signer = {
      account: B.fixed.account,
      async sign(r: SigningRequest) {
        if (r.kind !== "eip712") throw new Error(r.kind);
        handed.push((r.typedData as { primaryType: string }).primaryType);
        return key.signTypedData(r.typedData as unknown as TypedDataDefinition);
      },
    };
    const out = await transactApproved(B.fixed.D, withAgreement(), signer, seller());
    expect(out).not.toHaveProperty("decline");
    expect(out).toMatchObject({ agreement: RECEIPT, h: H });
    expect(handed.length).toBe(2);
    expect(handed[1]).toBe("TransferWithAuthorization");
  });
});
