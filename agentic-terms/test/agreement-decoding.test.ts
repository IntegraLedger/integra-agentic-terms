// The agreement exchange reads the seller's answers as the protocol package reads JSON text. PAYMENT-REQUIRED is padded
// standard base64 (RFC 4648 section 4; x402's HTTP transport carries it base64-encoded, and RFC 4648 section 3.2 keeps
// the pad characters), whose final character's unused bits are zero (RFC 4648 section 3.5). Every body and header
// decodes as UTF-8 whose leading byte order mark is kept as a character, and no JSON text begins with one (RFC 8259
// section 8.1), as the protocol package's readers and the Python gate read it. So buyer.json's BA13 header
// (`requiredUnpadded`), a header whose final character carries a non-zero unused bit, and a header whose JSON follows a
// byte order mark leave the 402 unread: agreement-failed after one fetch, with nothing signed. A paid 200 whose receipt
// follows a byte order mark is agreement-failed, with the sent agreement payment kept as `moved`. buyer.json's BA17 and
// BA18 rows give the byte order mark cases and a padded header with a space inside, built here as those rows build
// `receiptBomLed`, `requiredBomLed` and `requiredInnerSpace` from `required` and `receipt`, and each row's expected
// decline. The same cases run through the Python gate in test_agreement_decoding.py.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { hashTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Eip3009TypedData } from "@integraledger/lcp/x402";
import { agree, type Declined, type Fetch, type Signer, type SigningRequest } from "../src/index.js";

const B = JSON.parse(readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/buyer.json", import.meta.url), "utf8"));
const AG = B.fixed.agreement;
const A = Uint8Array.from(Buffer.from(B.fixed.A.replace(/^0x/, ""), "hex"));
const BOM = Uint8Array.of(0xef, 0xbb, 0xbf);

const canonical = Buffer.from(JSON.stringify(AG.required), "utf8").toString("base64");
/** The canonical header with its final character's lowest unused bit set: the same bytes, written another way. */
function nonCanonical(b64: string): string {
  const pads = b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0;
  if (pads === 0) throw new Error("the header has no unused bits");
  const at = b64.length - pads - 1;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  return b64.slice(0, at) + alphabet[alphabet.indexOf(b64[at]!) | 1]! + b64.slice(at + 1);
}

/** The seller: 402 with `header` until a payment is sent, then 200 with `paid`. It counts its answers. */
function seller(header: string, paid: Uint8Array): Fetch & { fetches: number } {
  const f = (async (_url: string, init: Parameters<Fetch>[1]) => {
    f.fetches++;
    if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }
    return new Response(new Uint8Array(paid), { status: 200 });
  }) as Fetch & { fetches: number };
  f.fetches = 0;
  return f;
}

function signer(): Signer & { calls: number } {
  const key = privateKeyToAccount(B.fixed.payerKey);
  const s = {
    account: B.fixed.account as string,
    calls: 0,
    async sign(r: SigningRequest) {
      s.calls++;
      return key.signTypedData((r as { typedData: Eip3009TypedData }).typedData as unknown as Parameters<typeof hashTypedData>[0]);
    },
  };
  return s;
}

async function exchange(header: string, paid: Uint8Array) {
  const f = seller(header, paid);
  const s = signer();
  const first = await agree(A, AG.url, s, f);
  const out = "approve" in first ? await agree(A, AG.url, s, f, { approved: first.approve }) : first;
  return { out, fetches: f.fetches, calls: s.calls };
}

const receipt = new TextEncoder().encode(JSON.stringify(AG.receipt));

describe("the agreement exchange's decoding", () => {
  it("the canonical header and a receipt with no byte order mark: the receipt", async () => {
    expect(nonCanonical(canonical)).not.toBe(canonical);
    expect(Buffer.from(nonCanonical(canonical), "base64")).toEqual(Buffer.from(canonical, "base64"));
    const { out, calls } = await exchange(canonical, receipt);
    expect(out).toEqual({ receipt: AG.receipt });
    expect(calls).toBe(1);
  });

  it.each([
    ["BA13's unpadded header", AG.requiredUnpadded as string],
    ["a header whose final character carries a non-zero unused bit", nonCanonical(canonical)],
    ["BA18: a header whose JSON follows a byte order mark", Buffer.concat([BOM, Buffer.from(JSON.stringify(AG.required), "utf8")]).toString("base64")],
    ["BA18: the padded header with a space after its fourth character", `${canonical.slice(0, 4)} ${canonical.slice(4)}`],
  ])("%s: agreement-failed after one fetch, nothing signed", async (_, header) => {
    const { out, fetches, calls } = await exchange(header, receipt);
    expect((out as Declined).decline?.code).toBe("agreement-failed");
    expect(out).not.toHaveProperty("moved");
    expect([fetches, calls]).toEqual([1, 0]);
  });

  it("BA17: a paid 200 whose receipt follows a byte order mark: agreement-failed, the sent payment kept as moved", async () => {
    const { out, calls } = await exchange(canonical, new Uint8Array([...BOM, ...receipt]));
    expect((out as Declined).decline?.code).toBe("agreement-failed");
    expect(out).toHaveProperty("moved");
    expect(calls).toBe(1);
  });
});
