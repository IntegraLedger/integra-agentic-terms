// The gate's requests ask for the identity coding, and a 200 that names any content coding is declined with its body
// unread. Sources: RFC 9110 §8.4 (a content coding is applied to the representation's bytes, and `Content-Encoding`
// lists the codings applied, in order) and §12.5.3 ("identity" is a synonym for "no encoding"; `Accept-Encoding:
// identity` asks for the bytes with no coding applied). The ATR, its hash and the agreement exchange's inputs are
// @integraledger/lcp's vectors/buyer.json; each gzip body is written by node:zlib.
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { hashTypedData } from "viem";
import type { AtrHash } from "@integraledger/lcp";
import { exactEip3009, type Eip3009TypedData, type PaymentRequired } from "@integraledger/lcp/x402";
import { agree, confirm, transact, type Declined, type Fetch, type Signer, type SigningRequest } from "../src/index.js";

const B = JSON.parse(
  readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/buyer.json", import.meta.url), "utf8"),
);
const row = (name: string) => B.rows.find((r: { name: string }) => r.name === name);
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const base64Json = (v: unknown): string => Buffer.from(JSON.stringify(v), "utf8").toString("base64");

const A = fromHex(B.fixed.A);
const D: PaymentRequired = B.fixed.D;
const ACCOUNT: string = B.fixed.account;
const H: AtrHash = row("B1").expect.h;
const LINK_A = `https://atr.seller.example/${H}`;
const AG = B.fixed.agreement;
const AGREEMENT_URL: string = AG.url;
const IDENTITY_DETAIL = "The link served a content coding other than identity.";
const AGREEMENT_DETAIL = "The agreement URL served a content coding other than identity.";

/** Content-Encoding values that name a coding: RFC 9110's registered codings, a stacked list, and an unregistered one. */
const CODINGS = ["gzip", "x-gzip", "deflate", "br", "compress", "zstd", "gzip, gzip", "identity, gzip", "unknown"];

/** A body whose reads and cancellation are observed. */
function observed(bytes: Uint8Array) {
  const seen = { pulled: 0, cancelled: false };
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        seen.pulled++;
        controller.enqueue(new Uint8Array(bytes));
        controller.close();
      },
      cancel() {
        seen.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { seen, body };
}

/** A fetch that records each call and answers with `answer`. */
type Recording = Fetch & { calls: { url: string; init: Parameters<Fetch>[1] }[] };
function recording(answer: (url: string, init: Parameters<Fetch>[1]) => Response): Recording {
  const calls: Recording["calls"] = [];
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    calls.push({ url, init });
    return answer(url, init);
  }) as Recording;
  f.calls = calls;
  return f;
}

type Eip712Request = { kind: "eip712"; typedData: Eip3009TypedData };
function counting(): Signer & { requests: SigningRequest[] } {
  const key = privateKeyToAccount(B.fixed.payerKey);
  const requests: SigningRequest[] = [];
  return {
    account: ACCOUNT,
    requests,
    async sign(request) {
      requests.push(request);
      return key.signTypedData(forViem((request as Eip712Request).typedData));
    },
  };
}

const forViem = (td: Eip3009TypedData) => td as unknown as Parameters<typeof hashTypedData>[0];
const decline = (r: unknown) => (r as Declined).decline;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(B.fixed.now * 1000);
});
afterEach(() => {
  vi.useRealTimers();
});

describe("the ATR fetch", () => {
  it("asks for the identity coding", async () => {
    const fetch = recording(() => new Response(new Uint8Array(A), { status: 200 }));
    const out = await confirm(D, exactEip3009, ACCOUNT, fetch);
    expect((out as { h: AtrHash }).h).toBe(H);
    expect(fetch.calls[0]!.init.headers).toEqual({ "Accept-Encoding": "identity" });
  });

  it.each(["identity", " IDENTITY ", ""])("a 200 with Content-Encoding %j is read as sent", async (coding) => {
    const fetch = recording(() => new Response(new Uint8Array(A), { status: 200, headers: { "content-encoding": coding } }));
    const out = await confirm(D, exactEip3009, ACCOUNT, fetch);
    expect((out as { h: AtrHash; bytes: Uint8Array }).h).toBe(H);
    expect((out as { bytes: Uint8Array }).bytes).toEqual(A);
  });

  it.each(CODINGS)("a 200 with Content-Encoding %j is atr-unfetchable, unread, and nothing is signed", async (coding) => {
    const { seen, body } = observed(gzipSync(A));
    const fetch = recording(() => ({ status: 200, headers: new Headers({ "content-encoding": coding }), body }) as unknown as Response);
    const signer = counting();
    expect(decline(await transact(D, exactEip3009, signer, fetch))).toEqual({ code: "atr-unfetchable", detail: IDENTITY_DETAIL });
    expect(seen.pulled).toBe(0);
    expect(seen.cancelled).toBe(true);
    expect(signer.requests.length).toBe(0);
  });

  it("gzip bytes served with no Content-Encoding are hashed as sent, so they do not match the ATR's hash", async () => {
    const fetch = recording(() => new Response(new Uint8Array(gzipSync(A)), { status: 200 }));
    expect(decline(await confirm(D, exactEip3009, ACCOUNT, fetch))?.code).toBe("hash-mismatch");
  });
});

describe("the agreement exchange", () => {
  const unpaid402 = () => new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
  const receipt = () => new Uint8Array(Buffer.from(JSON.stringify(AG.receipt), "utf8"));

  it("asks for the identity coding on the unpaid request and on the paid one", async () => {
    const fetch = recording((_, init) =>
      init.headers?.["PAYMENT-SIGNATURE"] === undefined ? unpaid402() : new Response(receipt(), { status: 200 }),
    );
    expect(await agree(H, AGREEMENT_URL, counting(), fetch, { bytes: A })).toEqual({ receipt: AG.receipt });
    expect(fetch.calls.length).toBe(2);
    expect(fetch.calls[0]!.init.headers).toEqual({ "Accept-Encoding": "identity" });
    expect(fetch.calls[1]!.init.headers?.["Accept-Encoding"]).toBe("identity");
    expect(typeof fetch.calls[1]!.init.headers?.["PAYMENT-SIGNATURE"]).toBe("string");
  });

  it.each(CODINGS)("an unpaid 200 with Content-Encoding %j is agreement-failed, unread, and nothing is signed", async (coding) => {
    const { seen, body } = observed(gzipSync(receipt()));
    const fetch = recording(() => ({ status: 200, headers: new Headers({ "content-encoding": coding }), body }) as unknown as Response);
    const signer = counting();
    const out = await agree(H, AGREEMENT_URL, signer, fetch, { bytes: A });
    expect(decline(out)).toEqual({ code: "agreement-failed", detail: AGREEMENT_DETAIL });
    expect(out).not.toHaveProperty("moved");
    expect(seen.pulled).toBe(0);
    expect(seen.cancelled).toBe(true);
    expect(signer.requests.length).toBe(0);
  });

  it("a paid 200 with Content-Encoding gzip is agreement-failed with the sent payment kept as moved", async () => {
    const { seen, body } = observed(gzipSync(receipt()));
    const fetch = recording((_, init) =>
      init.headers?.["PAYMENT-SIGNATURE"] === undefined
        ? unpaid402()
        : ({ status: 200, headers: new Headers({ "content-encoding": "gzip" }), body } as unknown as Response),
    );
    const signer = counting();
    const out = await agree(H, AGREEMENT_URL, signer, fetch, { bytes: A });
    expect(decline(out)).toEqual({ code: "agreement-failed", detail: AGREEMENT_DETAIL });
    const moved = (out as Declined).moved!;
    expect(base64Json(moved.signed)).toBe(fetch.calls[1]!.init.headers?.["PAYMENT-SIGNATURE"]);
    expect(moved.h).toBe(H);
    expect(seen.pulled).toBe(0);
    expect(signer.requests.length).toBe(1);
  });
});
