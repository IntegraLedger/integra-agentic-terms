// The agreement step's rows BA1-BA7. The expected values are read from @integraledger/lcp's vectors/buyer.json, except
// the bounds of the agreement exchange: each paid request is bounded by min(maxTimeoutSeconds, 120) + 60 + 10 seconds,
// the whole exchange by the agreement option's maxTimeoutSeconds + 180 seconds, a timeout or a 202 is pending and the
// same payment is sent again after retry-after, and the end of the bound is `agreement-pending` with the signed agreement payment kept as `moved`.
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashTypedData, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { AtrHash } from "@integraledger/lcp";
import {
  exactEip3009,
  type Eip3009Payment,
  type Eip3009TypedData,
  type PaymentRequired,
  type PaymentRequirements,
} from "@integraledger/lcp/x402";
import {
  agree,
  confirm,
  transact,
  type AgreeOptions,
  type AgreementReceipt,
  type Binding,
  type Declined,
  type Fetch,
  type Signer,
  type SigningRequest,
  type ToApprove,
  type TransactOptions,
} from "../src/index.js";

const B = JSON.parse(
  readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/buyer.json", import.meta.url), "utf8"),
);
type Script = { status: number; paymentRequired?: string; retryAfter?: string; body?: string; repeats?: boolean };
const row = (name: string) => B.rows.find((r: { name: string }) => r.name === name);

const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const forViem = (td: Eip3009TypedData) => td as unknown as Parameters<typeof hashTypedData>[0];
const base64Json = (v: unknown): string => Buffer.from(JSON.stringify(v), "utf8").toString("base64");
const fromBase64Json = (s: string): unknown => JSON.parse(Buffer.from(s, "base64").toString("utf8"));

const A = fromHex(B.fixed.A);
const D: PaymentRequired = B.fixed.D;
const ACCOUNT: string = B.fixed.account;
const H: AtrHash = row("B1").expect.h;
const LINK_A: string = B.fixed.link;
const AG = B.fixed.agreement;
const AGREEMENT_URL: string = AG.url;
const OPTION: PaymentRequirements = AG.option;
const B6_SIGNATURE: string = row("B6").expect.signature;
/** The exchange bounds for the agreement option, whose maxTimeoutSeconds is 60: 130 s per paid request, 240 s in all. */
const PAID_REQUEST_MS = (Math.min(OPTION.maxTimeoutSeconds, 120) + 60 + 10) * 1000;
const EXCHANGE_MS = (OPTION.maxTimeoutSeconds + 180) * 1000;

/** The pattern of a pairing whose payment is not itself a public proof of the hash. */
const NO_PUBLIC_PROOF = { ...exactEip3009.pattern, publicProof: false };

/** The x402/EVM binding as a pairing with no public proof, with `read` also giving the agreement URL. */
function withAgreement(url: string): Binding {
  const real = exactEip3009.read(D);
  if ("refused" in real) throw new Error(real.code);
  return { ...exactEip3009, pattern: NO_PUBLIC_PROOF, read: () => ({ ...real, agreement: url }) };
}

/** D with the agreement URL in its legal context, as a challenge mixing public-proof and other offers carries it. */
function mixed(url: string): PaymentRequired {
  const lc = D.extensions!["legalContext"]!;
  return { ...D, extensions: { ...D.extensions, legalContext: { ...lc, info: { ...(lc.info as object), legalContextAgreementUrl: url } } } };
}

/** A fetch that serves A at the ATR link and plays `script` at the agreement URL, recording every call. */
type Seller = Fetch & {
  calls: { url: string; init: Parameters<Fetch>[1] }[];
  agreementCalls: () => { url: string; init: Parameters<Fetch>[1] }[];
  paid: () => string[];
};
function seller(script: readonly Script[]): Seller {
  const calls: Seller["calls"] = [];
  let step = 0;
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    calls.push({ url, init });
    if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
    const s = script[Math.min(step, script.length - 1)]!;
    if (!s.repeats) step++;
    const headers = new Headers();
    if (s.paymentRequired !== undefined) headers.set("payment-required", base64Json(AG[s.paymentRequired]));
    if (s.retryAfter !== undefined) headers.set("retry-after", s.retryAfter);
    const body = s.body === undefined ? null : JSON.stringify(AG[s.body]);
    return new Response(body, { status: s.status, headers });
  }) as Seller;
  f.calls = calls;
  f.agreementCalls = () => calls.filter((c) => c.url !== LINK_A);
  f.paid = () => f.agreementCalls().flatMap((c) => (c.init.headers?.["PAYMENT-SIGNATURE"] ?? []) as string[]);
  return f;
}

/** A signer over the published Anvil key that counts its calls. */
type Eip712Request = { kind: "eip712"; typedData: Eip3009TypedData };
type Counting = Signer & { requests: Eip712Request[] };
function counting(account = ACCOUNT): Counting {
  const key = privateKeyToAccount(B.fixed.payerKey);
  const requests: Eip712Request[] = [];
  return {
    account,
    requests,
    async sign(request: SigningRequest) {
      const eip712 = request as Eip712Request;
      requests.push(eip712);
      return key.signTypedData(forViem(eip712.typedData));
    },
  };
}

/**
 * Runs `p` to its end under the fake clock: lets real asynchronous work (hashing, signing) finish, then moves the
 * clock to the next pending timer, until `p` settles. Returns its value and the fake time that passed.
 */
async function drive<T>(p: Promise<T>): Promise<{ value: T; elapsed: number }> {
  const start = Date.now();
  let done = false;
  let value: T | undefined;
  void p.then((v) => {
    done = true;
    value = v;
  });
  for (;;) {
    while (!done && vi.getTimerCount() === 0) await new Promise((resolve) => setImmediate(resolve));
    if (done) return { value: value as T, elapsed: Date.now() - start };
    await vi.advanceTimersToNextTimerAsync();
  }
}

/** `agree` in its two calls: the agreement payment to approve, then that payment, approved unchanged. */
async function approveAndAgree(
  signer: Signer,
  fetch: Fetch,
  options: AgreeOptions = {},
): Promise<ToApprove | { receipt: AgreementReceipt } | Declined> {
  const first = await agree(A, AGREEMENT_URL, signer, fetch, options);
  if (!("approve" in first)) return first;
  return agree(A, AGREEMENT_URL, signer, fetch, { ...options, approved: first.approve });
}

/** `transact` in its two calls: the agreement payment to approve, then the call with that payment approved unchanged. */
async function approveAndTransact(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  fetch: Fetch,
  options: TransactOptions = {},
): ReturnType<typeof transact> {
  const first = await transact(doc, binding, signer, fetch, options);
  if (!("approve" in first)) return first;
  return transact(doc, binding, signer, fetch, { ...options, approved: first.approve });
}

const code = (r: unknown): string | undefined => (r as Declined).decline?.code;
const isDeclined = (r: unknown): r is Declined => typeof r === "object" && r !== null && "decline" in r;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  vi.setSystemTime(B.fixed.now * 1000);
});
afterEach(() => {
  vi.useRealTimers();
});

describe("fixed agreement inputs", () => {
  it("the agreement challenges are what the binding's advertise writes for the agreement option", () => {
    const base: PaymentRequired = { x402Version: 2, resource: { url: AGREEMENT_URL }, accepts: [OPTION] };
    expect(exactEip3009.advertise(base, H, LINK_A, OPTION)).toEqual(AG.required);
    const hashC: AtrHash = B.fixed.hashC;
    const linkC: string = AG.requiredOtherHash.extensions.legalContext.info.legalContextUrl;
    expect(exactEip3009.advertise(base, hashC, linkC, OPTION)).toEqual(AG.requiredOtherHash);
  });
});

describe("confirm", () => {
  it("carries the agreement URL the binding read in chosen, and none when it read none", async () => {
    const withUrl = await confirm(D, withAgreement(AGREEMENT_URL), ACCOUNT, seller([]));
    if (isDeclined(withUrl)) throw new Error(withUrl.decline.code);
    expect(withUrl.chosen.agreement).toBe(AGREEMENT_URL);
    const without = await confirm(D, exactEip3009, ACCOUNT, seller([]));
    if (isDeclined(without)) throw new Error(without.decline.code);
    expect(without.chosen).not.toHaveProperty("agreement");
  });

  it("declines an agreement that is not a string before any fetch", async () => {
    const real = exactEip3009.read(D);
    if ("refused" in real) throw new Error(real.code);
    const odd = { ...exactEip3009, pattern: NO_PUBLIC_PROOF, read: () => ({ ...real, agreement: 7 }) } as unknown as Binding;
    const fetch = seller([]);
    expect(code(await confirm(D, odd, ACCOUNT, fetch))).toBe("offer-unreadable");
    expect(fetch.calls.length).toBe(0);
  });
});

describe("agreement rows", () => {
  it("BA1: the agreement is signed and paid first, then the full payment is signed once", async () => {
    const r = row("BA1");
    const fetch = seller(r.input.agreement);
    const signer = counting();
    const { value: settled, elapsed } = await drive(approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, fetch));
    if (isDeclined(settled)) throw new Error(settled.decline.code);
    const out = settled as { signed: Eip3009Payment; bytes: Uint8Array; h: AtrHash };
    expect(elapsed).toBe(Number(r.input.agreement[1].retryAfter) * 1000);

    expect(signer.requests.length).toBe(r.expect.signCalls);
    const [agreement, payment] = signer.requests;
    const m = r.expect.agreementMessage;
    expect(agreement!.typedData.message).toEqual({
      from: m.from,
      to: m.to,
      value: BigInt(m.value),
      validAfter: BigInt(m.validAfter),
      validBefore: BigInt(m.validBefore),
      nonce: m.nonce,
    });
    expect(hashTypedData(forViem(agreement!.typedData))).toBe(r.expect.agreementDigest);
    expect(payment!.typedData.message.nonce).toBe(H);
    expect(payment!.typedData.message.value).toBe(BigInt(D.accepts[0]!.amount));

    const paid = fetch.paid();
    expect(paid.length).toBe(r.expect.paidRequests);
    expect(new Set(paid).size).toBe(1);
    const sent = fromBase64Json(paid[0]!) as Eip3009Payment;
    expect(sent.payload.authorization.nonce).toBe(H);
    expect(sent.payload.authorization.value).toBe(m.value);
    expect(sent.payload.signature).toBe(r.expect.agreementSignature);
    expect(sent.accepted).toEqual(OPTION);
    expect(
      await recoverTypedDataAddress({ ...forViem(agreement!.typedData), signature: r.expect.agreementSignature }),
    ).toBe(m.from);

    expect(out.signed.payload.signature).toBe(B6_SIGNATURE);
    expect(out.h).toBe(H);
    expect(out.bytes).toEqual(A);
    expect(fetch.calls.map((c) => c.url)).toEqual([LINK_A, AGREEMENT_URL, LINK_A, AGREEMENT_URL, AGREEMENT_URL]);
    expect(fetch.agreementCalls()[0]!.init.headers).toEqual({ "Accept-Encoding": "identity" });
    for (const c of fetch.calls) {
      expect(c.init.method).toBe("GET");
      expect(c.init.redirect).toBe("manual");
      expect(c.init.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it("BA1: agree returns the receipt; an agreement signer, when given, signs the agreement", async () => {
    const r = row("BA1");
    const direct = seller(r.input.agreement);
    const { value } = await drive(approveAndAgree(counting(), direct));
    expect(value).toEqual({ receipt: AG[r.expect.receipt] as AgreementReceipt });

    const signer = counting();
    const agreementSigner = counting();
    const whole = await drive(
      approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, seller(r.input.agreement), { agreementSigner }),
    );
    expect(isDeclined(whole.value)).toBe(false);
    expect(agreementSigner.requests.map((q) => q.typedData.message.value)).toEqual([1n]);
    expect(signer.requests.map((q) => q.typedData.message.value)).toEqual([10000n]);
  });

  it("BA2 (the plant): an agreement challenge advertising another ATR's hash is never signed", async () => {
    const r = row("BA2");
    expect(r.plant).toBe(true);
    const fetch = seller(r.input.agreement);
    const signer = counting();
    expect(code(await approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, fetch))).toBe(r.expect.decline);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect(fetch.paid().length).toBe(r.expect.paidRequests);

    const direct = counting();
    expect(code(await approveAndAgree(direct, seller(r.input.agreement)))).toBe(r.expect.decline);
    expect(direct.requests.length).toBe(r.expect.signCalls);
  });

  it("BA3: a 202 that never becomes 200 is pending at the exchange bound; the agreement payment is kept, the full payment never signed", async () => {
    const r = row("BA3");
    const fetch = seller(r.input.agreement);
    const signer = counting();
    const { value, elapsed } = await drive(approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect(signer.requests[0]!.typedData.message.value).toBe(1n);
    const retryMs = Number(r.input.agreement[1].retryAfter) * 1000;
    expect(fetch.paid().length).toBe(EXCHANGE_MS / retryMs);
    expect(new Set(fetch.paid()).size).toBe(1);
    const moved = (value as Declined).moved!;
    expect(moved.h).toBe(H);
    expect(moved.bytes).toEqual(A);
    expect(base64Json(moved.signed)).toBe(fetch.paid()[0]);
  });

  // The 202's retry-after in its other forms, as buyer.json's BA15 writes them: the gate waits
  // retry-after's delay-seconds (RFC 9110 section 10.2.3), at least 1 s, and 2 s when it is absent or in any other
  // form, an HTTP-date included, so within the 240 s exchange the payment goes 120 times, or 240 times after "0".
  it.each([
    ["absent", undefined, 120],
    ["0", "0", 240],
    ["an HTTP-date", "Wed, 21 Oct 2026 07:28:00 GMT", 120],
  ] as const)("a 202 whose retry-after is %s: agreement-pending at the exchange bound, the payment sent %d times", async (_, retryAfter, paid) => {
    const fetch = seller([
      { status: 402, paymentRequired: "required" },
      { status: 202, ...(retryAfter === undefined ? {} : { retryAfter }), repeats: true },
    ]);
    const signer = counting();
    const { value, elapsed } = await drive(approveAndAgree(signer, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
    expect(signer.requests.length).toBe(1);
    expect(fetch.paid().length).toBe(paid);
    expect(new Set(fetch.paid()).size).toBe(1);
  });

  it("BA3: the exchange bound runs from the payment's first sending, not from the signer's call", async () => {
    const r = row("BA3");
    const fetch = seller(r.input.agreement);
    const inner = counting();
    const slow: Signer = {
      account: ACCOUNT,
      sign: (request) => new Promise((resolve) => setTimeout(() => resolve(inner.sign(request)), 30_000)),
    };
    const { value, elapsed } = await drive(approveAndAgree(slow, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(30_000 + EXCHANGE_MS);
  });

  it("a paid request that never answers is aborted at its bound and sent again, until the exchange bound", async () => {
    const calls: number[] = [];
    const fetch = (async (url: string, init: Parameters<Fetch>[1]) => {
      if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
      if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
        return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
      }
      calls.push(Date.now());
      return new Promise<Response>(() => undefined);
    }) as Fetch;
    const signer = counting();
    const { value, elapsed } = await drive(approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
    const start = B.fixed.now * 1000;
    expect(calls).toEqual([start, start + PAID_REQUEST_MS + 2000]);
    expect(signer.requests.length).toBe(1);
  });

  it("BA4: a receipt naming another ATR hash fails, and the full payment is never signed", async () => {
    const r = row("BA4");
    const signer = counting();
    expect(code(await approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, seller(r.input.agreement)))).toBe(
      r.expect.decline,
    );
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect(signer.requests[0]!.typedData.message.value).toBe(1n);
  });

  it("BA5: an http agreement URL is declined before any fetch of it", async () => {
    const r = row("BA5");
    const fetch = seller([]);
    const signer = counting();
    expect(code(await agree(A, r.input.agreementUrl, signer, fetch))).toBe(r.expect.decline);
    expect(fetch.calls.length).toBe(r.expect.agreementFetches);
    expect(signer.requests.length).toBe(r.expect.signCalls);

    const through = seller([]);
    const again = counting();
    expect(code(await approveAndTransact(D, withAgreement(r.input.agreementUrl), again, through))).toBe(r.expect.decline);
    expect(through.agreementCalls().length).toBe(r.expect.agreementFetches);
    expect(again.requests.length).toBe(r.expect.signCalls);
  });

  it("an agreement URL the gate refuses carries the protocol package's code in its detail", async () => {
    for (const [url, detail] of [
      ["http://pay.seller.example/agreement", "x402/link-not-https"],
      ["not a url", "x402/legal-context-malformed"],
      ["https://u@pay.seller.example/agreement", "x402/legal-context-malformed"],
    ] as const) {
      const fetch = seller([]);
      const signer = counting();
      expect(await approveAndTransact(D, withAgreement(url), signer, fetch)).toEqual({ decline: { code: "link-not-https", detail } });
      expect(fetch.agreementCalls().length).toBe(0);
      expect(signer.requests.length).toBe(0);
    }
  });

  // buyer.json's BA5, with its detail and its agree entry: agree, called with the agreement URL alone, declines a URL
  // it refuses link-not-https with the protocol package's code in x402's namespace, before any fetch or signer call:
  // link-not-https for an absolute URL of another scheme, legal-context-malformed for any other value.
  it("agree called with an agreement URL it refuses carries x402's code in its detail", async () => {
    for (const [url, detail] of [
      ["http://api.seller.example/agreement/b9d3d4b7-2c99-4d5f-9178-837645f75273", "x402/link-not-https"],
      ["api.seller.example/agreement/b9d3d4b7-2c99-4d5f-9178-837645f75273", "x402/legal-context-malformed"],
      ["not a url", "x402/legal-context-malformed"],
      ["https://u@pay.seller.example/agreement", "x402/legal-context-malformed"],
    ] as const) {
      const fetch = seller([]);
      const signer = counting();
      expect(await agree(A, url, signer, fetch)).toEqual({ decline: { code: "link-not-https", detail } });
      expect([fetch.calls.length, signer.requests.length]).toEqual([0, 0]);
    }
  });

  // A seller's challenge whose resource description is a lone surrogate, written as a JSON escape: the paid request's
  // PAYMENT-SIGNATURE carries it escaped, as JSON.stringify writes it, and the agreement is recorded.
  it("a lone surrogate the challenge echoes is sent escaped, and the agreement is recorded", async () => {
    const required = { ...AG.required, resource: { ...AG.required.resource, description: "\ud800" } };
    const header = Buffer.from(JSON.stringify(required)).toString("base64");
    const paid: string[] = [];
    const fetch = (async (_url: string, init: Parameters<Fetch>[1]) => {
      const signature = init.headers?.["PAYMENT-SIGNATURE"];
      if (signature === undefined) return new Response(null, { status: 402, headers: { "payment-required": header } });
      paid.push(signature);
      return new Response(JSON.stringify(AG.receipt), { status: 200 });
    }) as Fetch;
    expect(await approveAndAgree(counting(), fetch)).toEqual({ receipt: AG.receipt });
    const text = Buffer.from(paid[0]!, "base64").toString("utf8");
    expect(text).toContain('"description":"\\ud800"');
    expect(JSON.parse(text).resource.description).toBe("\ud800");
  });

  // A seller's challenge whose resource carries an integer of 401 digits: JSON.parse reads it as Infinity, and
  // JSON.stringify writes a number that is not finite as null (ECMA-262 SerializeJSONProperty). The signer is called
  // once, the paid request's PAYMENT-SIGNATURE carries null, and the agreement is recorded.
  it("a number outside the double range the challenge echoes is sent as null, and the agreement is recorded", async () => {
    const text402 = JSON.stringify({ ...AG.required, resource: { ...AG.required.resource, size: 0 } });
    const header = Buffer.from(text402.replace('"size":0', `"size":1${"0".repeat(400)}`)).toString("base64");
    const paid: string[] = [];
    const fetch = (async (_url: string, init: Parameters<Fetch>[1]) => {
      const signature = init.headers?.["PAYMENT-SIGNATURE"];
      if (signature === undefined) return new Response(null, { status: 402, headers: { "payment-required": header } });
      paid.push(signature);
      return new Response(JSON.stringify(AG.receipt), { status: 200 });
    }) as Fetch;
    const signer = counting();
    expect(await approveAndAgree(signer, fetch)).toEqual({ receipt: AG.receipt });
    expect([signer.requests.length, paid.length]).toEqual([1, 1]);
    const text = Buffer.from(paid[0]!, "base64").toString("utf8");
    expect(text).toContain('"size":null');
    expect(JSON.parse(text).resource.size).toBeNull();
  });

  // Number() of a declared length of 5000 digits is Infinity: the agreement URL's 200 is larger than 64 KiB.
  it("a receipt whose declared length has 5000 digits is larger than 64 KiB", async () => {
    const declared = "1" + "0".repeat(4999);
    const fetch = (async () => new Response(null, { status: 200, headers: { "content-length": declared } })) as Fetch;
    expect(await agree(A, AGREEMENT_URL, counting(), fetch)).toEqual({
      decline: { code: "agreement-failed", detail: "The agreement receipt is larger than 64 KiB." },
    });
  });

  it("BA6: a pairing whose payment is a public proof reads the agreement URL and does not pay it", async () => {
    const r = row("BA6");
    const doc = mixed(AGREEMENT_URL);
    const read = exactEip3009.read(doc);
    if ("refused" in read) throw new Error(read.code);
    expect(read.agreement).toBe(AGREEMENT_URL);
    const confirmed = await confirm(doc, exactEip3009, ACCOUNT, seller([]));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
    expect(confirmed).not.toHaveProperty("agreement");

    const fetch = seller([{ status: 402, paymentRequired: "required" }]);
    const signer = counting();
    const out = await transact(doc, exactEip3009, signer, fetch);
    if (isDeclined(out)) throw new Error(out.decline.code);
    if ("approve" in out) throw new Error("an agreement payment to approve");
    expect(fetch.agreementCalls().length).toBe(r.expect.agreementFetches);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect((out.signed as Eip3009Payment).payload.signature).toBe(row(r.expect.paymentSignature).expect.signature);
    expect(out).not.toHaveProperty("agreement");
  });

  it("BA7: transact returns the agreement's receipt beside the payment", async () => {
    const r = row("BA7");
    const { value: out } = await drive(approveAndTransact(D, withAgreement(AGREEMENT_URL), counting(), seller(r.input.agreement)));
    if (isDeclined(out)) throw new Error(out.decline.code);
    if ("approve" in out) throw new Error("an agreement payment to approve");
    expect(out.agreement).toEqual(AG[r.expect.agreement]);
    expect((out.signed as Eip3009Payment).payload.signature).toBe(row(r.expect.signed).expect.signature);
    const plain = await transact(D, exactEip3009, counting(), seller([]));
    if (isDeclined(plain)) throw new Error(plain.decline.code);
    expect(plain).not.toHaveProperty("agreement");
  });
});

describe("the agreement URL's other answers", () => {
  it("a recorded agreement answers 200 at once: the receipt, with no signature", async () => {
    const signer = counting();
    const out = await approveAndAgree(signer, seller([{ status: 200, body: "receipt" }]));
    expect(out).toEqual({ receipt: AG.receipt });
    expect(signer.requests.length).toBe(0);
  });

  it.each([
    ["an unpaid 404", [{ status: 404 }]],
    ["a 402 with no PAYMENT-REQUIRED", [{ status: 402 }]],
  ] as [string, Script[]][])("%s: agreement-failed, nothing signed", async (_, script) => {
    const signer = counting();
    expect(code(await approveAndAgree(signer, seller(script)))).toBe("agreement-failed");
    expect(signer.requests.length).toBe(0);
  });

  it("an unpaid 202, another sending of the agreement still settling: agreement-pending, nothing signed", async () => {
    const signer = counting();
    const out = await approveAndAgree(signer, seller([{ status: 202, retryAfter: "2" }]));
    expect(code(out)).toBe("agreement-pending");
    expect(out).not.toHaveProperty("moved");
    expect(signer.requests.length).toBe(0);
  });

  it("an answer the signer gives that does not complete the agreement payment: nothing is sent", async () => {
    const fetch = seller([{ status: 402, paymentRequired: "required" }]);
    const signer: Signer = { account: ACCOUNT, sign: async () => "0x00" };
    expect(code(await approveAndAgree(signer, fetch))).toBe("signed-not-bound");
    expect(fetch.paid().length).toBe(0);
  });

  it("a paid 402 re-challenge: agreement-failed after one signature, with the sent payment kept", async () => {
    const signer = counting();
    const script: Script[] = [
      { status: 402, paymentRequired: "required" },
      { status: 402, paymentRequired: "required" },
    ];
    const fetch = seller(script);
    const out = await approveAndAgree(signer, fetch);
    expect(code(out)).toBe("agreement-failed");
    expect(signer.requests.length).toBe(1);
    expect(fetch.paid().length).toBe(1);
    expect(base64Json((out as Declined).moved!.signed)).toBe(fetch.paid()[0]);
  });

  it("a signer on no offered chain: no-payable-option, nothing signed", async () => {
    const signer = counting("eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const script: Script[] = [{ status: 402, paymentRequired: "required" }];
    expect(code(await approveAndAgree(signer, seller(script)))).toBe("no-payable-option");
    expect(signer.requests.length).toBe(0);
  });

  // The unpaid request is bounded by the gate's deadline on each await, 10 s.
  it("an agreement URL that never answers fails at 10 s", async () => {
    const fetch = (() => new Promise<Response>(() => undefined)) as Fetch;
    const { value, elapsed } = await drive(approveAndAgree(counting(), fetch));
    expect(code(value)).toBe("agreement-failed");
    expect(elapsed).toBe(10_000);
  });
});

// Once the agreement payment is sent, no decline is bare: a 5xx to the paid request is read as a
// timeout, so the same payment is sent again until the exchange bound, which ends agreement-pending with the payment
// kept as moved; any other answer that is not a receipt naming H is agreement-failed with the payment kept as moved.
describe("after the agreement payment is sent", () => {
  /** The unpaid request answers 402 with the agreement challenge; every paid request answers `status` with `body`. */
  function paidAnswer(status: number, body: string | null): Seller {
    const calls: Seller["calls"] = [];
    const f = (async (url: string, init: Parameters<Fetch>[1]) => {
      calls.push({ url, init });
      if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
      if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
        return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
      }
      return new Response(body, { status });
    }) as Seller;
    f.calls = calls;
    f.agreementCalls = () => calls.filter((c) => c.url !== LINK_A);
    f.paid = () => f.agreementCalls().flatMap((c) => (c.init.headers?.["PAYMENT-SIGNATURE"] ?? []) as string[]);
    return f;
  }

  function keptAsMoved(out: unknown, fetch: Seller): void {
    const moved = (out as Declined).moved!;
    expect(moved).toBeDefined();
    expect(base64Json(moved.signed)).toBe(fetch.paid()[0]);
    expect(moved.bytes).toEqual(A);
    expect(moved.h).toBe(H);
  }

  it.each([504, 500])("a %i is read as a timeout: the same payment is sent again, then agreement-pending with moved", async (status) => {
    const fetch = paidAnswer(status, null);
    const signer = counting();
    const { value, elapsed } = await drive(approveAndAgree(signer, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
    expect(signer.requests.length).toBe(1);
    expect(fetch.paid().length).toBeGreaterThan(1);
    expect(new Set(fetch.paid()).size).toBe(1);
    keptAsMoved(value, fetch);
  });

  const otherHash = `0x${"11".repeat(32)}`;
  it.each([
    ["a paid 402", 402, null],
    ["a paid 404", 404, null],
    ["a 200 whose body is not JSON", 200, "not json"],
    ["a 200 whose receipt names another hash", 200, JSON.stringify({ ...AG.receipt, atrHash: otherHash })],
    ["a 200 whose receipt is over 64 KiB", 200, "x".repeat(65_537)],
  ] as [string, number, string | null][])("%s: agreement-failed, paid once, the payment kept as moved", async (_, status, body) => {
    const fetch = paidAnswer(status, body);
    const signer = counting();
    const { value } = await drive(approveAndAgree(signer, fetch));
    expect(code(value)).toBe("agreement-failed");
    expect(signer.requests.length).toBe(1);
    expect(fetch.paid().length).toBe(1);
    keptAsMoved(value, fetch);
  });
});

// The one JSON nesting cap for binding reads, 64 levels of arrays and objects (core-vectors.json `jsonDepth.max`): a
// PAYMENT-REQUIRED nested deeper is not read, so nothing is built or signed.
describe("the agreement challenge's JSON nesting", () => {
  const CAP: number = JSON.parse(
    readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/core-vectors.json", import.meta.url), "utf8"),
  ).jsonDepth.max;
  /** The agreement challenge, with arrays nested inside `extensions` so the document's depth is `depth`. */
  function nested(depth: number): string {
    const inner = depth - 2;
    const text = JSON.stringify({ ...AG.required, extensions: { ...AG.required.extensions, deep: "@" } });
    return Buffer.from(text.replace('"@"', "[".repeat(inner) + "]".repeat(inner)), "utf8").toString("base64");
  }
  function once(header: string): Seller {
    const f = seller([]);
    const g = (async (url: string, init: Parameters<Fetch>[1]) => {
      f.calls.push({ url, init });
      if (init.headers?.["PAYMENT-SIGNATURE"] !== undefined) {
        return new Response(JSON.stringify(AG.receipt), { status: 200 });
      }
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }) as Seller;
    return Object.assign(g, { calls: f.calls, agreementCalls: f.agreementCalls, paid: f.paid });
  }
  it("a challenge nested one level past the cap is unreadable, and the signer is never called", async () => {
    const signer = counting();
    const { value } = await drive(approveAndAgree(signer, once(nested(CAP + 1))));
    expect(isDeclined(value) && value.decline).toEqual({
      code: "agreement-failed",
      detail: "The agreement URL answered 402 without a readable PAYMENT-REQUIRED.",
    });
    expect(signer.requests.length).toBe(0);
  });
  it("a challenge nested exactly to the cap is read and paid", async () => {
    const signer = counting();
    const { value } = await drive(approveAndAgree(signer, once(nested(CAP))));
    expect(signer.requests.length).toBe(1);
    expect(value).toEqual({ receipt: AG.receipt });
  });
});

// A facilitator's settle failure after the agreement payment is sent, as the agreement URL relays it (x402 §9's
// `unexpected_settle_error`; `SettleResponse` {success, errorReason, payer, transaction, network}; a failed settle is
// answered 402 with `PAYMENT-REQUIRED` carrying `error`). After the payment is sent, a 5xx is read as a timeout and ends `agreement-pending`
// with `moved`; a 402, or a 200 whose body is not a receipt naming H, is `agreement-failed` with `moved`.
describe("a facilitator's settle failure relayed by the agreement URL", () => {
  const settleError = {
    success: false,
    errorReason: "unexpected_settle_error",
    payer: ACCOUNT,
    transaction: "",
    network: OPTION.network,
  };
  /** The unpaid request answers the agreement challenge; every paid request answers `status` with the settle error. */
  function relaying(status: number, rechallenge: boolean): Seller {
    const calls: Seller["calls"] = [];
    const f = (async (url: string, init: Parameters<Fetch>[1]) => {
      calls.push({ url, init });
      if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
      if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
        return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
      }
      const headers = new Headers({ "content-type": "application/json", "payment-response": base64Json(settleError) });
      if (rechallenge) headers.set("payment-required", base64Json({ ...AG.required, error: "unexpected_settle_error" }));
      return new Response(JSON.stringify(settleError), { status, headers });
    }) as Seller;
    f.calls = calls;
    f.agreementCalls = () => calls.filter((c) => c.url !== LINK_A);
    f.paid = () => f.agreementCalls().flatMap((c) => (c.init.headers?.["PAYMENT-SIGNATURE"] ?? []) as string[]);
    return f;
  }

  it.each([
    ["a 402 re-challenge whose error is unexpected_settle_error", 402, true, "agreement-failed"],
    ["a 502 whose body is the settle error", 502, false, "agreement-pending"],
    ["a 200 whose body is the settle error, naming no receipt", 200, false, "agreement-failed"],
  ] as [string, number, boolean, string][])("%s declines with the sent payment kept as moved", async (_, status, rechallenge, expected) => {
    const fetch = relaying(status, rechallenge);
    const signer = counting();
    const { value } = await drive(approveAndAgree(signer, fetch));
    expect(code(value)).toBe(expected);
    expect(signer.requests.length).toBe(1);
    const moved = (value as Declined).moved!;
    expect(moved).toBeDefined();
    expect(base64Json(moved.signed)).toBe(fetch.paid()[0]);
    expect(new Set(fetch.paid()).size).toBe(1);
    expect([moved.bytes, moved.h]).toEqual([A, H]);
  });

  it("through transact: the 402 settle failure declines agreement-failed with moved, and the full payment is never signed", async () => {
    const fetch = relaying(402, true);
    const signer = counting();
    const { value } = await drive(approveAndTransact(D, withAgreement(AGREEMENT_URL), signer, fetch));
    expect(code(value)).toBe("agreement-failed");
    expect(signer.requests.length).toBe(1);
    expect(base64Json((value as Declined).moved!.signed)).toBe(fetch.paid()[0]);
  });
});

// The agreement payment is a payment the buyer's agent approves like any other. The first call fetches the agreement
// URL's challenge and returns the payment it would make, signing nothing; only a second call carrying that payment back
// signs it. The option paid is chosen with the main payment's rule: the challenge's options in document order, the first
// the signer can pay whose pairing's payment is itself a public proof. The exchange is bounded by that option's
// `maxTimeoutSeconds`, a JSON number with an integral value, plus 180 s. Options are the vector files': buyer.json's
// agreement option, x402-exact-solana.json's option and x402-exact-eip155-erc7710.json's option.
describe("the agreement payment the agent approves", () => {
  const SOLANA_OPTION: PaymentRequirements = JSON.parse(
    readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/x402-exact-solana.json", import.meta.url), "utf8"),
  ).fixed.option;
  const ERC7710_OPTION: PaymentRequirements = JSON.parse(
    readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/x402-exact-eip155-erc7710.json", import.meta.url), "utf8"),
  ).fixed.option;

  /** A seller whose unpaid agreement answer is 402 with `header` as PAYMENT-REQUIRED, then plays `then`. */
  function challenging(header: string, then: readonly Script[]): Seller {
    const calls: Seller["calls"] = [];
    let step = 0;
    const f = (async (url: string, init: Parameters<Fetch>[1]) => {
      calls.push({ url, init });
      if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
      if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
        return new Response(null, { status: 402, headers: { "payment-required": header } });
      }
      const s = then[Math.min(step, then.length - 1)]!;
      if (!s.repeats) step++;
      const headers = new Headers();
      if (s.retryAfter !== undefined) headers.set("retry-after", s.retryAfter);
      return new Response(s.body === undefined ? null : JSON.stringify(AG[s.body]), { status: s.status, headers });
    }) as Seller;
    f.calls = calls;
    f.agreementCalls = () => calls.filter((c) => c.url !== LINK_A);
    f.paid = () => f.agreementCalls().flatMap((c) => (c.init.headers?.["PAYMENT-SIGNATURE"] ?? []) as string[]);
    return f;
  }
  const withAccepts = (accepts: unknown[]): string => base64Json({ ...AG.required, accepts });
  const RECORDED: Script[] = [{ status: 200, body: "receipt" }];
  const PENDING: Script[] = [{ status: 202, retryAfter: "2", repeats: true }];

  it("transact returns the agreement payment for approval and signs nothing", async () => {
    const fetch = seller(row("BA1").input.agreement);
    const signer = counting();
    const out = await transact(D, withAgreement(AGREEMENT_URL), signer, fetch);
    expect(out).toEqual({ approve: { url: AGREEMENT_URL, option: OPTION, required: AG.required }, bytes: A, h: H });
    expect(signer.requests.length).toBe(0);
    expect(fetch.paid().length).toBe(0);
    expect(fetch.agreementCalls().length).toBe(1);
  });

  it("agree returns the agreement payment for approval and signs nothing", async () => {
    const fetch = seller(row("BA1").input.agreement);
    const signer = counting();
    expect(await agree(A, AGREEMENT_URL, signer, fetch)).toEqual({
      approve: { url: AGREEMENT_URL, option: OPTION, required: AG.required },
      bytes: A,
      h: H,
    });
    expect(signer.requests.length).toBe(0);
    expect(fetch.paid().length).toBe(0);
  });

  it("the approved payment is signed as shown: its option's payTo, amount, asset and network, with H as the nonce", async () => {
    const fetch = seller(row("BA1").input.agreement);
    const signer = counting();
    const first = await agree(A, AGREEMENT_URL, signer, fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    const { value } = await drive(agree(A, AGREEMENT_URL, signer, fetch, { approved: first.approve }));
    expect(value).toEqual({ receipt: AG.receipt });
    expect(signer.requests.length).toBe(1);
    const { domain, message } = signer.requests[0]!.typedData;
    expect([message.to, message.value, domain.verifyingContract, `eip155:${domain.chainId}`, message.nonce]).toEqual([
      first.approve.option.payTo,
      BigInt(first.approve.option.amount),
      first.approve.option.asset,
      first.approve.option.network,
      H,
    ]);
    const sent = fromBase64Json(fetch.paid()[0]!) as Eip3009Payment;
    expect(sent.accepted).toEqual(first.approve.option);
    for (const c of fetch.agreementCalls().slice(1)) expect(c.init.headers?.["PAYMENT-SIGNATURE"]).toBeDefined();
  });

  it("an approved payment for another agreement URL: agreement-failed, nothing signed or sent", async () => {
    const fetch = seller(row("BA1").input.agreement);
    const signer = counting();
    const approved = { url: "https://api.seller.example/agreement/other", option: OPTION, required: AG.required };
    const out = await agree(A, AGREEMENT_URL, signer, fetch, { approved });
    expect(isDeclined(out) && out.decline).toEqual({
      code: "agreement-failed",
      detail: "The approved agreement payment names another agreement URL.",
    });
    expect(signer.requests.length).toBe(0);
    expect(fetch.calls.length).toBe(0);
  });

  it.each([64, 65, 100_000])("an agreement payment nested %i levels: sent within 64, else signed-not-bound", async (levels) => {
    // The signed payment nests `levels` levels: the payment 1, accepted 2, its extra 3, the array from 4. The protocol
    // package reads JSON nested at most 64 levels, so a deeper payment is declined after the signer's one call, unsent.
    let deep: unknown = [];
    for (let i = 0; i < levels - 4; i++) deep = [deep];
    const fetch = seller(row("BA1").input.agreement);
    const signer = counting();
    const first = await agree(A, AGREEMENT_URL, signer, fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    const option = { ...first.approve.option, extra: { ...first.approve.option.extra, deep } } as PaymentRequirements;
    const { value } = await drive(agree(A, AGREEMENT_URL, signer, fetch, { approved: { ...first.approve, option } }));
    expect(signer.requests.length).toBe(1);
    if (levels <= 64) {
      expect(value).toEqual({ receipt: AG.receipt });
      expect(fetch.paid().length).toBe(row("BA1").expect.paidRequests);
      expect(new Set(fetch.paid()).size).toBe(1);
    } else {
      expect(isDeclined(value) && value.decline).toEqual({
        code: "signed-not-bound",
        detail: "The agreement payment is not plain JSON.",
      });
      expect(fetch.paid().length).toBe(0);
    }
  });

  it("an approved value that is not an agreement payment: no-payable-option, nothing fetched", async () => {
    const fetch = seller([]);
    const approved = { url: AGREEMENT_URL } as unknown as AgreeOptions["approved"];
    const out = await agree(A, AGREEMENT_URL, counting(), fetch, { approved });
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect(fetch.calls.length).toBe(0);
  });

  it("an approved payment whose challenge advertises another hash: hash-mismatch, nothing signed", async () => {
    const fetch = seller([]);
    const signer = counting();
    const approved = { url: AGREEMENT_URL, option: OPTION, required: AG.requiredOtherHash };
    expect(code(await agree(A, AGREEMENT_URL, signer, fetch, { approved }))).toBe("hash-mismatch");
    expect(signer.requests.length).toBe(0);
    expect(fetch.calls.length).toBe(0);
  });

  it("accepts [Solana, EVM] with an EVM signer: the EVM option is the one to approve, then paid", async () => {
    const fetch = challenging(withAccepts([SOLANA_OPTION, OPTION]), RECORDED);
    const signer = counting();
    const first = await agree(A, AGREEMENT_URL, signer, fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    expect(first.approve.option).toEqual(OPTION);
    const { value } = await drive(agree(A, AGREEMENT_URL, signer, fetch, { approved: first.approve }));
    expect(value).toEqual({ receipt: AG.receipt });
    expect(signer.requests.map((q) => q.typedData.message.value)).toEqual([1n]);
  });

  it("an option whose pairing is not a public proof is passed over for the next one", async () => {
    const fetch = challenging(withAccepts([ERC7710_OPTION, OPTION]), RECORDED);
    const first = await agree(A, AGREEMENT_URL, counting(), fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    expect(first.approve.option).toEqual(OPTION);
  });

  it("an option on another chain than the signer's is passed over for the next one", async () => {
    const mainnet = { ...OPTION, network: "eip155:1" };
    const first = await agree(A, AGREEMENT_URL, counting(), challenging(withAccepts([mainnet, OPTION]), RECORDED));
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    expect(first.approve.option).toEqual(OPTION);
  });

  it("no option the signer can pay with a public-proof pairing: no-payable-option, nothing signed", async () => {
    const signer = counting();
    const out = await agree(A, AGREEMENT_URL, signer, challenging(withAccepts([SOLANA_OPTION, ERC7710_OPTION]), RECORDED));
    expect(code(out)).toBe("no-payable-option");
    expect(signer.requests.length).toBe(0);
  });

  it("the exchange is bounded by the chosen option's maxTimeoutSeconds plus 180 s, not the first option's", async () => {
    const fetch = challenging(withAccepts([{ ...SOLANA_OPTION, maxTimeoutSeconds: 600 }, OPTION]), PENDING);
    const { value, elapsed } = await drive(approveAndAgree(counting(), fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
  });

  it("maxTimeoutSeconds written 60.0 is the value 60: the exchange is bounded at 240 s", async () => {
    const text = JSON.stringify(AG.required).replace('"maxTimeoutSeconds":60', '"maxTimeoutSeconds":60.0');
    expect(text).toContain('"maxTimeoutSeconds":60.0');
    const fetch = challenging(Buffer.from(text, "utf8").toString("base64"), PENDING);
    const signer = counting();
    const { value, elapsed } = await drive(approveAndAgree(signer, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
    expect(signer.requests.length).toBe(1);
  });

  // The pairing's read applies the filter its build applies, which takes a maxTimeoutSeconds only as an integral number
  // of seconds from 1 to 2^53 - 1, so the agreement challenge offers no option the pairing can pay.
  it.each([["60.5"], ["0"], ['"60"'], ["9007199254740992"]])(
    "maxTimeoutSeconds written %s is not an integral number of seconds from 1 to 2^53 - 1: no option is offered",
    async (written) => {
      const text = JSON.stringify(AG.required).replace('"maxTimeoutSeconds":60', `"maxTimeoutSeconds":${written}`);
      const signer = counting();
      const out = await agree(A, AGREEMENT_URL, signer, challenging(Buffer.from(text, "utf8").toString("base64"), RECORDED));
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/no-payable-option" });
      expect(signer.requests.length).toBe(0);
    },
  );
});

// The caller's signal ends the agreement exchange at its next step. Before the agreement payment is sent, nothing is
// signed or sent and the result is agreement-failed; after, the result is agreement-pending with the payment as moved.
describe("the caller's signal", () => {
  it("a signal already aborted: agreement-failed with no request", async () => {
    const fetch = seller(row("BA1").input.agreement);
    const out = await agree(A, AGREEMENT_URL, counting(), fetch, { signal: AbortSignal.abort() });
    expect(code(out)).toBe("agreement-failed");
    expect(fetch.calls.length).toBe(0);
  });

  it("aborted while the unpaid request is unanswered: agreement-failed at that moment, nothing signed", async () => {
    const fetch = (() => new Promise<Response>(() => undefined)) as Fetch;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 3_000);
    const signer = counting();
    const { value, elapsed } = await drive(agree(A, AGREEMENT_URL, signer, fetch, { signal: controller.signal }));
    expect(code(value)).toBe("agreement-failed");
    expect(elapsed).toBe(3_000);
    expect(signer.requests.length).toBe(0);
  });

  it("aborted after the payment is sent, while it settles: agreement-pending with the payment kept as moved", async () => {
    const fetch = seller(row("BA3").input.agreement);
    const signer = counting();
    const first = await agree(A, AGREEMENT_URL, signer, fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    const controller = new AbortController();
    // The caller aborts while the second paid request is in flight, 2 s after the payment was first sent.
    const aborting = (async (url: string, init: Parameters<Fetch>[1]) => {
      const answer = await fetch(url, init);
      if (fetch.paid().length === 2) controller.abort();
      return answer;
    }) as Fetch;
    const { value, elapsed } = await drive(
      agree(A, AGREEMENT_URL, signer, aborting, { approved: first.approve, signal: controller.signal }),
    );
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(Number(row("BA3").input.agreement[1].retryAfter) * 1000);
    expect(fetch.paid().length).toBe(2);
    expect(signer.requests.length).toBe(1);
    expect(base64Json((value as Declined).moved!.signed)).toBe(fetch.paid()[0]);
  });

  it("aborted while waiting to send the payment again: agreement-pending at that moment, with the payment as moved", async () => {
    const fetch = seller(row("BA3").input.agreement);
    const signer = counting();
    const first = await agree(A, AGREEMENT_URL, signer, fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    const controller = new AbortController();
    // The caller aborts 1 s into the 2 s wait that follows the first 202.
    const aborting = (async (url: string, init: Parameters<Fetch>[1]) => {
      const answer = await fetch(url, init);
      if (fetch.paid().length === 1) setTimeout(() => controller.abort(), 1_000);
      return answer;
    }) as Fetch;
    const { value, elapsed } = await drive(
      agree(A, AGREEMENT_URL, signer, aborting, { approved: first.approve, signal: controller.signal }),
    );
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(1_000);
    expect(fetch.paid().length).toBe(1);
    expect(base64Json((value as Declined).moved!.signed)).toBe(fetch.paid()[0]);
  });

  it("through transact: an aborted signal ends the exchange before the agreement is signed, and the payment is never signed", async () => {
    const fetch = seller(row("BA1").input.agreement);
    const signer = counting();
    const first = await transact(D, withAgreement(AGREEMENT_URL), signer, fetch);
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    const out = await transact(D, withAgreement(AGREEMENT_URL), signer, fetch, {
      approved: first.approve,
      signal: AbortSignal.abort(),
    });
    expect(code(out)).toBe("agreement-failed");
    expect(signer.requests.length).toBe(0);
    expect(fetch.paid().length).toBe(0);
  });

  it("through transact: a signal that is not an AbortSignal is declined before any fetch", async () => {
    const fetch = seller([]);
    const out = await transact(D, withAgreement(AGREEMENT_URL), counting(), fetch, {
      signal: {} as unknown as AbortSignal,
    });
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect(fetch.calls.length).toBe(0);
  });
});

// Each header value the gate reads (retry-after, content-length and content-encoding, at the ATR's GET and at the
// agreement URL's) loses its leading and trailing HTTP whitespace, which the Fetch standard names as tab, LF, CR and
// space and removes from a header value; any other character stays, and the value is read with it. Each of the 256
// characters a header value decodes to (U+0000-U+00FF) is put on both sides of a value, in an answer whose headers give
// the value as written. The expected answers are this rule's, with RFC 9110's delay-seconds for retry-after (one to
// nine digits here, at least 1 s; 2 s for any other value) and the bounds the gate states: 1 MiB for the ATR (B12),
// 64 KiB for the receipt.
describe("a header value read without its surrounding HTTP whitespace", () => {
  const CHARACTERS = Array.from({ length: 256 }, (_, c) => String.fromCharCode(c));
  const HTTP_WHITESPACE = ["\t", "\n", "\r", " "];
  /** `inner` with `c` on both sides, as the rule reads it. */
  const ruled = (c: string, inner: string): string => (HTTP_WHITESPACE.includes(c) ? inner : c + inner + c);
  const label = (c: string): string => `U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
  /** An answer whose headers give each value as written; a Headers object refuses some of these characters. */
  function answer(status: number, headers: Record<string, string>, body: BodyInit | null = null): Response {
    const real = new Response(body, { status });
    const get = (name: string): string | null => headers[name.toLowerCase()] ?? null;
    return { status, type: real.type, body: real.body, headers: { get } } as unknown as Response;
  }
  const RECEIPT = JSON.stringify(AG.receipt);
  const ATR_BOUND: number = row("B12").input.bodyLength;
  const RECEIPT_BOUND = 64 * 1024;
  const over = (value: string, bound: number): boolean => /^[0-9]+$/.test(value) && Number(value) > bound;
  const outcome = (out: unknown): string => (isDeclined(out) ? out.decline.detail : "read");

  it("retry-after: the wait after a 202 is the rule's, for each character around the digit 5", async () => {
    const want: [string, number][] = [];
    const got: [string, number][] = [];
    for (const c of CHARACTERS) {
      const value = ruled(c, "5");
      const seconds = /^[0-9]{1,9}$/.test(value) ? Math.max(1, Number(value)) : 2;
      want.push([label(c), Math.min(seconds * 1000, EXCHANGE_MS)]);
      const paidAt: number[] = [];
      const fetch = (async (_url: string, init: Parameters<Fetch>[1]) => {
        if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
          return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
        }
        paidAt.push(Date.now());
        return paidAt.length === 1 ? answer(202, { "retry-after": c + "5" + c }) : answer(200, {}, RECEIPT);
      }) as Fetch;
      await drive(approveAndAgree(counting(), fetch));
      got.push([label(c), (paidAt[1] ?? Date.now()) - paidAt[0]!]);
    }
    expect(got).toEqual(want);
  });

  it("content-length: a declared length over the bound is read by the rule, for each character around it, at both GETs", async () => {
    const want: [string, string, string][] = [];
    const got: [string, string, string][] = [];
    for (const c of CHARACTERS) {
      const atrLength = String(ATR_BOUND + 1);
      const receiptLength = String(RECEIPT_BOUND + 1);
      want.push([
        label(c),
        over(ruled(c, atrLength), ATR_BOUND) ? `The ATR is larger than ${ATR_BOUND} bytes.` : "read",
        over(ruled(c, receiptLength), RECEIPT_BOUND) ? "The agreement receipt is larger than 64 KiB." : "read",
      ]);
      const atr = (async () => answer(200, { "content-length": c + atrLength + c }, new Uint8Array(A))) as Fetch;
      const receipt = (async () => answer(200, { "content-length": c + receiptLength + c }, RECEIPT)) as Fetch;
      got.push([
        label(c),
        outcome(await confirm(D, exactEip3009, ACCOUNT, atr)),
        outcome(await agree(A, AGREEMENT_URL, counting(), receipt)),
      ]);
    }
    expect(got).toEqual(want);
  });

  it("content-encoding: identity is read by the rule, for each character around it, at both GETs", async () => {
    const want: [string, string, string][] = [];
    const got: [string, string, string][] = [];
    for (const c of CHARACTERS) {
      const identity = ["", "identity"].includes(ruled(c, "identity").toLowerCase());
      want.push([
        label(c),
        identity ? "read" : "The link served a content coding other than identity.",
        identity ? "read" : "The agreement URL served a content coding other than identity.",
      ]);
      const coded = { "content-encoding": c + "identity" + c };
      const atr = (async () => answer(200, coded, new Uint8Array(A))) as Fetch;
      const receipt = (async () => answer(200, coded, RECEIPT)) as Fetch;
      got.push([
        label(c),
        outcome(await confirm(D, exactEip3009, ACCOUNT, atr)),
        outcome(await agree(A, AGREEMENT_URL, counting(), receipt)),
      ]);
    }
    expect(got).toEqual(want);
  });
});
