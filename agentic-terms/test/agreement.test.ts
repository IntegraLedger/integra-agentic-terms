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
  type AgreementReceipt,
  type Binding,
  type Declined,
  type Fetch,
  type Signer,
  type SigningRequest,
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
const LINK_A = `https://atr.seller.example/${H}`;
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
    expect(exactEip3009.advertise(base, hashC, `https://atr.seller.example/${hashC}`, OPTION)).toEqual(
      AG.requiredOtherHash,
    );
  });
});

describe("confirm", () => {
  it("returns the agreement URL the binding read, and none when it read none", async () => {
    const withUrl = await confirm(D, withAgreement(AGREEMENT_URL), ACCOUNT, seller([]));
    if (isDeclined(withUrl)) throw new Error(withUrl.decline.code);
    expect(withUrl.agreement).toBe(AGREEMENT_URL);
    const without = await confirm(D, exactEip3009, ACCOUNT, seller([]));
    if (isDeclined(without)) throw new Error(without.decline.code);
    expect(without).not.toHaveProperty("agreement");
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
    const { value: settled, elapsed } = await drive(transact(D, withAgreement(AGREEMENT_URL), signer, fetch));
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
    expect(fetch.calls.map((c) => c.url)).toEqual([LINK_A, AGREEMENT_URL, AGREEMENT_URL, AGREEMENT_URL]);
    expect(fetch.agreementCalls()[0]!.init.headers).toBeUndefined();
    for (const c of fetch.calls) {
      expect(c.init.method).toBe("GET");
      expect(c.init.redirect).toBe("manual");
      expect(c.init.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it("BA1: agree returns the receipt; an agreement signer, when given, signs the agreement", async () => {
    const r = row("BA1");
    const direct = seller(r.input.agreement);
    const { value } = await drive(agree(H, AGREEMENT_URL, counting(), direct, { bytes: A }));
    expect(value).toEqual({ receipt: AG[r.expect.receipt] as AgreementReceipt });

    const signer = counting();
    const agreementSigner = counting();
    const whole = await drive(
      transact(D, withAgreement(AGREEMENT_URL), signer, seller(r.input.agreement), { agreementSigner }),
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
    expect(code(await transact(D, withAgreement(AGREEMENT_URL), signer, fetch))).toBe(r.expect.decline);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect(fetch.paid().length).toBe(r.expect.paidRequests);

    const direct = counting();
    expect(code(await agree(H, AGREEMENT_URL, direct, seller(r.input.agreement), { bytes: A }))).toBe(r.expect.decline);
    expect(direct.requests.length).toBe(r.expect.signCalls);
  });

  it("BA3: a 202 that never becomes 200 is pending at the exchange bound; the agreement payment is kept, the full payment never signed", async () => {
    const r = row("BA3");
    const fetch = seller(r.input.agreement);
    const signer = counting();
    const { value, elapsed } = await drive(transact(D, withAgreement(AGREEMENT_URL), signer, fetch));
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

  it("BA3: the exchange bound runs from the payment's first sending, not from the signer's call", async () => {
    const r = row("BA3");
    const fetch = seller(r.input.agreement);
    const inner = counting();
    const slow: Signer = {
      account: ACCOUNT,
      sign: (request) => new Promise((resolve) => setTimeout(() => resolve(inner.sign(request)), 30_000)),
    };
    const { value, elapsed } = await drive(agree(H, AGREEMENT_URL, slow, fetch, { bytes: A }));
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
    const { value, elapsed } = await drive(transact(D, withAgreement(AGREEMENT_URL), signer, fetch));
    expect(code(value)).toBe("agreement-pending");
    expect(elapsed).toBe(EXCHANGE_MS);
    const start = B.fixed.now * 1000;
    expect(calls).toEqual([start, start + PAID_REQUEST_MS + 2000]);
    expect(signer.requests.length).toBe(1);
  });

  it("BA4: a receipt naming another ATR hash fails, and the full payment is never signed", async () => {
    const r = row("BA4");
    const signer = counting();
    expect(code(await transact(D, withAgreement(AGREEMENT_URL), signer, seller(r.input.agreement)))).toBe(
      r.expect.decline,
    );
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect(signer.requests[0]!.typedData.message.value).toBe(1n);
  });

  it("BA5: an http agreement URL is declined before any fetch of it", async () => {
    const r = row("BA5");
    const fetch = seller([]);
    const signer = counting();
    expect(code(await agree(H, r.input.agreementUrl, signer, fetch, { bytes: A }))).toBe(r.expect.decline);
    expect(fetch.calls.length).toBe(r.expect.agreementFetches);
    expect(signer.requests.length).toBe(r.expect.signCalls);

    const through = seller([]);
    const again = counting();
    expect(code(await transact(D, withAgreement(r.input.agreementUrl), again, through))).toBe(r.expect.decline);
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
      expect(await transact(D, withAgreement(url), signer, fetch)).toEqual({ decline: { code: "link-not-https", detail } });
      expect(fetch.agreementCalls().length).toBe(0);
      expect(signer.requests.length).toBe(0);
    }
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
    expect(fetch.agreementCalls().length).toBe(r.expect.agreementFetches);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect((out.signed as Eip3009Payment).payload.signature).toBe(row(r.expect.paymentSignature).expect.signature);
    expect(out).not.toHaveProperty("agreement");
  });

  it("BA7: transact returns the agreement's receipt beside the payment", async () => {
    const r = row("BA7");
    const { value: out } = await drive(transact(D, withAgreement(AGREEMENT_URL), counting(), seller(r.input.agreement)));
    if (isDeclined(out)) throw new Error(out.decline.code);
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
    const out = await agree(H, AGREEMENT_URL, signer, seller([{ status: 200, body: "receipt" }]), { bytes: A });
    expect(out).toEqual({ receipt: AG.receipt });
    expect(signer.requests.length).toBe(0);
  });

  it.each([
    ["an unpaid 404", [{ status: 404 }]],
    ["a 402 with no PAYMENT-REQUIRED", [{ status: 402 }]],
  ] as [string, Script[]][])("%s: agreement-failed, nothing signed", async (_, script) => {
    const signer = counting();
    expect(code(await agree(H, AGREEMENT_URL, signer, seller(script), { bytes: A }))).toBe("agreement-failed");
    expect(signer.requests.length).toBe(0);
  });

  it("an unpaid 202, another sending of the agreement still settling: agreement-pending, nothing signed", async () => {
    const signer = counting();
    const out = await agree(H, AGREEMENT_URL, signer, seller([{ status: 202, retryAfter: "2" }]), { bytes: A });
    expect(code(out)).toBe("agreement-pending");
    expect(out).not.toHaveProperty("moved");
    expect(signer.requests.length).toBe(0);
  });

  it("an answer the signer gives that does not complete the agreement payment: nothing is sent", async () => {
    const fetch = seller([{ status: 402, paymentRequired: "required" }]);
    const signer: Signer = { account: ACCOUNT, sign: async () => "0x00" };
    expect(code(await agree(H, AGREEMENT_URL, signer, fetch, { bytes: A }))).toBe("signed-not-bound");
    expect(fetch.paid().length).toBe(0);
  });

  it("a paid 402 re-challenge: agreement-failed after one signature, with the sent payment kept", async () => {
    const signer = counting();
    const script: Script[] = [
      { status: 402, paymentRequired: "required" },
      { status: 402, paymentRequired: "required" },
    ];
    const fetch = seller(script);
    const out = await agree(H, AGREEMENT_URL, signer, fetch, { bytes: A });
    expect(code(out)).toBe("agreement-failed");
    expect(signer.requests.length).toBe(1);
    expect(fetch.paid().length).toBe(1);
    expect(base64Json((out as Declined).moved!.signed)).toBe(fetch.paid()[0]);
  });

  it("a signer on no offered chain: no-payable-option, nothing signed", async () => {
    const signer = counting("eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const script: Script[] = [{ status: 402, paymentRequired: "required" }];
    expect(code(await agree(H, AGREEMENT_URL, signer, seller(script), { bytes: A }))).toBe("no-payable-option");
    expect(signer.requests.length).toBe(0);
  });

  // The unpaid request is bounded by the gate's deadline on each await, 10 s.
  it("an agreement URL that never answers fails at 10 s", async () => {
    const fetch = (() => new Promise<Response>(() => undefined)) as Fetch;
    const { value, elapsed } = await drive(agree(H, AGREEMENT_URL, counting(), fetch, { bytes: A }));
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
    const { value, elapsed } = await drive(agree(H, AGREEMENT_URL, signer, fetch, { bytes: A }));
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
    const { value } = await drive(agree(H, AGREEMENT_URL, signer, fetch, { bytes: A }));
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
    const { value } = await drive(agree(H, AGREEMENT_URL, signer, once(nested(CAP + 1)), { bytes: A }));
    expect(isDeclined(value) && value.decline).toEqual({
      code: "agreement-failed",
      detail: "The agreement URL answered 402 without a readable PAYMENT-REQUIRED.",
    });
    expect(signer.requests.length).toBe(0);
  });
  it("a challenge nested exactly to the cap is read and paid", async () => {
    const signer = counting();
    const { value } = await drive(agree(H, AGREEMENT_URL, signer, once(nested(CAP)), { bytes: A }));
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
    const { value } = await drive(agree(H, AGREEMENT_URL, signer, fetch, { bytes: A }));
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
    const { value } = await drive(transact(D, withAgreement(AGREEMENT_URL), signer, fetch));
    expect(code(value)).toBe("agreement-failed");
    expect(signer.requests.length).toBe(1);
    expect(base64Json((value as Declined).moved!.signed)).toBe(fetch.paid()[0]);
  });
});
