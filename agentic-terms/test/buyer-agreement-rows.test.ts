// buyer.json's agreement rows (BA1-BA11) and coding rows (BE1, BE2), run from the rows' own data: every input,
// script and expected value is the row's or the file's `fixed`. A row with `input.approve` runs `transact` twice: the
// first call returns the agreement payment for approval, whose option is compared with `expect.approval`, and signs
// nothing; with `approve: true` the second call carries that payment back as `approved`. A row with no `approve`
// declines, or pays no agreement, in its one call. BE1's bodies are the row's hex, served under each case's
// `Content-Encoding`; BE2's gzip and br bodies are written by node:zlib.
import { brotliCompressSync, gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { AtrHash } from "@integraledger/lcp";
import { exactEip3009, type Eip3009Payment, type Eip3009TypedData, type PaymentRequired } from "@integraledger/lcp/x402";
import { transact, type Binding, type Declined, type Fetch, type Signer, type SigningRequest } from "../src/index.js";
import { vectors } from "./support.js";

type Step = {
  status: number;
  paymentRequired?: string;
  paymentRequiredText?: string;
  retryAfter?: string;
  body?: string;
  repeats?: boolean;
  contentEncoding?: string;
};
type Expect = {
  decline?: string;
  signCalls?: number;
  paidRequests?: number;
  agreementFetches?: number;
  order?: string[];
  approval?: Record<string, string>;
  agreementMessage?: Record<string, string>;
  agreementDigest?: string;
  agreementSignature?: string;
  paymentSignature?: string;
  signed?: string;
  receipt?: string;
  agreement?: string;
  requestHeaders?: Record<string, string>;
};
type Row = {
  name: string;
  input: {
    doc?: string;
    agreement?: Step[];
    agreementUrl?: string;
    approve?: boolean;
    advanceMs?: number;
    cases?: { case: string; contentEncoding?: string; bodyHex?: string; agreement?: Step[]; expect?: Expect }[];
  };
  expect: Expect;
  control?: { expect: Expect };
};

const B = vectors<{ rows: Row[]; fixed: Record<string, any> }>("buyer.json");
const row = (name: string): Row => B.rows.find((r) => r.name === name)!;
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const base64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");
const forViem = (td: Eip3009TypedData) => td as unknown as Parameters<typeof hashTypedData>[0];

const A = fromHex(B.fixed.A);
const D: PaymentRequired = B.fixed.D;
const H: AtrHash = (row("B1").expect as unknown as { h: AtrHash }).h;
const LINK_A = `https://atr.seller.example/${H}`;
const AG = B.fixed.agreement;
const SIGNATURES: Record<string, string> = { B6: (row("B6").expect as unknown as { signature: string }).signature };

/** The x402/EVM binding as a pairing with no public proof, whose read also gives the agreement URL `url`. */
function withAgreement(url: string): Binding {
  const real = exactEip3009.read(D);
  if ("refused" in real) throw new Error(real.code);
  return { ...exactEip3009, pattern: { ...exactEip3009.pattern, publicProof: false }, read: () => ({ ...real, agreement: url }) };
}

/** D with the agreement URL in its legal context after `legalContextUrl`, read through the public-proof pairing. */
function mixed(): PaymentRequired {
  const lc = D.extensions!["legalContext"]!;
  return { ...D, extensions: { ...D.extensions, legalContext: { ...lc, info: { ...(lc.info as object), legalContextAgreementUrl: AG.url } } } };
}

/** A body in `coding`, of the bytes given. */
function coded(coding: string | undefined, bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (coding === "gzip") return new Uint8Array(gzipSync(bytes));
  if (coding === "br") return new Uint8Array(brotliCompressSync(bytes));
  return new Uint8Array(bytes);
}

type Call = { url: string; init: Parameters<Fetch>[1] };
/** Serves A at the ATR link and plays `script` at the agreement URL, one step per request, the last one repeating. */
function seller(script: readonly Step[]): Fetch & { calls: Call[] } {
  const calls: Call[] = [];
  let step = 0;
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    calls.push({ url, init });
    if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
    const s = script[Math.min(step, script.length - 1)]!;
    if (!s.repeats) step++;
    const headers = new Headers();
    if (s.paymentRequired !== undefined) headers.set("payment-required", base64(JSON.stringify(AG[s.paymentRequired])));
    if (s.paymentRequiredText !== undefined) headers.set("payment-required", base64(AG[s.paymentRequiredText] as string));
    if (s.retryAfter !== undefined) headers.set("retry-after", s.retryAfter);
    if (s.contentEncoding !== undefined) headers.set("content-encoding", s.contentEncoding);
    const body = s.body === undefined ? null : coded(s.contentEncoding, new TextEncoder().encode(JSON.stringify(AG[s.body])));
    return new Response(body, { status: s.status, headers });
  }) as Fetch & { calls: Call[] };
  f.calls = calls;
  return f;
}

type Counting = Signer & { requests: { kind: "eip712"; typedData: Eip3009TypedData }[] };
function counting(): Counting {
  const key = privateKeyToAccount(B.fixed.payerKey);
  const requests: Counting["requests"] = [];
  return {
    account: B.fixed.account,
    requests,
    async sign(request: SigningRequest) {
      const r = request as { kind: "eip712"; typedData: Eip3009TypedData };
      requests.push(r);
      return key.signTypedData(forViem(r.typedData));
    },
  };
}

/** Runs `p` to its end under the fake clock, and returns its value and the fake time that passed. */
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
const paidOf = (calls: Call[]): string[] =>
  calls.filter((c) => c.url !== LINK_A).flatMap((c) => (c.init.headers?.["PAYMENT-SIGNATURE"] ?? []) as string[]);

/** The row's exchange: one call, or, with `approve`, the call that asks for approval and, when approved, the second. */
async function exchange(r: Row, script: readonly Step[], expected: Expect) {
  const url = r.input.agreementUrl ?? AG.url;
  const [doc, binding] = r.name === "BA6" ? [mixed(), exactEip3009 as Binding] : [D, withAgreement(url)];
  const fetch = seller(script);
  const signer = counting();
  let { value: out, elapsed } = await drive(transact(doc, binding, signer, fetch));
  if (expected.approval !== undefined && !("approve" in out)) {
    throw new Error(`${r.name}: the agreement payment is returned for approval`);
  }
  if ("approve" in out) {
    expect(r.input.approve).toBeDefined();
    const { amount, asset, payTo, network } = out.approve.option;
    if (expected.approval !== undefined) expect({ amount, asset, payTo, network }).toEqual(expected.approval);
    expect(signer.requests.length).toBe(0);
    expect(paidOf(fetch.calls)).toEqual([]);
    if (r.input.approve === true) {
      ({ value: out, elapsed } = await drive(transact(doc, binding, signer, fetch, { approved: out.approve })));
    }
  }
  return { out, elapsed, fetch, signer };
}

/** Every expected value the row states, against what the exchange did. */
function compare(r: Row, e: Expect, run: Awaited<ReturnType<typeof exchange>>): void {
  const { out, elapsed, fetch, signer } = run;
  const agreementCalls = fetch.calls.filter((c) => c.url !== LINK_A);
  const paid = paidOf(fetch.calls);
  if (e.decline !== undefined) expect(code(out)).toBe(e.decline);
  else expect(code(out)).toBeUndefined();
  if (e.signCalls !== undefined) expect(signer.requests.length).toBe(e.signCalls);
  if (e.paidRequests !== undefined) expect(paid.length).toBe(e.paidRequests);
  if (e.agreementFetches !== undefined) expect(agreementCalls.length).toBe(e.agreementFetches);
  if (r.input.advanceMs !== undefined) expect(elapsed).toBe(r.input.advanceMs);
  if (e.order !== undefined) {
    const values = signer.requests.map((q) => q.typedData.message.value);
    expect(values).toEqual(e.order.map((o) => BigInt(o === "agreement" ? AG.option.amount : D.accepts[0]!.amount)));
  }
  const agreement = signer.requests[0]?.typedData;
  if (e.agreementMessage !== undefined) {
    const m = e.agreementMessage;
    expect(agreement!.message).toEqual({
      from: m.from,
      to: m.to,
      value: BigInt(m.value!),
      validAfter: BigInt(m.validAfter!),
      validBefore: BigInt(m.validBefore!),
      nonce: m.nonce,
    });
  }
  if (e.agreementDigest !== undefined) expect(hashTypedData(forViem(agreement!))).toBe(e.agreementDigest);
  if (e.agreementSignature !== undefined) {
    expect(new Set(paid).size).toBe(1);
    const sent = JSON.parse(Buffer.from(paid[0]!, "base64").toString("utf8")) as Eip3009Payment;
    expect(sent.payload.signature).toBe(e.agreementSignature);
  }
  const signed = (out as { signed?: Eip3009Payment }).signed;
  if (e.paymentSignature !== undefined) expect(signed?.payload.signature).toBe(SIGNATURES[e.paymentSignature]);
  if (e.signed !== undefined) expect(signed?.payload.signature).toBe(SIGNATURES[e.signed]);
  if (e.agreement !== undefined) expect((out as { agreement?: unknown }).agreement).toEqual(AG[e.agreement]);
  if (e.requestHeaders !== undefined) {
    for (const c of fetch.calls) {
      for (const [k, v] of Object.entries(e.requestHeaders)) {
        const sent = Object.entries(c.init.headers ?? {}).find(([name]) => name.toLowerCase() === k);
        expect(sent?.[1]).toBe(v);
      }
    }
  }
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  vi.setSystemTime(B.fixed.now * 1000);
});
afterEach(() => {
  vi.useRealTimers();
});

describe("buyer.json's agreement rows, through the gate's two calls", () => {
  const rows = B.rows.filter((r) => /^BA[0-9]+$/.test(r.name));

  it("the file holds BA1 to BA11", () => {
    expect(rows.map((r) => r.name)).toEqual(Array.from({ length: 11 }, (_, i) => `BA${i + 1}`));
  });

  for (const r of rows) {
    it(`${r.name}`, async () => {
      compare(r, r.expect, await exchange(r, r.input.agreement ?? [], r.expect));
    });
  }
});

describe("buyer.json's coding rows", () => {
  const BE1 = row("BE1");
  for (const c of BE1.input.cases!) {
    it(`BE1 ${c.case}: ${BE1.expect.decline}, nothing hashed or signed`, async () => {
      const calls: Call[] = [];
      const fetch = (async (url: string, init: Parameters<Fetch>[1]) => {
        calls.push({ url, init });
        return new Response(new Uint8Array(fromHex(c.bodyHex!)), { status: 200, headers: { "content-encoding": c.contentEncoding! } });
      }) as Fetch;
      const signer = counting();
      const out = await transact(D, exactEip3009, signer, fetch);
      expect(code(out)).toBe(BE1.expect.decline);
      expect(signer.requests.length).toBe(BE1.expect.signCalls);
      expect(calls.map((k) => k.init.headers)).toEqual([{ "Accept-Encoding": BE1.expect.requestHeaders!["accept-encoding"] }]);
    });
  }

  it("BE1 control: the same exchange answered in the identity coding is paid as B6", async () => {
    const e = BE1.control!.expect;
    const calls: Call[] = [];
    const fetch = (async (url: string, init: Parameters<Fetch>[1]) => {
      calls.push({ url, init });
      return new Response(new Uint8Array(A), { status: 200, headers: { "content-encoding": "identity" } });
    }) as Fetch;
    const signer = counting();
    const out = await transact(D, exactEip3009, signer, fetch);
    expect(signer.requests.length).toBe(e.signCalls);
    expect((out as { signed: Eip3009Payment }).signed.payload.signature).toBe(SIGNATURES[e.paymentSignature!]);
    expect(calls.map((k) => k.init.headers)).toEqual([{ "Accept-Encoding": e.requestHeaders!["accept-encoding"] }]);
  });

  const BE2 = row("BE2");
  for (const c of BE2.input.cases!) {
    it(`BE2 ${c.case}`, async () => {
      const r: Row = { name: "BE2", input: { ...BE2.input, agreement: c.agreement! }, expect: {} };
      const e = { ...BE2.expect, ...c.expect };
      compare(r, e, await exchange(r, c.agreement!, e));
    });
  }
});
