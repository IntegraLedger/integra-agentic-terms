// buyer.json's agreement rows (BA1-BA19) and coding rows (BE1, BE2), run from the rows' own data: every input,
// script and expected value is the row's or the file's `fixed`. A row with `input.approve` runs its entry twice: the
// first call returns the agreement payment for approval, whose option is compared with `expect.approval`, and signs
// nothing; with `approve: true` the second call carries that payment back as `approved`. A row with no `approve`
// declines, or pays no agreement, in its one call. A row's cases share its input and expect except where a case gives
// its own; a row runs through `transact`, or through each gate function its `entry` or `entries` names. A step's
// `paymentRequiredHeader` and `bodyHex` are sent as the fixture's text and bytes are, unchanged. BE1's bodies are the
// row's hex, served under each case's `Content-Encoding`; BE2's gzip and br bodies are written by node:zlib.
import { brotliCompressSync, gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { exactEip3009, type Eip3009Payment, type Eip3009TypedData, type PaymentRequired } from "@integraledger/lcp/x402";
import { agree, transact, type Binding, type Declined, type Fetch, type Signer, type SigningRequest } from "../src/index.js";
import { vectors } from "./support.js";

type Step = {
  status: number;
  paymentRequired?: string;
  paymentRequiredText?: string;
  paymentRequiredHeader?: string;
  retryAfter?: string;
  body?: string;
  bodyHex?: string;
  repeats?: boolean;
  contentEncoding?: string;
};
type Expect = {
  decline?: string;
  detail?: string;
  moved?: boolean;
  signCalls?: number;
  paidRequests?: number;
  fetches?: number;
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
type Input = {
  doc?: string;
  signer?: string;
  agreement?: Step[];
  agreementUrl?: string;
  approve?: boolean;
  advanceMs?: number;
  entry?: string;
  entries?: string[];
  atr?: string;
  serves?: string;
  inputs?: unknown;
};
type Case = Input & { case: string; contentEncoding?: string; bodyHex?: string; expect?: Expect };
type Row = { name: string; input: Input & { cases?: Case[] }; expect: Expect; control?: { expect: Expect } };

const B = vectors<{ rows: Row[]; fixed: Record<string, any> }>("buyer.json");
const row = (name: string): Row => B.rows.find((r) => r.name === name)!;
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const base64 = (text: string): string => Buffer.from(text, "utf8").toString("base64");
const forViem = (td: Eip3009TypedData) => td as unknown as Parameters<typeof hashTypedData>[0];
/** A value a row names by its path in the file, as `fixed.agreement.url`; any other string is the value itself. */
const named = (v: string): any => (v.startsWith("fixed.") ? v.split(".").reduce((o: any, k) => o[k], B) : v);

const A = fromHex(B.fixed.A);
const D: PaymentRequired = B.fixed.D;
const LINK_A: string = B.fixed.link;
const AG = B.fixed.agreement;
const SIGNATURES: Record<string, string> = { B6: (row("B6").expect as unknown as { signature: string }).signature };

/** The members a step, an input and an expect may hold: a row with any other is not run as written. */
const STEP_KEYS = ["status", "paymentRequired", "paymentRequiredText", "paymentRequiredHeader", "retryAfter", "body", "bodyHex", "repeats", "contentEncoding"];
const INPUT_KEYS = ["doc", "signer", "agreement", "agreementUrl", "approve", "advanceMs", "entry", "entries", "atr", "serves", "inputs"];
const EXPECT_KEYS = [
  "decline", "detail", "moved", "signCalls", "paidRequests", "fetches", "agreementFetches", "order", "approval",
  "agreementMessage", "agreementDigest", "agreementSignature", "paymentSignature", "signed", "receipt", "agreement",
  "requestHeaders",
];

/** The x402/EVM binding as a pairing with no public proof, whose read also gives the agreement URL `url`, if any. */
function noPublicProof(url: string | undefined): Binding {
  const real = exactEip3009.read(D);
  if ("refused" in real) throw new Error(real.code);
  const read = url === undefined ? real : { ...real, agreement: url };
  return { ...exactEip3009, pattern: { ...exactEip3009.pattern, publicProof: false }, read: () => read };
}

/** D with the agreement URL in its legal context after `legalContextUrl`, read through the public-proof pairing. */
function mixed(): PaymentRequired {
  const lc = D.extensions!["legalContext"]!;
  return { ...D, extensions: { ...D.extensions, legalContext: { ...lc, info: { ...(lc.info as object), legalContextAgreementUrl: AG.url } } } };
}

/** The offer and binding a row's `doc` describes: BA6's reads D through the public-proof pairing itself, BA12's
 * through the stub whose read gives no agreement URL, and BA1's (or "as BA1", or none, for a row run through `agree`)
 * through the stub whose read gives `url`. A row whose `doc` is any other text is not run as written. */
function offerOf(doc: string | undefined, url: string): [PaymentRequired, Binding] {
  if (doc === row("BA6").input.doc) return [mixed(), exactEip3009 as Binding];
  if (doc === row("BA12").input.doc) return [D, noPublicProof(undefined)];
  if (doc === undefined || doc === "as BA1" || doc === row("BA1").input.doc) return [D, noPublicProof(url)];
  throw new Error(`no offer is described by the doc ${doc}`);
}

/** A body in `coding`, of the bytes given. */
function coded(coding: string | undefined, bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (coding === "gzip") return new Uint8Array(gzipSync(bytes));
  if (coding === "br") return new Uint8Array(brotliCompressSync(bytes));
  return new Uint8Array(bytes);
}

type Call = { url: string; init: Parameters<Fetch>[1] };
/** Serves `atr` at the ATR link and plays `script` at the agreement URL, one step per request, the last one repeating;
 * `bare` counts the 402 answers it sent with no PAYMENT-REQUIRED and the 200 answers with no body, which no row's step
 * asks for. */
function seller(script: readonly Step[], atr: Uint8Array = A): Fetch & { calls: Call[]; bare: number } {
  const calls: Call[] = [];
  let step = 0;
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    calls.push({ url, init });
    if (url === LINK_A) return new Response(new Uint8Array(atr), { status: 200 });
    const s = script[Math.min(step, script.length - 1)]!;
    if (!s.repeats) step++;
    const headers = new Headers();
    if (s.paymentRequired !== undefined) headers.set("payment-required", base64(JSON.stringify(AG[s.paymentRequired])));
    if (s.paymentRequiredText !== undefined) headers.set("payment-required", base64(AG[s.paymentRequiredText] as string));
    if (s.paymentRequiredHeader !== undefined) headers.set("payment-required", AG[s.paymentRequiredHeader] as string);
    if (s.retryAfter !== undefined) headers.set("retry-after", s.retryAfter);
    if (s.contentEncoding !== undefined) headers.set("content-encoding", s.contentEncoding);
    const text = s.body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(AG[s.body]));
    const bytes = s.bodyHex === undefined ? text : fromHex(AG[s.bodyHex] as string);
    if ((s.status === 402 && !headers.has("payment-required")) || (s.status === 200 && bytes === undefined)) f.bare++;
    return new Response(bytes === undefined ? null : coded(s.contentEncoding, bytes), { status: s.status, headers });
  }) as Fetch & { calls: Call[]; bare: number };
  f.calls = calls;
  f.bare = 0;
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

const reason = (r: unknown): { code?: string; detail?: string } => (r as Declined).decline ?? {};
const paidOf = (calls: Call[]): string[] =>
  calls.filter((c) => c.url !== LINK_A).flatMap((c) => (c.init.headers?.["PAYMENT-SIGNATURE"] ?? []) as string[]);

/** The row's exchange through `entry`: one call, or, with `approve`, the call that asks for approval and, when
 * approved, the second. */
async function exchange(name: string, input: Input, expected: Expect, entry = "transact") {
  const url = named(input.agreementUrl ?? "fixed.agreement.url") as string;
  const [doc, binding] = offerOf(input.doc, url);
  const fetch = seller(input.agreement ?? [], input.serves === undefined ? A : fromHex(B.fixed[input.serves]));
  const signer = counting();
  const given = input.inputs === undefined ? {} : { inputs: input.inputs as never };
  type Out = Awaited<ReturnType<typeof transact>> | Awaited<ReturnType<typeof agree>>;
  const call = (more: object): Promise<Out> =>
    entry === "agree"
      ? agree(input.atr === undefined ? A : fromHex(named(input.atr)), url, signer, fetch, { ...given, ...more })
      : entry === "transact"
        ? transact(doc, binding, signer, fetch, { ...given, ...more })
        : Promise.reject(new Error(`${name}: no entry ${entry}`));
  let { value: out, elapsed } = await drive(call({}));
  if (expected.approval !== undefined && !("approve" in out)) {
    throw new Error(`${name}: the agreement payment is returned for approval`);
  }
  if ("approve" in out) {
    expect(input.approve).toBeDefined();
    const { amount, asset, payTo, network } = out.approve.option;
    if (expected.approval !== undefined) expect({ amount, asset, payTo, network }).toEqual(expected.approval);
    expect(signer.requests.length).toBe(0);
    expect(paidOf(fetch.calls)).toEqual([]);
    if (input.approve === true) ({ value: out, elapsed } = await drive(call({ approved: out.approve })));
  }
  return { out, elapsed, fetch, signer };
}

/** Every expected value the row states, against what the exchange did. */
function compare(input: Input, e: Expect, run: Awaited<ReturnType<typeof exchange>>): void {
  const { out, elapsed, fetch, signer } = run;
  const agreementCalls = fetch.calls.filter((c) => c.url !== LINK_A);
  const paid = paidOf(fetch.calls);
  expect(fetch.bare).toBe(0);
  expect(reason(out).code).toBe(e.decline);
  if (e.detail !== undefined) expect(reason(out).detail).toBe(e.detail);
  if (e.moved !== undefined) expect((out as Declined).moved !== undefined).toBe(e.moved);
  if (e.signCalls !== undefined) expect(signer.requests.length).toBe(e.signCalls);
  if (e.paidRequests !== undefined) expect(paid.length).toBe(e.paidRequests);
  if (e.fetches !== undefined) expect(fetch.calls.length - agreementCalls.length).toBe(e.fetches);
  if (e.agreementFetches !== undefined) expect(agreementCalls.length).toBe(e.agreementFetches);
  if (input.advanceMs !== undefined) expect(elapsed).toBe(input.advanceMs);
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
  if (e.receipt !== undefined) expect((out as { agreement?: unknown }).agreement).toEqual(AG[e.receipt]);
  if (e.requestHeaders !== undefined) {
    for (const c of fetch.calls) {
      for (const [k, v] of Object.entries(e.requestHeaders)) {
        const sent = Object.entries(c.init.headers ?? {}).find(([name]) => name.toLowerCase() === k);
        expect(sent?.[1]).toBe(v);
      }
    }
  }
}

type Run = { case: string; entry: string; input: Input; expect: Expect };
/** Each run a row asks for: every case, or the row itself, through every entry it names. */
function runsOf(r: Row): Run[] {
  const { cases, ...shared } = r.input;
  return (cases ?? [{ case: r.name }]).flatMap(({ case: label, expect: own, ...given }) => {
    const input: Input = { ...shared, ...given };
    const entries = input.entries ?? [input.entry ?? "transact"];
    return entries.map((entry) => ({ case: label, entry, input, expect: { ...r.expect, ...own } }));
  });
}

/** Runs one of a row's runs, once its members are found to be those this runner reads. */
async function play(name: string, run: Run): Promise<void> {
  const where = `${name}, ${run.case}, through ${run.entry}`;
  for (const k of Object.keys(run.input)) expect(INPUT_KEYS, `${where}: input ${k}`).toContain(k);
  for (const k of Object.keys(run.expect)) expect(EXPECT_KEYS, `${where}: expect ${k}`).toContain(k);
  for (const s of run.input.agreement ?? []) for (const k of Object.keys(s)) expect(STEP_KEYS, `${where}: step ${k}`).toContain(k);
  expect(run.input.signer, `${where}: signer`).toBe("counting");
  try {
    compare(run.input, run.expect, await exchange(name, run.input, run.expect, run.entry));
  } catch (err) {
    throw new Error(`${where}: ${(err as Error).message}`);
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

  it("the file holds BA1 to BA19", () => {
    expect(rows.map((r) => r.name)).toEqual(Array.from({ length: 19 }, (_, i) => `BA${i + 1}`));
  });

  for (const r of rows) {
    it(`${r.name}`, async () => {
      for (const run of runsOf(r)) await play(r.name, run);
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
      expect(reason(out).code).toBe(BE1.expect.decline);
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
  for (const run of runsOf(BE2)) {
    it(`BE2 ${run.case}`, async () => {
      await play("BE2", run);
    });
  }
});
