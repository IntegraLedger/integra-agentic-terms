// The buyer gate's rows. Every expected value is read from @integraledger/lcp's vectors/buyer.json, except
// B18, whose source is written beside it.
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashTypedData, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { hash, type AtrHash } from "@integraledger/lcp";
import {
  exactEip3009,
  type Eip3009Payment,
  type Eip3009TypedData,
  type PaymentRequired,
  type PaymentRequirements,
} from "@integraledger/lcp/x402";
import {
  check,
  confirm,
  finish,
  transact,
  type Binding,
  type Declined,
  type Fetch,
  type Signer,
  type SigningRequest,
} from "../src/index.js";

const B = JSON.parse(
  readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/buyer.json", import.meta.url), "utf8"),
);
type Outcome = { decline: string; signCalls: number; fetches: number; detail: string; streamCancelled: boolean };
type Rows = {
  B1: { input: { hashOf: string }; expect: { h: AtrHash } };
  B2: { plant: boolean; expect: Outcome };
  B2b: { plant: boolean; input: { doc: PaymentRequired; servesHex: string }; expect: Outcome };
  B3: { input: { servesHex: string }; servedHash: string; expect: Outcome };
  B4: { input: { servesHex: string }; servedHash: string; expect: Outcome };
  B5: { input: { stubRead: { h: AtrHash } }; expect: { match: boolean; h: AtrHash; buildReceives: AtrHash } };
  B6: {
    input: { then: { finish: { signature: `0x${string}` } } };
    expect: {
      message: { from: string; to: string; value: string; validAfter: string; validBefore: string; nonce: string };
      digest: string;
      signature: `0x${string}`;
      signedNonce: AtrHash;
      recovers: string;
    };
  };
  B7: { expect: [{ h: AtrHash }, { decline: string }] };
  B8: {
    input: { runs: number };
    expect: { paymentIdentifierPattern: string; differsBetweenRuns: boolean };
  };
  B9: { input: { stubBound: "hashC" }; expect: Outcome };
  B10: { input: [unknown, { stubRead: { link: string } }]; expect: [Outcome, Outcome] };
  B11: { input: { fetch: unknown[] }; expect: Outcome };
  B12: { input: { bodyLength: number }; expect: Outcome };
  B13: { input: [{ bodyLength: number }, { contentLength: number }]; expect: Outcome };
  B14: { input: { advanceMs: number }; expect: Outcome };
  B15: { expect: Outcome };
  B16: { input: { accounts: string[] }; expect: Outcome };
  B17: { input: { stubBindingId: string }; expect: Outcome };
};
const row = <K extends keyof Rows>(name: K): Rows[K] => B.rows.find((r: { name: string }) => r.name === name);

const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const forViem = (td: Eip3009TypedData) => td as unknown as Parameters<typeof hashTypedData>[0];

const A = fromHex(B.fixed.A);
const C = fromHex(B.fixed.C);
const D: PaymentRequired = B.fixed.D;
const O: PaymentRequirements = D.accepts[0]!;
const ACCOUNT: string = B.fixed.account;
const HASH_A: AtrHash = row("B1").expect.h;
const LINK_A = `https://atr.seller.example/${HASH_A}`;
const binding: Binding = exactEip3009;

/** A fetch stub that counts its calls and records what it was given. */
type Stub = Fetch & { calls: { url: string; init: Parameters<Fetch>[1] }[] };
function stub(answer: (init: Parameters<Fetch>[1]) => Promise<Response> | Response): Stub {
  const calls: Stub["calls"] = [];
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    calls.push({ url, init });
    return answer(init);
  }) as Stub;
  f.calls = calls;
  return f;
}
const serving = (bytes: Uint8Array): Stub => stub(() => new Response(new Uint8Array(bytes), { status: 200 }));

/**
 * A Response-shaped answer whose body is a stream of the given chunk sizes that stays open after the last one, as a
 * body still arriving would. Its cancellation is observed.
 */
function streamed(sizes: readonly number[], contentLength?: string) {
  const seen = { cancelled: false, pulled: 0 };
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        const size = sizes[seen.pulled];
        if (size === undefined) return new Promise<void>(() => undefined);
        seen.pulled++;
        controller.enqueue(new Uint8Array(size));
      },
      cancel() {
        seen.cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const headers = new Headers(contentLength === undefined ? {} : { "content-length": contentLength });
  return { seen, response: { status: 200, headers, body } as unknown as Response };
}

/** A signer over the published Anvil key that counts its calls. */
type Counting = Signer & { requests: SigningRequest[] };
function counting(account = ACCOUNT): Counting {
  const key = privateKeyToAccount(B.fixed.payerKey);
  const requests: SigningRequest[] = [];
  return {
    account,
    requests,
    async sign(request) {
      requests.push(request);
      return key.signTypedData(forViem(typedDataOf(request)));
    },
  };
}

/** The typed data of an EIP-712 signing request. */
function typedDataOf(request: SigningRequest | null): Eip3009TypedData {
  if (request === null || request.kind !== "eip712") throw new Error("not an EIP-712 request");
  return request.typedData as Eip3009TypedData;
}
/** The signed payment as an x402 payment. */
const x402 = (signed: unknown) => signed as Eip3009Payment;

const code = (r: unknown): string | undefined => (r as Declined).decline?.code;
const isDeclined = (r: unknown): r is Declined => typeof r === "object" && r !== null && "decline" in r;

function withExtension(doc: PaymentRequired, id: string, ext: { info: unknown; schema: unknown }): PaymentRequired {
  return { ...doc, extensions: { ...doc.extensions, [id]: ext } } as PaymentRequired;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  vi.setSystemTime(B.fixed.now * 1000);
});
afterEach(() => {
  vi.useRealTimers();
});

describe("fixed inputs", () => {
  it("D is what the binding's advertise writes for hash(A), A's link and O", () => {
    const base: PaymentRequired = { x402Version: 2, resource: D.resource, accepts: [O] };
    expect(exactEip3009.advertise(base, HASH_A, LINK_A, O)).toEqual(D);
  });

  it("C is A with byte 124 changed from 0x30 to 0x31", () => {
    expect(A.length).toBe(138);
    expect(A[124]).toBe(0x30);
    const c = A.slice();
    c[124] = 0x31;
    expect(c).toEqual(C);
  });
});

describe("buyer rows", () => {
  it("B1: hash(A), and confirm returns it for the bytes it served", async () => {
    expect(await hash(A)).toBe(row("B1").expect.h);
    const r = await confirm(D, binding, ACCOUNT, serving(A));
    expect(isDeclined(r)).toBe(false);
    if (isDeclined(r)) return;
    expect(r.h).toBe(row("B1").expect.h);
    expect(r.bytes).toEqual(A);
  });

  it("B2 (the plant): the link serves C; the gate declines and never signs", async () => {
    const r = row("B2");
    expect(r.plant).toBe(true);
    expect(await hash(C)).toBe(B.fixed.hashC);
    const signer = counting();
    expect(code(await transact(D, binding, signer, serving(C)))).toBe(r.expect.decline);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    const confirmed = await confirm(D, binding, ACCOUNT, serving(C));
    expect(code(confirmed)).toBe(r.expect.decline);
    expect(confirmed).not.toHaveProperty("request");
  });

  it("B2b (the core's plant): D advertises the core's V1 hash and the link serves V6's bytes", async () => {
    const r = row("B2b");
    const signer = counting();
    const fetch = serving(fromHex(r.input.servesHex));
    expect(code(await transact(r.input.doc, binding, signer, fetch))).toBe(r.expect.decline);
    expect(signer.requests.length).toBe(r.expect.signCalls);
    expect(fetch.calls.length).toBe(1);
  });

  it.each(["B3", "B4"] as const)("%s: a re-serialised ATR is not the ATR", async (name) => {
    const r = row(name);
    const served = fromHex(r.input.servesHex);
    expect(await hash(served)).toBe(r.servedHash);
    const signer = counting();
    expect(code(await transact(D, binding, signer, serving(served)))).toBe(r.expect.decline);
    expect(signer.requests.length).toBe(r.expect.signCalls);
  });

  it("B5: an upper-case advertised hash matches by decoded bytes; build receives the lowercase computed hash", async () => {
    const r = row("B5");
    const real = exactEip3009.read(D);
    if ("refused" in real) throw new Error(real.code);
    const received: string[] = [];
    const stubbed: Binding = {
      ...exactEip3009,
      read: () => ({ ...real, h: r.input.stubRead.h }),
      build: async (choice: Parameters<typeof exactEip3009.build>[0], h: AtrHash) => {
        received.push(h);
        return exactEip3009.build(choice, h);
      },
    };
    const out = await confirm(D, stubbed, ACCOUNT, serving(A));
    expect(isDeclined(out)).toBe(!r.expect.match);
    if (isDeclined(out)) return;
    expect(out.h).toBe(r.expect.h);
    expect(received).toEqual([r.expect.buildReceives]);
  });

  it("B6: confirm builds the authorization with nonce hash(A); finish binds the signature", async () => {
    const r = row("B6");
    const confirmed = await confirm(D, binding, ACCOUNT, serving(A));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
    const typedData = typedDataOf(confirmed.request);
    expect(confirmed.request?.kind).toBe("eip712");
    const m = r.expect.message;
    expect(typedData.message).toEqual({
      from: m.from,
      to: m.to,
      value: BigInt(m.value),
      validAfter: BigInt(m.validAfter),
      validBefore: BigInt(m.validBefore),
      nonce: m.nonce,
    });
    expect(hashTypedData(forViem(typedData))).toBe(r.expect.digest);

    const done = await finish(fromHex(B.fixed.A), confirmed.chosen, r.input.then.finish.signature, binding);
    if (isDeclined(done) || !("signed" in done)) throw new Error("not signed");
    const signed = done.signed as Eip3009Payment;
    expect(signed.payload.authorization.nonce).toBe(r.expect.signedNonce);
    expect(signed.payload.signature).toBe(r.expect.signature);
    expect(done.h).toBe(r.expect.signedNonce);
    expect(await recoverTypedDataAddress({ ...forViem(typedData), signature: r.expect.signature })).toBe(
      r.expect.recovers,
    );

    const signer = counting();
    const whole = await transact(D, binding, signer, serving(A));
    if (isDeclined(whole)) throw new Error(whole.decline.code);
    if ("approve" in whole) throw new Error("an agreement payment to approve");
    expect(signer.requests.length).toBe(1);
    expect((whole.signed as Eip3009Payment).payload.signature).toBe(r.expect.signature);
    expect(whole.bytes).toEqual(A);
    expect(whole.h).toBe(r.expect.signedNonce);
  });

  it("B7: check confirms the B6 payment against A, and declines it against C", async () => {
    const r = row("B7");
    const whole = await transact(D, binding, counting(), serving(A));
    if (isDeclined(whole)) throw new Error(whole.decline.code);
    if ("approve" in whole) throw new Error("an agreement payment to approve");
    expect(await check(A, whole.signed, binding)).toEqual({ h: r.expect[0].h });
    expect(code(await check(C, whole.signed, binding))).toBe(r.expect[1].decline);
  });

  it("B8: an advertised payment-identifier gains a fresh 32-character id; none is added unadvertised", async () => {
    const r = row("B8");
    const doc = withExtension(D, "payment-identifier", { info: {}, schema: {} });
    const ids: string[] = [];
    for (let i = 0; i < r.input.runs; i++) {
      const out = await transact(doc, binding, counting(), serving(A));
      if (isDeclined(out)) throw new Error(out.decline.code);
      if ("approve" in out) throw new Error("an agreement payment to approve");
      const info = x402(out.signed).extensions?.["payment-identifier"]?.info as { id?: string };
      expect(info.id).toMatch(new RegExp(r.expect.paymentIdentifierPattern));
      ids.push(info.id!);
      expect(x402(out.signed).extensions?.["legalContext"]).toEqual(D.extensions?.["legalContext"]);
    }
    expect(ids[0] !== ids[1]).toBe(r.expect.differsBetweenRuns);
    expect(doc.extensions?.["payment-identifier"]).toEqual({ info: {}, schema: {} });

    const plain = await transact(D, binding, counting(), serving(A));
    if (isDeclined(plain)) throw new Error(plain.decline.code);
    if ("approve" in plain) throw new Error("an agreement payment to approve");
    expect(x402(plain.signed).extensions).not.toHaveProperty("payment-identifier");
  });

  it("B9: a payment whose signed value is another hash is not returned", async () => {
    const r = row("B9");
    const stubbed: Binding = { ...exactEip3009, bound: async () => B.fixed[r.input.stubBound] };
    const signer = counting();
    const out = await transact(D, stubbed, signer, serving(A));
    expect(code(out)).toBe(r.expect.decline);
    expect(out).not.toHaveProperty("signed");
    expect(signer.requests.length).toBe(r.expect.signCalls);
  });

  it("B10: an http link is declined before any fetch", async () => {
    const r = row("B10");
    const httpLink = LINK_A.replace("https://", "http://");
    const legalContext = D.extensions!["legalContext"]!;
    const httpDoc = withExtension(D, "legalContext", {
      ...legalContext,
      info: { ...(legalContext.info as object), legalContextUrl: httpLink },
    });
    const first = serving(A);
    const out = await confirm(httpDoc, binding, ACCOUNT, first);
    expect(code(out)).toBe(r.expect[0].decline);
    expect((out as Declined).decline.detail).toBe(r.expect[0].detail);
    expect(first.calls.length).toBe(r.expect[0].fetches);

    const real = exactEip3009.read(D);
    if ("refused" in real) throw new Error(real.code);
    const stubbed: Binding = { ...exactEip3009, read: () => ({ ...real, link: r.input[1].stubRead.link }) };
    const second = serving(A);
    expect(code(await confirm(D, stubbed, ACCOUNT, second))).toBe(r.expect[1].decline);
    expect(second.calls.length).toBe(r.expect[1].fetches);
  });

  // The https-link rule, over the shared rows of core-vectors.json: every accepted link is fetched, every refused one
  // is link-not-https before any fetch.
  const LINKS: { name: string; case: string; link: string; accept: boolean; refusedAs: string }[] = JSON.parse(
    readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/core-vectors.json", import.meta.url), "utf8"),
  ).links.rows;
  it.each(LINKS.map((r) => [r.name, r.case, r] as const))("the https-link rule, %s (%s)", async (_name, _case, r) => {
    const real = exactEip3009.read(D);
    if ("refused" in real) throw new Error(real.code);
    const stubbed: Binding = { ...exactEip3009, read: () => ({ ...real, link: r.link }) };
    const fetch = serving(A);
    const out = await confirm(D, stubbed, ACCOUNT, fetch);
    if (r.accept) {
      expect(fetch.calls.map((c) => c.url)).toEqual([r.link]);
    } else {
      expect(out).toEqual({ decline: { code: "link-not-https", detail: `x402/${r.refusedAs}` } });
      expect(fetch.calls.length).toBe(0);
    }
  });

  // A link the protocol package's reading refuses is offer-unreadable, its detail that package's own code.
  it.each([
    ["http://atr.seller.example/x", "x402/link-not-https"],
    ["https://u@atr.seller.example/x", "x402/legal-context-malformed"],
    ["not a url", "x402/legal-context-malformed"],
    [`https://atr.seller.example/${"a".repeat(2049 - "https://atr.seller.example/".length)}`, "x402/legal-context-malformed"],
  ])("a document whose link is %s is offer-unreadable with detail %s", async (link, detail) => {
    const legalContext = D.extensions!["legalContext"]!;
    const doc = withExtension(D, "legalContext", { ...legalContext, info: { ...(legalContext.info as object), legalContextUrl: link } });
    const fetch = serving(A);
    expect(await confirm(doc, binding, ACCOUNT, fetch)).toEqual({ decline: { code: "offer-unreadable", detail } });
    expect(fetch.calls.length).toBe(0);
  });

  it("B11: a redirect, a 404 or a rejected fetch is unfetchable, and nothing is signed", async () => {
    const r = row("B11");
    const answers = [
      () => new Response(null, { status: 302, headers: { location: LINK_A } }),
      () => new Response("not here", { status: 404 }),
      () => Promise.reject(new TypeError("fetch failed")),
    ];
    expect(answers.length).toBe(r.input.fetch.length);
    for (const answer of answers) {
      const signer = counting();
      const fetch = stub(answer);
      expect(code(await transact(D, binding, signer, fetch))).toBe(r.expect.decline);
      expect(signer.requests.length).toBe(r.expect.signCalls);
      expect(fetch.calls.length).toBe(1);
      expect(fetch.calls[0]!.url).toBe(LINK_A);
      expect(fetch.calls[0]!.init.method).toBe("GET");
      expect(fetch.calls[0]!.init.redirect).toBe("manual");
      expect(fetch.calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it("B12: a body of exactly 1 MiB is read and hashed", async () => {
    const r = row("B12");
    expect(code(await confirm(D, binding, ACCOUNT, serving(new Uint8Array(r.input.bodyLength))))).toBe(
      r.expect.decline,
    );
  });

  it("B13: one byte over 1 MiB, streamed or declared, is too large and the stream is cancelled", async () => {
    const r = row("B13");
    const over = r.input[0].bodyLength;
    const sizes = [...Array<number>(Math.floor(over / 65_536)).fill(65_536), over % 65_536];
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(over);
    const whole = streamed(sizes);
    const declared = streamed([1], String(r.input[1].contentLength));
    for (const s of [whole, declared]) {
      const signer = counting();
      expect(code(await transact(D, binding, signer, stub(() => s.response)))).toBe(r.expect.decline);
      expect(s.seen.cancelled).toBe(r.expect.streamCancelled);
      expect(signer.requests.length).toBe(r.expect.signCalls);
    }
    expect(whole.seen.pulled).toBe(sizes.length);
    expect(declared.seen.pulled).toBe(0);
  });

  it("B14: a link that never answers is unfetchable at 10 000 ms", async () => {
    const r = row("B14");
    const fetch = stub(() => new Promise<Response>(() => undefined));
    let settled: unknown;
    const pending = confirm(D, binding, ACCOUNT, fetch).then((v) => (settled = v));
    await vi.advanceTimersByTimeAsync(r.input.advanceMs - 1);
    expect(settled).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await pending;
    expect(code(settled)).toBe(r.expect.decline);
    expect(fetch.calls[0]!.init.signal.aborted).toBe(true);
  });

  it("B14: the same deadline covers a body that never ends", async () => {
    const r = row("B14");
    const body = new ReadableStream<Uint8Array>({ pull: () => new Promise<void>(() => undefined) });
    const fetch = stub(() => ({ status: 200, headers: new Headers(), body }) as unknown as Response);
    const pending = confirm(D, binding, ACCOUNT, fetch);
    await vi.advanceTimersByTimeAsync(r.input.advanceMs);
    expect(code(await pending)).toBe(r.expect.decline);
  });

  it("B15: a signer that rejects or throws is signer-failed", async () => {
    const r = row("B15");
    const rejects: Signer = { account: ACCOUNT, sign: () => Promise.reject(new Error("user declined")) };
    const throws: Signer = {
      account: ACCOUNT,
      sign: () => {
        throw new Error("no wallet");
      },
    };
    expect(code(await transact(D, binding, rejects, serving(A)))).toBe(r.expect.decline);
    expect(code(await transact(D, binding, throws, serving(A)))).toBe(r.expect.decline);
  });

  it("B16: an account on no offered chain, or not an EVM account, has no payable option; nothing is fetched", async () => {
    const r = row("B16");
    for (const account of r.input.accounts) {
      const fetch = serving(A);
      expect(code(await confirm(D, binding, account, fetch))).toBe(r.expect.decline);
      expect(fetch.calls.length).toBe(r.expect.fetches);
    }
  });

  it("B17: a pairing with no buyer piece is refused by name", async () => {
    const r = row("B17");
    const stubbed = { ...exactEip3009, id: r.input.stubBindingId } as unknown as Binding;
    const fetch = serving(A);
    expect(code(await confirm(D, stubbed, ACCOUNT, fetch))).toBe(r.expect.decline);
    expect(code(await transact(D, stubbed, counting(), fetch))).toBe(r.expect.decline);
    expect(code(await finish(A, {} as never, "0x", stubbed))).toBe(r.expect.decline);
    expect(fetch.calls.length).toBe(0);
  });
});

// B18. Source: x402's specification on extensions, "it may append additional info but cannot delete or overwrite existing info", with
// the gate's `complete`, whose refusal is `signed-not-bound`, and the refusal code the Python gate uses.
describe("B18: an advertised payment-identifier that cannot take an id without overwriting", () => {
  it.each([
    ["an info that already holds id", { info: { id: "seller-chosen-id-0001" }, schema: {} }],
    ["an info that is not an object", { info: "x", schema: {} }],
    ["an extension with no info", { schema: {} }],
  ])("%s: signed-not-bound, and no payment is returned", async (_, ext) => {
    const doc = withExtension(D, "payment-identifier", ext as { info: unknown; schema: unknown });
    const signer = counting();
    const out = await transact(doc, binding, signer, serving(A));
    expect(out).toEqual({
      decline: { code: "signed-not-bound", detail: "x402/payment-identifier-unwritable" },
    });
    expect(signer.requests.length).toBe(1);
  });
});

describe("what a seller serves never throws", () => {
  const junk: [string, unknown][] = [
    ["null", null],
    ["a string", "402"],
    ["an array", [D]],
    ["version 1", { ...D, x402Version: 1 }],
    ["no extensions", { ...D, extensions: undefined }],
    ["accepts not an array", { ...D, accepts: {} }],
    ["an amount of 100 digits", { ...D, accepts: [{ ...O, amount: "9".repeat(100) }] }],
    ["an option with no extra", { ...D, accepts: [{ ...O, extra: undefined }] }],
  ];
  it.each(junk)("%s: a decline value", async (_, doc) => {
    const signer = counting();
    const out = await transact(doc, binding, signer, serving(A));
    expect(isDeclined(out)).toBe(true);
    expect(signer.requests.length).toBe(0);
  });

  it("a fetch that throws synchronously, or answers something that is not a Response, is unfetchable", async () => {
    const throwing = (() => {
      throw new Error("sync");
    }) as unknown as Fetch;
    expect(code(await confirm(D, binding, ACCOUNT, throwing))).toBe("atr-unfetchable");
    expect(code(await confirm(D, binding, ACCOUNT, stub(() => undefined as unknown as Response)))).toBe(
      "atr-unfetchable",
    );
    const strings = new ReadableStream({ start: (c) => (c.enqueue("text"), c.close()) });
    const odd = stub(() => ({ status: 200, headers: new Headers(), body: strings }) as unknown as Response);
    expect(code(await confirm(D, binding, ACCOUNT, odd))).toBe("atr-unfetchable");
  });

  it("finish and check decline what they cannot bind, without throwing", async () => {
    const whole = await transact(D, binding, counting(), serving(A));
    if (isDeclined(whole)) throw new Error(whole.decline.code);
    if ("approve" in whole) throw new Error("an agreement payment to approve");
    expect(code(await check(A, null, binding))).toBe("signed-not-bound");
    expect(code(await check(A, { ...x402(whole.signed), x402Version: 1 }, binding))).toBe("signed-not-bound");
    expect(code(await check(new Uint8Array(1_048_577), whole.signed, binding))).toBe("atr-too-large");
    expect(code(await finish(new Uint8Array(1_048_577), {} as never, "0x", binding))).toBe("atr-too-large");
    expect(code(await finish(A, null as never, "0x", binding))).toBe("offer-unreadable");
    const confirmed = await confirm(D, binding, ACCOUNT, serving(A));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
    expect(code(await finish(A, confirmed.chosen, "0x1234", binding))).toBe("signed-not-bound");
  });
});
