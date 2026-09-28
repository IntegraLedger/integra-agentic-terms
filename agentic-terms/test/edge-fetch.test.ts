// The gate and the agreement exchange over a fetch that behaves as the Cloudflare Workers runtime's does: it refuses
// `redirect: "error"` with the runtime's own TypeError, and with `redirect: "manual"` it answers a redirect as the 3xx
// itself, or, as browsers do, as a response of type "opaqueredirect" and status 0. The expected outcomes are
// buyer.json's rows B11 (a redirect is `atr-unfetchable`, and nothing is signed) and BA1 (the agreement exchange), and
// the agreement exchange as the Python gate runs it (`follow_redirects=False`): a redirect from the agreement URL, before
// or after the payment is sent, is `agreement-failed`, and after it the signed payment is kept as `moved`.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { AtrHash } from "@integraledger/lcp";
import { exactEip3009, type PaymentRequired } from "@integraledger/lcp/x402";
import { agree, transact, type Binding, type Declined, type Fetch, type SigningRequest } from "../src/index.js";
import { counting, fromHex, vectors } from "./support.js";

type Row = { name: string; input: Record<string, unknown>; expect: Record<string, unknown> };
type Script = { status: number; paymentRequired?: string; retryAfter?: string; body?: string };
const B = vectors<{ rows: Row[]; fixed: Record<string, any> }>("buyer.json");
const row = (name: string): Row => B.rows.find((r) => r.name === name)!;

const A = fromHex(B.fixed.A);
const D: PaymentRequired = B.fixed.D;
const ACCOUNT: string = B.fixed.account;
const H = row("B1").expect["h"] as AtrHash;
const LINK_A = `https://atr.seller.example/${H}`;
const AG = B.fixed.agreement;
const AGREEMENT_URL: string = AG.url;
const B11 = row("B11").expect as { decline: string; signCalls: number };

/** The Workers runtime's answer to `redirect: "error"`, verbatim. */
const WORKERS_REFUSAL =
  'Invalid redirect value, must be one of "follow" or "manual" ("error" won\'t be implemented since it does not make ' +
  'sense at the edge; use "manual" and check the response status code).';

type Call = { url: string; init: Parameters<Fetch>[1] };
type Edge = Fetch & { calls: Call[] };

/** A fetch with the Workers runtime's redirect handling in front of `serve`, recording every call it accepts. */
function workers(serve: (url: string, init: Parameters<Fetch>[1]) => Response): Edge {
  const calls: Call[] = [];
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    if ((init.redirect as string) === "error") throw new TypeError(WORKERS_REFUSAL);
    calls.push({ url, init });
    return serve(url, init);
  }) as Edge;
  f.calls = calls;
  return f;
}

/** A 3xx to `location`, as the Workers runtime returns it under `redirect: "manual"`. */
const redirectTo = (status: number, location: string) => () => new Response(null, { status, headers: { location } });

/** A response of type "opaqueredirect" and status 0, as a browser returns a redirect under `redirect: "manual"`. */
function opaqueRedirect(): Response {
  const r = Response.error();
  Object.defineProperty(r, "type", { value: "opaqueredirect" });
  return r;
}

/** Serves A at the ATR link and plays `script` at the agreement URL, one step per request, the last one repeating. */
function seller(script: readonly (Script | (() => Response))[]) {
  let step = 0;
  return (url: string): Response => {
    if (url === LINK_A) return new Response(new Uint8Array(A), { status: 200 });
    const s = script[Math.min(step++, script.length - 1)]!;
    if (typeof s === "function") return s();
    const headers = new Headers();
    if (s.paymentRequired !== undefined) {
      headers.set("payment-required", Buffer.from(JSON.stringify(AG[s.paymentRequired]), "utf8").toString("base64"));
    }
    if (s.retryAfter !== undefined) headers.set("retry-after", s.retryAfter);
    return new Response(s.body === undefined ? null : JSON.stringify(AG[s.body]), { status: s.status, headers });
  };
}

/** A signer over the vectors' published Anvil key that counts its calls. */
function signer() {
  const key = privateKeyToAccount(B.fixed.payerKey);
  return counting(ACCOUNT, async (r: SigningRequest) => {
    if (r.kind !== "eip712") throw new Error("not an EIP-712 request");
    return key.signTypedData(r.typedData as unknown as Parameters<typeof hashTypedData>[0]);
  });
}

/** The x402/EVM binding as a pairing with no public proof whose read also gives the agreement URL. */
function withAgreement(): Binding {
  const real = exactEip3009.read(D);
  if ("refused" in real) throw new Error(real.code);
  return { ...exactEip3009, pattern: { ...exactEip3009.pattern, publicProof: false }, read: () => ({ ...real, agreement: AGREEMENT_URL }) };
}

/** Runs `p` to its end under the fake clock, moving the clock to each pending timer until `p` settles. */
async function drive<T>(p: Promise<T>): Promise<T> {
  let done = false;
  let value: T | undefined;
  void p.then((v) => {
    done = true;
    value = v;
  });
  for (;;) {
    while (!done && vi.getTimerCount() === 0) await new Promise((resolve) => setImmediate(resolve));
    if (done) return value as T;
    await vi.advanceTimersToNextTimerAsync();
  }
}

const code = (r: unknown): string | undefined => (r as Declined).decline?.code;
const isDeclined = (r: unknown): r is Declined => typeof r === "object" && r !== null && "decline" in r;

function expectManual(calls: readonly Call[]): void {
  for (const c of calls) {
    expect(c.init.method).toBe("GET");
    expect(c.init.redirect).toBe("manual");
    expect(c.init.signal).toBeInstanceOf(AbortSignal);
  }
}

describe("the gate on a Workers fetch", () => {
  it("fetches the ATR, compares it and signs once", async () => {
    const fetch = workers(() => new Response(new Uint8Array(A), { status: 200 }));
    const s = signer();
    const out = await transact(D, exactEip3009, s, fetch);
    if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
    expect(out.h).toBe(H);
    expect(s.requests.length).toBe(1);
    expect(fetch.calls.map((c) => c.url)).toEqual([LINK_A]);
    expectManual(fetch.calls);
  });

  it.each([301, 302, 303, 307, 308])("B11: a %i redirect is atr-unfetchable, and nothing is signed", async (status) => {
    const fetch = workers(redirectTo(status, LINK_A));
    const s = signer();
    expect(code(await transact(D, exactEip3009, s, fetch))).toBe(B11.decline);
    expect(s.requests.length).toBe(B11.signCalls);
    expect(fetch.calls.length).toBe(1);
    expectManual(fetch.calls);
  });

  it("B11: an opaque redirect (type opaqueredirect, status 0) is atr-unfetchable, and nothing is signed", async () => {
    const fetch = workers(opaqueRedirect);
    const s = signer();
    expect(code(await transact(D, exactEip3009, s, fetch))).toBe(B11.decline);
    expect(s.requests.length).toBe(B11.signCalls);
    expect(fetch.calls.length).toBe(1);
  });
});

describe("the agreement exchange on a Workers fetch", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(B.fixed.now * 1000);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("BA1: the agreement is paid, then the full payment is signed", async () => {
    const r = row("BA1");
    const fetch = workers(seller(r.input["agreement"] as Script[]));
    const s = signer();
    const first = await drive(transact(D, withAgreement(), s, fetch));
    if (isDeclined(first) || !("approve" in first)) throw new Error("the agreement payment is returned for approval");
    expect(s.requests.length).toBe(0);
    const out = await drive(transact(D, withAgreement(), s, fetch, { approved: first.approve }));
    if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
    expect(s.requests.length).toBe(r.expect["signCalls"]);
    expect(fetch.calls.map((c) => c.url)).toEqual([LINK_A, AGREEMENT_URL, LINK_A, AGREEMENT_URL, AGREEMENT_URL]);
    expectManual(fetch.calls);
  });

  it.each([
    ["a 302", redirectTo(302, "https://elsewhere.example/")],
    ["an opaque redirect", opaqueRedirect],
  ])("a redirect from the agreement URL before payment is agreement-failed, and nothing is signed (%s)", async (_, answer) => {
    const fetch = workers(seller([answer]));
    const s = signer();
    expect(code(await drive(agree(A, AGREEMENT_URL, s, fetch)))).toBe("agreement-failed");
    expect(s.requests.length).toBe(0);
    expect(fetch.calls.length).toBe(1);
  });

  it.each([
    ["a 307", redirectTo(307, "https://elsewhere.example/")],
    ["an opaque redirect", opaqueRedirect],
  ])("a redirect answering the paid request is agreement-failed, and the payment is kept as moved (%s)", async (_, answer) => {
    const fetch = workers(seller([{ status: 402, paymentRequired: "required" }, answer, { status: 200, body: "receipt" }]));
    const s = signer();
    const first = await drive(agree(A, AGREEMENT_URL, s, fetch));
    if (!("approve" in first)) throw new Error("the agreement payment is returned for approval");
    const out = await drive(agree(A, AGREEMENT_URL, s, fetch, { approved: first.approve }));
    expect(code(out)).toBe("agreement-failed");
    expect((out as Declined).moved?.h).toBe(H);
    expect(s.requests.length).toBe(1);
    const paid = fetch.calls.map((c) => c.init.headers?.["PAYMENT-SIGNATURE"]).filter((p) => p !== undefined);
    expect(paid.length).toBe(1);
    expectManual(fetch.calls);
  });
});
