// What the breadth rows share: the vector files, the ATR bytes the vectors hash, a fetch stub, a counting signer, and
// the two rows every pairing adds: B2 (the plant) and B6 (build and sign).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import {
  check,
  confirm,
  finish,
  transact,
  type Binding,
  type Declined,
  type Fetch,
  type Inputs,
  type Presented,
  type Signature,
  type Signer,
  type SigningRequest,
  type TransactOptions,
} from "../src/index.js";

/** A vector file of `@integraledger/lcp`, as data of the shape the caller names. */
export function vectors<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
}

/** `abc`, whose SHA-256 is the vectors' H (FIPS 180-2); `abd`, one byte changed, for the plant. */
export const ABC = new TextEncoder().encode("abc");
export const ABD = new TextEncoder().encode("abd");
export const H: AtrHash = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
export const LINK = `https://atr.seller.example/${H}`;

export const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
export const toHex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString("hex")}`;

/** The agreement URL a `publicProof: false` pairing's offer names, and its receipt once the agreement is recorded. */
const AGREEMENT_BASE = "https://api.seller.example/agreement/";
export const AGREEMENT_URL = `${AGREEMENT_BASE}${H}`;
/** The agreement resource's receipt for `h`. */
export const receiptFor = (h: string) => ({ atrHash: h, agreed: true, network: "eip155:84532", transaction: `0x${"cd".repeat(32)}` });
export const RECEIPT = receiptFor(H);

/**
 * A fetch stub serving the bytes at every link, counting its calls; the agreement URL answers 200 with the receipt for
 * the served bytes' hash, as the agreement resource answers once the agreement is recorded.
 */
export type Stub = Fetch & { calls: number };
export function serving(bytes: Uint8Array): Stub {
  const f = (async (url: string) => {
    f.calls++;
    if (url === AGREEMENT_URL) {
      const h = `0x${createHash("sha256").update(bytes).digest("hex")}`;
      return new Response(JSON.stringify(receiptFor(h)), { status: 200 });
    }
    return new Response(new Uint8Array(bytes), { status: 200 });
  }) as unknown as Stub;
  f.calls = 0;
  return f;
}

/** A signer that records what it was handed and answers with `answer`. */
export type Counting = Signer & { requests: SigningRequest[] };
export function counting(account: string, answer: (r: SigningRequest) => Promise<Signature>): Counting {
  const requests: SigningRequest[] = [];
  return {
    account,
    requests,
    async sign(request) {
      requests.push(request);
      return answer(request);
    },
  };
}

/** Whether the pairing's payment is itself a public proof of the hash. */
export function isPublicProof(binding: Binding): boolean {
  return (binding as { pattern?: { publicProof?: unknown } }).pattern?.publicProof === true;
}

/**
 * The binding a seller's offer is read through: for a pairing whose payment is not a public proof, the offer also names
 * the agreement URL, as the seller's stack places it beside the carriers.
 */
export function offered(binding: Binding): Binding {
  if (isPublicProof(binding)) return binding;
  const b = binding as unknown as { read(doc: unknown): unknown };
  return {
    ...binding,
    read(doc: unknown) {
      const r = b.read(doc);
      return typeof r === "object" && r !== null && !("refused" in r) ? { ...r, agreement: AGREEMENT_URL } : r;
    },
  } as unknown as Binding;
}

/**
 * `transact` in its two calls: the first returns the agreement payment to approve, and the second is made with that
 * payment approved unchanged. A pairing that pays no agreement, or whose agreement is already recorded, finishes in the
 * first.
 */
export async function transactApproved(
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

export const isDeclined = (r: unknown): r is Declined => typeof r === "object" && r !== null && "decline" in r;
export const code = (r: unknown): string | undefined => (r as Declined).decline?.code;

export interface Pairing {
  binding: Binding;
  /** The seller's document as the pairing's `advertise` placed it, advertising H and LINK. */
  doc: unknown;
  account: string;
  inputs?: Inputs;
  /** The test signer's answer to the request the pairing builds: a key generated or published for tests only. */
  answer: (r: SigningRequest) => Promise<Signature>;
}

/** B2 for a pairing: the link serves `abd`; the gate declines hash-mismatch and never calls the signer. */
export async function plant(p: Pairing): Promise<void> {
  const signer = counting(p.account, p.answer);
  const binding = offered(p.binding);
  const out = await transact(p.doc, binding, signer, serving(ABD), { inputs: p.inputs ?? {} });
  expect(code(out)).toBe("hash-mismatch");
  expect(signer.requests.length).toBe(0);
  const confirmed = await confirm(p.doc, binding, p.account, serving(ABD), p.inputs);
  expect(code(confirmed)).toBe("hash-mismatch");
  expect(confirmed).not.toHaveProperty("request");
}

/**
 * B6 for a pairing: `confirm` over `abc` gives the request the pairing builds with H, which `inspect` checks against
 * the vectors; `finish` with the test signer's answer returns a payment whose bound hash is H; `transact` signs once;
 * `check` confirms that payment against `abc` and declines it against `abd`.
 */
export async function buildAndSign(
  p: Pairing,
  inspect: (request: SigningRequest) => void | Promise<void>,
): Promise<{ signed: Presented; request: SigningRequest }> {
  const binding = offered(p.binding);
  const confirmed = await confirm(p.doc, binding, p.account, serving(ABC), p.inputs);
  if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
  expect(confirmed.h).toBe(H);
  if (confirmed.request === null) throw new Error("nothing to sign");
  await inspect(confirmed.request);

  const chosen = JSON.parse(JSON.stringify(confirmed.chosen));
  const answers: Signature[] = [await p.answer(confirmed.request)];
  let done = await finish(ABC, chosen, answers[0]!, p.binding);
  while (!isDeclined(done) && "next" in done) {
    answers.push(await p.answer(done.next));
    done = await finish(ABC, chosen, answers, p.binding);
  }
  if (isDeclined(done)) throw new Error(`${done.decline.code}: ${done.decline.detail}`);
  expect(done.h).toBe(H);

  const signer = counting(p.account, p.answer);
  const whole = await transact(p.doc, binding, signer, serving(ABC), { inputs: p.inputs ?? {} });
  if (isDeclined(whole)) throw new Error(`${whole.decline.code}: ${whole.decline.detail}`);
  if ("approve" in whole) throw new Error("an agreement payment to approve");
  expect(signer.requests.length).toBe(answers.length);
  expect(whole.bytes).toEqual(ABC);
  expect(whole.agreement).toEqual(isPublicProof(p.binding) ? undefined : RECEIPT);

  // What the buyer holds to confirm later: the payment, with the landed receipt `finish` returns beside it, if any.
  expect(whole.landed).toEqual(done.landed);
  const held = done.landed !== undefined ? ({ ...(done.signed as object), landed: done.landed } as Presented) : done.signed;
  expect(await check(ABC, held, p.binding)).toEqual({ h: H });
  expect(code(await check(ABD, held, p.binding))).toBe("signed-not-bound");
  return { signed: done.signed, request: confirmed.request };
}
