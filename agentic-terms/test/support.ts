// What the breadth rows share: the vector files, the ATR bytes the vectors hash, a fetch stub, a counting signer, and
// the two rows every pairing adds: B2 (the plant) and B6 (build and sign).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { hash } from "@integraledger/lcp/core";
import { pay } from "../src/gate.js";
import { PIECES } from "../src/pairings/index.js";
import {
  check,
  confirm,
  transact,
  type Binding,
  type Ceilings,
  type Chosen,
  type Declined,
  type Fetch,
  type Inputs,
  type Presented,
  type Signature,
  type ConfirmOptions,
  type Signer,
  type SigningRequest,
  type TransactOptions,
} from "../src/index.js";

/** A vector file of `@integraledger/lcp`, as data of the shape the caller names. */
export function vectors<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
}

/**
 * The buyer's own request, as the gate takes it: the protocol package's x402-request-commitment.json `http[0]` request,
 * its body the UTF-8 bytes of its `bodyUtf8`.
 */
const HTTP0 = vectors<{ http: { request: { method: string; target: string; bodyUtf8: string } }[] }>("x402-request-commitment.json").http[0]!.request;
export const RESOURCE_REQUEST = { method: HTTP0.method, target: HTTP0.target, body: new TextEncoder().encode(HTTP0.bodyUtf8) };
/** `confirm`'s required option: the buyer's own request. */
export const CONFIRMING: ConfirmOptions = { resourceRequest: RESOURCE_REQUEST };
/** `transact`'s required options for a test whose subject is not the approval: an approver approving every signing. */
export const GATE: TransactOptions = { approver: () => true, resourceRequest: RESOURCE_REQUEST };

/**
 * `abc`, whose SHA-256 is the vectors' H (FIPS 180-2); `abd`, one byte changed, for the plant. `abc` is no JSON text, so
 * the gate declines it at its parse: a test pays over it only with the pairing's own build, completion and `bound`,
 * which never parse, and pays through the gate over `A`.
 */
export const ABC = new TextEncoder().encode("abc");
export const ABD = new TextEncoder().encode("abd");
export const H: AtrHash = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/** The protocol package's buyer.json `fixed.A`, an ATR that is one JSON text, and its H as that file's `fixed.D` advertises it. */
const BUYER = vectors<{ fixed: { A: string; D: { extensions: { legalContext: { info: { value: AtrHash } } } } } }>("buyer.json").fixed;
export const A = fromHexBytes(BUYER.A);
export const HA: AtrHash = BUYER.D.extensions.legalContext.info.value;

function fromHexBytes(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
}

/**
 * THE SUMMARY_PENDING SET, by the kind of request the pairing's build hands the signer: the pairings whose request the
 * gate has no summary of yet (terms' profile buyer-gate.md, rule 13), so it declines them summary-missing before any
 * signer call. A test that pays one of them through the gate asserts that decline and no signer call, never skipping
 * silently; whoever fills a kind's summary removes its pairings here, and the test then pays them through the gate in
 * full.
 */
export const SUMMARY_PENDING: ReadonlyMap<string, readonly string[]> = new Map<string, readonly string[]>([
  ["batch", ["x402/batch-settlement/solana"]],
]);

/** Whether the gate has no summary yet of the request `pairing`'s build hands the signer: SUMMARY_PENDING lists it. */
export function summaryPending(pairing: string): boolean {
  return [...SUMMARY_PENDING.values()].some((ids) => ids.includes(pairing));
}

/**
 * The kinds of request SUMMARY_PENDING lists `pairing` under. A payment signed in steps whose first step has a summary
 * and a later one none is declined at that later step, its earlier steps shown and signed: no request of these kinds
 * reaches the signer.
 */
export function pendingKinds(pairing: string): string[] {
  return [...SUMMARY_PENDING].filter(([, ids]) => ids.includes(pairing)).map(([kind]) => kind);
}
/** The vectors' link and agreement URL for H, each a random token's path. */
const FIXED = vectors<{ fixed: { link: string; agreementUrl: string } }>("mpp-challenge.json").fixed;
export const LINK = FIXED.link;

export const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
export const toHex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString("hex")}`;

/** The agreement URL a coverage-`none` pairing's offer names, and its receipt once the agreement is recorded. */
export const AGREEMENT_URL = FIXED.agreementUrl;
/** The agreement resource's receipt for `h`. */
export const receiptFor = (h: string) => ({ atrHash: h, agreed: true, network: "eip155:84532", transaction: `0x${"cd".repeat(32)}` });
export const RECEIPT = receiptFor(H);
/**
 * The receipt `serving`'s agreement URL answers the unpaid request with, as the gate returns it: marked `unpaid: true`,
 * no agreement payment having been made or read (profile `buyer-gate.md`, rule 18).
 */
export const unpaidReceiptFor = (h: string) => ({ ...receiptFor(h), unpaid: true as const });

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

/** Whether the pairing's payment is itself a public proof of the hash: its data states coverage `full`. */
export function isPublicProof(binding: Binding): boolean {
  return (binding as { data?: { coverage?: unknown } }).data?.coverage === "full";
}

/**
 * The binding as a pairing at coverage `none`, whose payment carries H only as a link, so its agreement is paid first.
 * Its data holds no `agreement`, which the protocol package states only at coverage `full`; every other member is the
 * binding's own.
 */
export function coverageNone<B>(binding: B): B {
  const { agreement: _agreement, ...data } = (binding as unknown as { data: Record<string, unknown> }).data;
  return { ...binding, data: { ...data, coverage: "none", link: "h", agreementOn: "any" } } as B;
}

/**
 * The binding a seller's offer is read through: for a pairing at coverage `none`, the offer also names
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
  options: Partial<TransactOptions> = {},
): ReturnType<typeof transact> {
  const given: TransactOptions = { ...GATE, ...options };
  const first = await transact(doc, binding, signer, fetch, { ...GATE, ...given });
  if (!("approve" in first)) return first;
  return transact(doc, binding, signer, fetch, { ...GATE, ...given, approved: first.approve });
}

export const isDeclined = (r: unknown): r is Declined => typeof r === "object" && r !== null && "decline" in r;
export const code = (r: unknown): string | undefined => (r as Declined).decline?.code;

export interface Pairing {
  binding: Binding;
  /** The seller's document as the pairing's `advertise` placed it, advertising H and LINK. */
  doc: unknown;
  /**
   * The same document as the pairing's `advertise` places it for another hash: given, B6 also pays the pairing through
   * the gate over `A`, its document placed for `HA`.
   */
  placed?: (h: AtrHash) => unknown;
  /** Where a test pays the pairing by its own steps alone, with no `placed`, why: where its gate-level run is. */
  pieceOnly?: string;
  account: string;
  inputs?: Inputs;
  /** The ceilings the payment through the gate is given, where the profile asks the caller to raise one. */
  ceilings?: Ceilings;
  /**
   * Where the ATR the document advertises lists in its binding slot no option the document offers, why: through the
   * gate the payment is declined `option-not-in-atr` before anything is signed (profile `buyer-gate.md`, rule 6).
   */
  notInAtr?: string;
  /** The test signer's answer to the request the pairing builds: a key generated or published for tests only. */
  answer: (r: SigningRequest) => Promise<Signature>;
}

/** B2 for a pairing: the link serves `abd`; the gate declines hash-mismatch and never calls the signer. */
export async function plant(p: Pairing): Promise<void> {
  const signer = counting(p.account, p.answer);
  const binding = offered(p.binding);
  const out = await transact(p.doc, binding, signer, serving(ABD), { ...GATE, inputs: p.inputs ?? {} });
  expect(code(out)).toBe("hash-mismatch");
  expect(signer.requests.length).toBe(0);
  const confirmed = await confirm(p.doc, binding, p.account, serving(ABD), { ...CONFIRMING, inputs: p.inputs });
  expect(code(confirmed)).toBe("hash-mismatch");
  expect(confirmed).not.toHaveProperty("request");
}

/**
 * `confirm` by the pairing's own steps, with no gate and nothing fetched: its read, the piece's choice of option for the
 * account, and the build with the hash of `bytes` (the vector's H for `abc`, which the gate's parse declines), giving
 * the request the signer is handed and the choice kept, or the decline the gate gives each step's refusal. For a
 * pairing whose payment is not itself a public proof, the choice names the agreement URL the offer names.
 */
export async function pieceConfirm(
  doc: unknown,
  binding: Binding,
  account: string,
  inputs: Inputs = {},
  bytes: Uint8Array = ABC,
): Promise<{ chosen: Chosen; request: SigningRequest | null; bytes: Uint8Array; h: AtrHash } | Declined> {
  const piece = PIECES.get(binding.id);
  if (piece === undefined) return { decline: { code: "pairing-not-supported", detail: binding.id } };
  const b = binding as unknown as {
    read(doc: unknown): { agreement?: string } | { refused: true; code: string };
    build?(choice: unknown, h: AtrHash, act: "payment"): Promise<unknown>;
  };
  const refused = (v: unknown): v is { code: string } => typeof v === "object" && v !== null && "refused" in v;
  const read = b.read(doc);
  if (refused(read)) return { decline: { code: "offer-unreadable", detail: read.code } };
  const choice = await piece.choose(read as never, account, inputs, Math.floor(Date.now() / 1000), "r".repeat(32), doc);
  if (refused(choice)) return { decline: { code: "no-payable-option", detail: choice.code } };
  const agreement = isPublicProof(binding) ? undefined : (read as { agreement?: string }).agreement;
  const chosen: Chosen = agreement === undefined ? choice : { ...choice, agreement };
  const h = await hash(bytes);
  const input = piece.choice(chosen, bytes);
  if (refused(input)) return { decline: { code: "offer-unreadable", detail: input.code } };
  const unsigned = piece.build !== undefined ? await piece.build(input, h, "payment") : await b.build!(input, h, "payment");
  if (refused(unsigned)) {
    if (/\/(no-signed-place|nothing-to-sign)$/.test(unsigned.code)) return { chosen, request: null, bytes, h };
    return { decline: { code: "offer-unreadable", detail: unsigned.code } };
  }
  const request = piece.request(unsigned);
  if (refused(request)) return { decline: { code: "offer-unreadable", detail: request.code } };
  return { chosen: piece.kept === undefined ? chosen : piece.kept(chosen, unsigned), request, bytes, h };
}

/**
 * `transact` by the pairing's own steps, with no gate: `pieceConfirm`, then the signer once per step, and the payment
 * completed and held to `bound` reading the hash of `bytes`. No agreement is paid, and nothing is shown or approved.
 */
export async function piecePay(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  inputs: Inputs = {},
  bytes: Uint8Array = ABC,
): Promise<{ signed: Presented | null; landed?: unknown; h: AtrHash; bytes: Uint8Array } | Declined> {
  const confirmed = await pieceConfirm(doc, binding, signer.account, inputs, bytes);
  if (isDeclined(confirmed)) return confirmed;
  const done = await pay(binding, confirmed.chosen, signer, bytes);
  return isDeclined(done) ? done : { ...done, bytes };
}

/** `pieceConfirm` over the offer as `offered` reads it, for B6: a decline throws. */
export async function built(
  binding: Binding,
  doc: unknown,
  account: string,
  inputs: Inputs = {},
): Promise<{ chosen: Chosen; request: SigningRequest | null; h: AtrHash }> {
  const out = await pieceConfirm(doc, offered(binding), account, inputs);
  if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
  return out;
}

/**
 * The pairing paid through the gate over `A`, its document placed for `HA`: where SUMMARY_PENDING lists the pairing,
 * declined summary-missing with no signer call; otherwise signed `count` times, returning `A` with, for a pairing whose
 * payment is not itself a public proof, the agreement's receipt for `HA`, and a payment `check` reads `HA` from.
 */
export async function throughGate(p: Pairing & { placed: (h: AtrHash) => unknown }, count: number): Promise<void> {
  const signer = counting(p.account, p.answer);
  const options = { ...GATE, inputs: p.inputs ?? {}, ...(p.ceilings === undefined ? {} : { ceilings: p.ceilings }) };
  const whole = await transact(p.placed(HA), offered(p.binding), signer, serving(A), options);
  if (summaryPending(p.binding.id)) {
    expect(code(whole)).toBe("summary-missing");
    expect(signer.requests.length).toBe(0);
    return;
  }
  if (isDeclined(whole)) throw new Error(`${whole.decline.code}: ${whole.decline.detail}`);
  if ("approve" in whole || !("signed" in whole)) throw new Error("an agreement payment to approve");
  expect(signer.requests.length).toBe(count);
  expect(whole.bytes).toEqual(A);
  expect(whole.agreement).toEqual(isPublicProof(p.binding) ? undefined : unpaidReceiptFor(HA));
  expect(await check(A, whole.signed, p.binding, whole.landed)).toEqual({ h: HA });
}

/**
 * THE PIECE-ONLY SET: the pairings a B6 test pays by the pairing's own steps alone, over `abc`, with no document placed
 * for `HA` to pay them through the gate, each with where its gate-level run is or why it has none here. `buildAndSign`,
 * and the protocol groups' B6 in pairings-proto.test.ts, assert that a pairing they cannot place is listed, or that the
 * test gives its own reason (`pieceOnly`), so none is skipped unseen; whoever places one removes it.
 */
export const PIECE_ONLY: ReadonlyMap<string, string> = new Map([
  ["x402/batch-settlement/eip155", "paid through the gate over A in channels.test.ts (opensThroughGate)"],
  ["x402/batch-settlement/solana", "paid through the gate over A in channels.test.ts (opensThroughGate)"],
  ["mpp/session/tempo", "paid through the gate over A in channels.test.ts (opensThroughGate)"],
  ["mpp/session/evm", "not placed for A: no gate-level run of its two-step opening yet"],
  ["mpp/subscription/tempo", "not placed for A: no gate-level run yet"],
  ["card/visa-tap", "C2's TAP answer signs a nonce built for H(abc); no answer signed for another H is published"],
  ["card/mastercard-agent-pay", "T6's Agent Pay answers sign C2's nonce, built for H(abc); no answer signed for another H is published"],
  ["card/mastercard-vi/immediate", "C6's user credential is signed over the checkout mandate for H(abc); none is published for another H"],
  ["card/mastercard-vi/autonomous", "C7's agent chain is signed over the checkout mandate for H(abc); none is published for another H"],
  ["ack/payment-request", "K2's Payment Request token is signed with the id of H(abc), which the read holds the legal context to"],
  ["mpp/charge/lightning", "L3's invoice commits to H(abc), and the protocol package refuses to place it again for another H"],
  ["mpp/session/lightning", "the deposit invoice commits to H(abc), and the protocol package refuses to place it again for another H"],
  ["mpp/charge/usdc/stacks", "M4's recorded transaction is signed over H(abc), so it carries no other ATR's hash"],
  ["x402/exact/xrpl", "V2's recorded blob is signed over H(abc), so it carries no other ATR's hash"],
  ["mpp/charge/xrpl", "V3's recorded blob is signed over H(abc), so it carries no other ATR's hash"],
  ["mpp/session/xrpl", "XS2's recorded blob is signed over H(abc); buyer.json BX1 hands its opening to the signer through the gate over A"],
  ["x402/exact/ccd", "D3's recorded transaction is bound to H(abc); no signer here makes one for another H"],
  ["x402/exact/starknet", "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H"],
  ["x402/exact/polkadot/lcp-assets-remark", "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H"],
  ["x402/exact/sui", "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H"],
  ["x402/exact/cardano", "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H"],
  ["x402/exact/cardano/lock", "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H"],
  ["ucp/checkout/agent-signed", "the bound rows' signed request bodies carry H(abc); none is published for another H"],
]);

/**
 * B6 for a pairing, by its own steps with no gate: the build with the vector's H gives the request, which `inspect`
 * checks against the vectors; the test signer's answers complete a payment whose bound hash is H, the signer called
 * once per step; `check` confirms that payment against `abc` and declines it against `abd`. Where the pairing gives
 * `placed`, it is then paid through the gate over `A` (`throughGate`); where it gives none, PIECE_ONLY lists it.
 */
export async function buildAndSign(
  p: Pairing,
  inspect: (request: SigningRequest) => void | Promise<void>,
): Promise<{ signed: Presented; request: SigningRequest }> {
  const { chosen, request, h } = await built(p.binding, p.doc, p.account, p.inputs);
  expect(h).toBe(H);
  if (request === null) throw new Error("nothing to sign");
  await inspect(request);

  const signer = counting(p.account, p.answer);
  const done = await pay(p.binding, JSON.parse(JSON.stringify(chosen)), signer, ABC);
  if (isDeclined(done)) throw new Error(`${done.decline.code}: ${done.decline.detail}`);
  if (done.signed === null) throw new Error("nothing signed");
  expect(done.h).toBe(H);
  expect(signer.requests[0]).toEqual(request);

  // What the buyer holds to confirm later: the payment, with the landed receipt beside it, if any.
  expect(await check(ABC, done.signed, p.binding, done.landed)).toEqual({ h: H });
  expect(code(await check(ABD, done.signed, p.binding, done.landed))).toBe("signed-not-bound");
  if (p.placed !== undefined) await throughGate({ ...p, placed: p.placed }, signer.requests.length);
  else if (p.pieceOnly === undefined) {
    expect(PIECE_ONLY.has(p.binding.id), `${p.binding.id} is paid by its own steps alone and PIECE_ONLY does not list it`).toBe(true);
  }
  return { signed: done.signed, request };
}
