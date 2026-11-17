/**
 * The buyer gate. `confirm` reads the offer, fetches the ATR from the seller's link, compares its SHA-256 with the
 * advertised hash, and only on a match builds the signing request with the hash it computed. `finish` completes the
 * payment with the signature and returns it only when the pairing's `bound` reads the hash of these bytes from the
 * completed payment, or, for a pairing at coverage `none`, whose proof is the agreement payment, completes it without
 * that reading. `check` confirms a payment held later against kept bytes, as the act it was paid as.
 */
import type { Act } from "@integraledger/lcp";
import {
  hash,
  hashEquals,
  isHttpsLink,
  isOtherSchemeLink,
  toBase64Url,
  type AtrHash,
  type Refusal,
} from "@integraledger/lcp/core";
import {
  approves,
  floorMissing,
  isCeilings,
  networkOfAccount,
  parseAtr,
  requestHeld,
  shown,
  slotHolds,
  stepsOf,
  type Approval,
} from "./checks.js";
import { heldToDeadline, withDeadline } from "./deadline.js";
import { fetchedOf, held, isRefusal, jsonSafe, refuse } from "./pairings/common.js";
import { PIECES } from "./pairings/index.js";
import { summaryOf, type Opened } from "./summary.js";
import {
  MAX_ATR_BYTES,
  type Binding,
  type BuyerPiece,
  type Ceilings,
  type Chosen,
  type ConfirmOptions,
  type DeclineCode,
  type Declined,
  type Fetch,
  type FinishOptions,
  type Inputs,
  type Next,
  type Presented,
  type Read,
  type ResourceRequest,
  type Signature,
  type Signer,
  type SigningRequest,
  type Summary,
} from "./types.js";

/**
 * The binding members the gate calls, whatever the pairing's own types. `build` is absent where the protocol package
 * builds no payment for the pairing. `build` and `bound` take the act, and `bound` H with it, where the gate gives them.
 */
interface Steps {
  id: string;
  read(doc: unknown): Read | Refusal;
  build?(choice: unknown, h: AtrHash, act?: Act): Promise<unknown>;
  bound(presented: unknown, given?: { readonly act: Act; readonly h: AtrHash }): Promise<AtrHash | Refusal> | AtrHash | Refusal;
}

/** The binding's members, as the gate calls them. */
function steps(binding: Binding): Steps {
  return binding as unknown as Steps;
}

/** A build refusal that means the pairing has nothing for the buyer to sign: the gate confirms only. */
const NOTHING_TO_SIGN = /\/(no-signed-place|nothing-to-sign)$/;
/** The most signer calls one payment takes: a funding and then a voucher. */
const MAX_STEPS = 2;

const FETCH_DEADLINE_MS = 10_000;
const REF_BYTES = 24;
const DECIMAL = /^[0-9]+$/;

export function declined(code: DeclineCode, detail: string): Declined {
  return { decline: { code, detail } };
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Whether a signer's `account` is a string, the form every pairing reads its payer from. */
export function hasAccount(signer: unknown): boolean {
  return typeof (signer as { account?: unknown } | null | undefined)?.account === "string";
}

/** The pairing's namespace: its id up to the first `/`. */
export function namespaceOf(binding: Binding): string {
  return String(binding.id).split("/")[0]!;
}

/** The protocol package's refusal code for a link that is not an https link, in the pairing's namespace. */
function linkRefusal(binding: Binding, link: unknown): string {
  return `${namespaceOf(binding)}/${isOtherSchemeLink(link) ? "link-not-https" : "legal-context-malformed"}`;
}

/**
 * Whether the pairing's payment is itself a public proof of the hash, so the offer's agreement URL is not paid: the
 * pairing's data states coverage `full`, the payer's own signed act on a public ledger binding all of H.
 */
export function isFullCoverage(binding: Binding): boolean {
  const data: unknown = isObject(binding) ? (binding as { data?: unknown }).data : undefined;
  return isObject(data) && data["coverage"] === "full";
}

export function pieceOf(binding: Binding): BuyerPiece | undefined {
  const id: unknown = isObject(binding) ? binding.id : undefined;
  return typeof id === "string" ? PIECES.get(id) : undefined;
}

export function unsupported(binding: Binding): Declined {
  const id: unknown = isObject(binding) ? binding.id : undefined;
  return declined("pairing-not-supported", `The gate has no buyer piece for the pairing ${String(id)}.`);
}

const tooLarge = (): Declined => declined("atr-too-large", `The ATR is larger than ${MAX_ATR_BYTES} bytes.`);

/** 24 random bytes as unpadded base64url: 32 characters from `[A-Za-z0-9_-]`. */
export function newRef(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(REF_BYTES)));
}

/** Whether an answer to a `redirect: "manual"` request is a redirect: a 3xx status, or the opaque form a browser gives. */
export function redirected(response: Response): boolean {
  return response.type === "opaqueredirect" || (response.status >= 300 && response.status <= 399);
}

/** The request header that asks for the body with no content coding, so the bytes hashed are the bytes sent. */
export const IDENTITY = { "Accept-Encoding": "identity" } as const;

/** HTTP whitespace, as the Fetch standard names it: tab, LF, CR and space. */
const HTTP_WHITESPACE = "\t\n\r ";

/**
 * A header value without its leading and trailing HTTP whitespace, as Fetch normalizes one. Any other character stays,
 * so a value it surrounds is read as written.
 */
export function trimHttpWhitespace(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && HTTP_WHITESPACE.includes(value[start]!)) start++;
  while (end > start && HTTP_WHITESPACE.includes(value[end - 1]!)) end--;
  return value.slice(start, end);
}

/**
 * Whether a `Content-Encoding` value names no coding: absent, empty, or `identity`, surrounding spaces, tabs, CRs and
 * LFs aside.
 */
export function isIdentity(contentEncoding: string | null): boolean {
  const v = trimHttpWhitespace(contentEncoding ?? "").toLowerCase();
  return v === "" || v === "identity";
}

/**
 * One GET of the link, asking for the identity coding, with no redirect followed, one 10-second deadline over headers
 * and body, and at most `MAX_ATR_BYTES` read. A redirect, like any status but 200, is `atr-unfetchable`, and so is a 200
 * whose `Content-Encoding` names any coding: its body is never read or decoded. A declared or streamed length over the
 * bound cancels the body. The bytes are returned exactly as received.
 */
export async function fetchAtr(fetch: Fetch, link: string): Promise<Uint8Array | Declined> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new DOMException("The ATR fetch passed its deadline.", "TimeoutError")),
    FETCH_DEADLINE_MS,
  );
  const deadline = new Promise<never>((_, reject) => {
    controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
  });
  deadline.catch(() => undefined);

  let body: ReadableStream<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let whole = false;
  try {
    const response = await Promise.race([
      fetch(link, { method: "GET", redirect: "manual", signal: controller.signal, headers: { ...IDENTITY } }),
      deadline,
    ]);
    body = response.body;
    if (redirected(response)) return declined("atr-unfetchable", "The link answered with a redirect.");
    if (response.status !== 200) return declined("atr-unfetchable", `The link answered status ${response.status}.`);
    if (!isIdentity(response.headers.get("content-encoding"))) {
      return declined("atr-unfetchable", "The link served a content coding other than identity.");
    }
    const length = response.headers.get("content-length");
    const declared = length === null ? undefined : trimHttpWhitespace(length);
    if (declared !== undefined && DECIMAL.test(declared) && Number(declared) > MAX_ATR_BYTES) return tooLarge();
    if (body === null) {
      whole = true;
      return new Uint8Array(0);
    }

    reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const next = await Promise.race([reader.read(), deadline]);
      if (next.done) break;
      if (!(next.value instanceof Uint8Array)) return declined("atr-unfetchable", "The link served a non-byte chunk.");
      total += next.value.length;
      if (total > MAX_ATR_BYTES) return tooLarge();
      chunks.push(next.value);
    }
    whole = true;
    const bytes = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      bytes.set(c, at);
      at += c.length;
    }
    return bytes;
  } catch {
    return declined("atr-unfetchable", "The ATR could not be fetched from the link.");
  } finally {
    clearTimeout(timer);
    if (!whole) {
      cancel(reader ?? body);
      controller.abort();
    }
  }
}

/** Cancels a body or its reader, ignoring whatever the cancellation answers. */
function cancel(s: ReadableStream<Uint8Array> | ReadableStreamDefaultReader<Uint8Array> | null | undefined): void {
  if (s === null || s === undefined) return;
  try {
    s.cancel().catch(() => undefined);
  } catch {
    // A body that cannot be cancelled is left to the fetch's own abort.
  }
}

/**
 * What the gate's checks 3 to 11 read beside the offer: the buyer's request, its inputs and the raised ceilings; and,
 * where the caller gives it, the payment `confirm` chose, built again exactly rather than chosen anew.
 */
export interface GateArgs {
  readonly resourceRequest: ResourceRequest;
  readonly inputs: Inputs;
  readonly ceilings: Ceilings | undefined;
  readonly chosen?: Chosen | undefined;
}

/**
 * The choice of a `chosen` given back, with the latest deadline it keeps for a wallet that picks the expiry, and without
 * the agreement URL the offer names again; undefined for another form.
 */
function givenChoice(chosen: unknown, pairing: string): Chosen | undefined {
  if (!isObject(chosen) || chosen["pairing"] !== pairing || !isObject(chosen["choice"]) || typeof chosen["ref"] !== "string") {
    return undefined;
  }
  const deadline = chosen["deadline"];
  if (deadline !== undefined && (typeof deadline !== "string" || !/^[0-9]{1,78}$/.test(deadline))) return undefined;
  const given: Chosen = { pairing, choice: chosen["choice"] as Chosen["choice"], ref: chosen["ref"] };
  return deadline === undefined ? given : { ...given, deadline };
}

/** What checks 3 to 11 give: the choice, the request for the signer with its summary, the bytes and H. */
export interface Gated {
  chosen: Chosen;
  request: SigningRequest | null;
  summary?: Summary;
  count: number;
  bytes: Uint8Array;
  h: AtrHash;
}

const CONFIRM_KEYS: readonly string[] = ["resourceRequest", "inputs", "ceilings"];

/**
 * Whether `confirm`'s options are an object holding `resourceRequest` (an object) and only `inputs` and `ceilings`, the
 * latter of rule 8's form for `pairing`.
 */
function confirmOptionsOk(options: unknown, pairing: string): options is ConfirmOptions {
  if (!isObject(options) || !Object.keys(options).every((k) => CONFIRM_KEYS.includes(k))) return false;
  const { resourceRequest, inputs, ceilings } = options;
  return isObject(resourceRequest) && (inputs === undefined || isObject(inputs)) && isCeilings(ceilings, pairing);
}

/**
 * Reads the offer, chooses the option, fetches the ATR and compares its SHA-256 with the advertised hash; parses the
 * bytes, holds the option chosen to the ATR's binding slot and the buyer's request to its request commitment; and only
 * then builds, with the hash it computed, and holds the request to its summary and its ceiling (terms' profile
 * `buyer-gate.md`, checks 1 to 11). `request` is what the signer is handed, with `summary`, or `null` when nothing is
 * handed to the signer: the pairing has nothing for the buyer to sign, or the build is itself the payment, which
 * `finish` completes with no signature. For a pairing whose payment is not itself a public proof, `chosen.agreement` is
 * the agreement URL the offer names. Options that are not an object holding `resourceRequest` and only `inputs` and
 * `ceilings` of their forms are declined `no-payable-option` with `<namespace>/input-malformed` before the offer is
 * read.
 */
export async function confirm(
  doc: unknown,
  binding: Binding,
  account: string,
  fetch: Fetch,
  options: ConfirmOptions,
): Promise<{ chosen: Chosen; request: SigningRequest | null; summary?: Summary; bytes: Uint8Array; h: AtrHash } | Declined> {
  if (pieceOf(binding) === undefined) return unsupported(binding);
  if (!confirmOptionsOk(options, String(binding.id))) return declined("no-payable-option", `${namespaceOf(binding)}/input-malformed`);
  const { resourceRequest, inputs = {}, ceilings } = options;
  const out = await gate(doc, binding, account, fetch, { resourceRequest, inputs, ceilings });
  if ("decline" in out) return out;
  const { count: _count, ...confirmed } = out;
  return confirmed;
}

/** Checks 3 to 11 of the profile, for `confirm` and `transact`, once the pairing and the arguments are known good. */
export async function gate(doc: unknown, binding: Binding, account: string, fetch: Fetch, args: GateArgs): Promise<Gated | Declined> {
  const piece = pieceOf(binding);
  if (piece === undefined) return unsupported(binding);
  const { inputs, ceilings, resourceRequest } = args;
  const b = steps(binding);
  const floor = floorMissing(b.id, inputs);
  if (floor !== undefined) return floor;

  const read = b.read(doc);
  if (isRefusal(read)) return declined("offer-unreadable", read.code);
  const agreement: unknown = isFullCoverage(binding) ? undefined : (read as { agreement?: unknown }).agreement;
  if (agreement !== undefined && typeof agreement !== "string") {
    return declined("offer-unreadable", "The offer names an agreement URL that is not a string.");
  }

  const given = args.chosen === undefined ? undefined : givenChoice(args.chosen, b.id);
  if (args.chosen !== undefined && given === undefined) return declined("no-payable-option", `${namespaceOf(binding)}/input-malformed`);
  const choice = given ?? (await piece.choose(read, account, inputs, Math.floor(Date.now() / 1000), newRef(), doc));
  if (isRefusal(choice)) return declined("no-payable-option", choice.code);
  const chosen: Chosen = agreement === undefined ? choice : { ...choice, agreement };

  if (!isHttpsLink(read.link)) return declined("link-not-https", linkRefusal(binding, read.link));

  const bytes = await fetchAtr(fetch, read.link);
  if (!(bytes instanceof Uint8Array)) return bytes;

  const computed = await hash(bytes);
  if (!hashEquals(read.h, computed)) {
    return declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.");
  }
  const parsed = parseAtr(bytes);
  if ("decline" in parsed) return parsed;
  const notHeld = await slotHolds(binding, chosen, parsed.value);
  if (notHeld !== undefined) return notHeld;
  const otherRequest = await requestHeld(binding, parsed.value, resourceRequest);
  if (otherRequest !== undefined) return otherRequest;
  if (!isFullCoverage(binding) && agreement === undefined) {
    return declined("agreement-not-offered", "The pairing's payment carries no public proof and the offer names no agreement URL.");
  }

  return charged(binding, chosen, account, bytes, computed, inputs, ceilings);
}

/**
 * Checks 9 to 11 on the payment chosen, for the gate and for the return after an agreement: the pairing's build with
 * H, the request handed to the signer, and that request's summary and ceiling. `request` is `null` where nothing is
 * handed to the signer.
 */
export async function charged(
  binding: Binding,
  chosen: Chosen,
  account: string,
  bytes: Uint8Array,
  h: AtrHash,
  inputs: Inputs,
  ceilings: Ceilings | undefined,
): Promise<Gated | Declined> {
  const piece = pieceOf(binding);
  if (piece === undefined) return unsupported(binding);
  const unsigned = await buildWith(piece, steps(binding), chosen, h, bytes);
  if (isRefusal(unsigned)) {
    if (NOTHING_TO_SIGN.test(unsigned.code)) return { chosen, request: null, count: 0, bytes, h };
    return declined("offer-unreadable", unsigned.code);
  }
  const built = piece.request(unsigned);
  if (isRefusal(built)) return declined("offer-unreadable", built.code);
  const bounded = withDeadline(binding, built, chosen, inputs, ceilings, Math.floor(Date.now() / 1000));
  if ("decline" in bounded) return bounded;
  const { request } = bounded;
  const kept = keptWith(piece, bounded.chosen, unsigned);
  if (request === null) return { chosen: kept, request, count: 0, bytes, h };
  const summary = await shown(binding, request, bytes, inputs, ceilings, networkOfAccount(account));
  if ("decline" in summary) return summary;
  return { chosen: kept, request, summary, count: stepsOf(unsigned), bytes, h };
}

/** `chosen` with what the build drew itself, where the piece keeps it, so a rebuild gives the request the signer saw. */
function keptWith(piece: BuyerPiece, chosen: Chosen, unsigned: unknown): Chosen {
  return piece.kept === undefined ? chosen : piece.kept(chosen, unsigned);
}

/**
 * The pairing's build over the choice the piece revives from `chosen`, for the act: the agreement payment is built with
 * the act `agreement`. A pairing for which the protocol package builds nothing has nothing for the buyer to sign.
 */
async function buildWith(
  piece: BuyerPiece,
  b: Steps,
  chosen: Chosen,
  h: AtrHash,
  bytes: Uint8Array,
  act: Act = "payment",
): Promise<unknown> {
  const choice = piece.choice(chosen, bytes);
  if (isRefusal(choice)) return choice;
  const ns = b.id.split("/")[0]!;
  try {
    if (piece.build !== undefined) return await piece.build(choice, h, act);
    if (typeof b.build !== "function") return refuse(`${ns}/nothing-to-sign`);
    return await b.build(choice, h, act);
  } catch {
    return refuse(`${ns}/build-failed`);
  }
}

/**
 * Rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and returns the payment only when the
 * pairing's `bound` reads the hash of these bytes from the completed payment. A later step's request is returned as
 * `next`, with its `summary`, only once it has a summary and is within the pairing's ceiling, `ceilings` raising it
 * (checks 10 and 11). For a pairing whose payment is not a public proof and whose `bound` finds no signed place for the hash, the proof is the agreement payment, and the
 * completed payment is returned as it is. Where the signer moved the payment itself, a decline keeps it as `moved`.
 * Where the completion carried the landed receipt `bound` reads and the payment sent leaves it out, `landed` is
 * returned beside the payment as JSON, each integer a decimal string, so `check` and `openChannel` can later read the
 * payment with it.
 */
export async function finish(
  bytes: Uint8Array,
  chosen: Chosen,
  signature: Signature,
  binding: Binding,
  options?: FinishOptions,
): Promise<{ signed: Presented; landed?: unknown; h: AtrHash } | { next: SigningRequest; summary: Summary; h: AtrHash } | Declined> {
  const given: unknown = options;
  const ceilings: unknown = isObject(given) ? given["ceilings"] : undefined;
  const ok =
    given === undefined ||
    (isObject(given) && Object.keys(given).every((k) => k === "ceilings") && isCeilings(ceilings, String(binding.id)));
  if (!ok) return declined("no-payable-option", `${namespaceOf(binding)}/input-malformed`);
  const out = await finishAs(bytes, chosen, signature, binding, "payment");
  if (!("next" in out)) return out;
  const first = out.first === null ? undefined : await summaryOf(String(binding.id), out.first, bytes);
  const opened = first === undefined || out.first === null ? undefined : openedBy(out.first, first, signature);
  const summary = await shown(binding, out.next, bytes, {}, ceilings as Ceilings | undefined, undefined, opened);
  return "decline" in summary ? summary : { next: out.next, summary, h: out.h };
}

/** The step that opened a payment signed in steps, for its later step's summary: its request, summary and answer. */
function openedBy(request: SigningRequest, summary: Summary, signature: Signature): Opened {
  const { atr: _atr, ...facts } = summary;
  return { request, summary: facts, signature };
}

/**
 * `finish` for the act: the agreement payment is rebuilt with the act `agreement`, and `bound` is given that act and the
 * hash, so it reads the hash where the payment carries the agreement's own single-use value in its place.
 */
async function finishAs(
  bytes: Uint8Array,
  chosen: Chosen,
  signature: Signature,
  binding: Binding,
  act: Act,
): Promise<
  { signed: Presented; landed?: unknown; h: AtrHash } | { next: SigningRequest; h: AtrHash; first: SigningRequest | null } | Declined
> {
  const piece = pieceOf(binding);
  if (piece === undefined) return unsupported(binding);
  const b = steps(binding);
  if (bytes.length > MAX_ATR_BYTES) return tooLarge();
  if (!isObject(chosen) || !isObject(chosen.choice)) {
    return declined("offer-unreadable", "The chosen payment carries no choice to build from.");
  }
  if (chosen.pairing !== b.id) {
    return declined("pairing-not-supported", `The chosen payment is not for the pairing ${b.id}.`);
  }

  const h = await hash(bytes);
  const unsigned = await buildWith(piece, b, chosen, h, bytes, act);
  if (isRefusal(unsigned)) return declined("offer-unreadable", unsigned.code);
  const moves = signature !== null && (movesWith(piece, unsigned) || movedBy(piece, signature));
  const keep = (d: Declined, signed: unknown): Declined => (moves ? { ...d, moved: { signed, bytes, h } } : d);

  let signed: Presented | Next | Refusal;
  try {
    signed = await piece.complete(unsigned, signature, chosen);
  } catch {
    return keep(declined("signed-not-bound", "The signer's answer did not complete the payment."), signature);
  }
  if (isRefusal(signed)) return keep(declined("signed-not-bound", signed.code), signature);
  if (isNext(signed)) {
    const first = piece.request(unsigned);
    return { next: signed.next, h, first: first === null || isRefusal(first) ? null : first };
  }

  const sent = piece.sent !== undefined ? piece.sent(signed) : signed;
  const inside = await boundOf(b, signed, act === "agreement" ? { act, h } : undefined);
  const onAgreement = !isFullCoverage(binding) && isRefusal(inside) && NOTHING_TO_SIGN.test(inside.code);
  if (!onAgreement && (isRefusal(inside) || !hashEquals(inside, h))) {
    return keep(
      declined("signed-not-bound", "The pairing does not read the hash of the compared bytes from the payment."),
      sent,
    );
  }
  // A wallet that picked the expiry is held to the latest deadline it was handed; a payment past it is discarded.
  const request = piece.request(unsigned);
  const late = await heldToDeadline(binding, isRefusal(request) ? null : request, signed, chosen);
  if (late !== undefined) return late;
  const landed = sent !== signed ? jsonSafe(fetchedOf(signed)) : undefined;
  return landed === undefined ? { signed: sent, h } : { signed: sent, landed, h };
}

/** Whether the signer, handed the build's first request, moves the payment itself. */
function movesWith(piece: BuyerPiece, unsigned: unknown): boolean {
  if (piece.moves === undefined) return false;
  const request = piece.request(unsigned);
  return request !== null && !isRefusal(request) && piece.moves(request);
}

/** Whether the signer's answer shows that its side moved the payment itself, where the piece reads that from the answer. */
function movedBy(piece: BuyerPiece, signature: Signature): boolean {
  try {
    return piece.movedBy?.(signature) === true;
  } catch {
    return false;
  }
}

/** The binding's `bound`, given the act and the hash where the gate gives them, with a throw read as a refusal. */
async function boundOf(
  b: Steps,
  presented: unknown,
  given?: { readonly act: Act; readonly h: AtrHash },
): Promise<AtrHash | Refusal> {
  try {
    return await (given === undefined ? b.bound(presented) : b.bound(presented, given));
  } catch {
    return refuse("bound-failed");
  }
}

/**
 * Confirms that the ATR hash the pairing reads from a payment held later is the SHA-256 of the kept bytes, with the
 * `landed` receipt `finish` or `transact` returned beside the payment, where it returned one, held under the payment's
 * own `FETCHED` member as `bound` reads it. The caller passes as `landed` only the receipt its own reader read for the
 * payment, as `finish` or `transact` returned it, never a value another party sent. A `landed` of `null` is no
 * receipt: the payment is read alone, as without one. `act` is the act the payment was paid as: `agreement` for the
 * agreement payment, which `bound` is then given with the hash, so it reads the hash where the payment carries the
 * agreement's own single-use value in its place; `payment`, the default, for any other. A payment from which the
 * pairing reads no ATR hash is declined `signed-not-bound`, as is a `landed` receipt that is not a JSON object beside a
 * payment that is one. A `landed` member of the payment's own is not read.
 */
export async function check(
  bytes: Uint8Array,
  presented: unknown,
  binding: Binding,
  landed?: unknown,
  act: Act = "payment",
): Promise<{ h: AtrHash } | Declined> {
  if (bytes.length > MAX_ATR_BYTES) return tooLarge();
  const read = landed === null ? undefined : landed;
  if (read !== undefined && (!isObject(read) || !isObject(presented))) {
    return declined("signed-not-bound", "The landed receipt is not a JSON object beside the payment.");
  }
  const h = await hash(bytes);
  const b = await boundOf(
    steps(binding),
    read === undefined ? presented : held(presented as object, read),
    act === "agreement" ? { act, h } : undefined,
  );
  if (isRefusal(b) || !hashEquals(b, h)) {
    return declined("signed-not-bound", "The pairing does not read the hash of the compared bytes from the payment.");
  }
  return { h };
}

/**
 * Builds and signs the payment `chosen` names, for the act, with the hash of `bytes`: the signer is called once, or, for
 * a pairing signed in steps, once per step in order, and the payment is returned only through `finish`. `signed` is
 * null where the pairing has nothing for the buyer to sign. With `approval`, each signing is first held to its summary
 * and ceiling and asked of the approver.
 */
export async function pay(
  binding: Binding,
  chosen: Chosen,
  signer: Signer,
  bytes: Uint8Array,
  act: Act = "payment",
  approval?: Approval,
): Promise<{ signed: Presented | null; landed?: unknown; h: AtrHash } | Declined> {
  const piece = pieceOf(binding);
  if (piece === undefined) return unsupported(binding);
  const h = await hash(bytes);
  const unsigned = await buildWith(piece, steps(binding), chosen, h, bytes, act);
  if (isRefusal(unsigned)) {
    if (NOTHING_TO_SIGN.test(unsigned.code)) return { signed: null, h };
    return declined("offer-unreadable", unsigned.code);
  }
  const built = piece.request(unsigned);
  if (isRefusal(built)) return declined("offer-unreadable", built.code);
  // Where a ceiling holds the payment (`approval`), a wallet that picks the expiry is handed the latest it may sign.
  const bounded =
    approval === undefined
      ? { request: built, chosen }
      : withDeadline(binding, built, chosen, approval.inputs, approval.ceilings, Math.floor(Date.now() / 1000));
  if ("decline" in bounded) return bounded;
  return signSteps(binding, keptWith(piece, bounded.chosen, unsigned), bounded.request, signer, bytes, h, act, approval, stepsOf(unsigned));
}

/**
 * The signer, once per step in order, then `finish` over its answers. A request of null is a build that is itself the
 * payment: `finish` completes it with no signer call. With `approval`, each step's request is held to its summary and
 * its ceiling and asked of the approver before the signer is called for it (checks 10 to 12); `count` is the number of
 * signings the build takes.
 */
export async function signSteps(
  binding: Binding,
  chosen: Chosen,
  first: SigningRequest | null,
  signer: Signer,
  bytes: Uint8Array,
  h: AtrHash,
  act: Act = "payment",
  approval?: Approval,
  count = 1,
): Promise<{ signed: Presented | null; landed?: unknown; h: AtrHash } | Declined> {
  if (first === null) {
    const whole = await finishAs(bytes, chosen, null, binding, act);
    if ("decline" in whole && NOTHING_TO_SIGN.test(whole.decline.detail)) return { signed: null, h };
    if ("decline" in whole) return whole;
    if ("next" in whole) return declined("signed-not-bound", "The pairing asked for a signature it did not request.");
    return whole;
  }
  const piece = pieceOf(binding)!;
  const moves = piece.moves !== undefined && piece.moves(first);
  const answers: Signature[] = [];
  let request: SigningRequest = first;
  let opened: Opened | undefined;
  for (let step = 0; step < MAX_STEPS; step++) {
    let summary: Summary | undefined;
    if (approval !== undefined) {
      const at = { index: step, count: Math.max(count, step + 1) };
      const approved = await approves(binding, act, request, bytes, at, approval, networkOfAccount(signer.account), opened);
      if ("decline" in approved) {
        return moves && answers.length > 0 ? { ...approved, moved: { signed: answers.length === 1 ? answers[0] : answers, bytes, h } } : approved;
      }
      summary = approved;
    }
    try {
      answers.push(await signer.sign(request));
    } catch {
      const d = declined("signer-failed", "The signer did not sign.");
      return moves && answers.length > 0 ? { ...d, moved: { signed: answers.length === 1 ? answers[0] : answers, bytes, h } } : d;
    }
    const finished = await finishAs(bytes, chosen, answers.length === 1 ? answers[0]! : answers, binding, act);
    if ("decline" in finished) return finished;
    if (!("next" in finished)) return finished;
    if (step === 0 && summary !== undefined) opened = openedBy(request, summary, answers[0]!);
    request = finished.next;
  }
  const d = declined("signed-not-bound", "The pairing asked for more signatures than a payment takes.");
  return moves ? { ...d, moved: { signed: answers, bytes, h } } : d;
}

function isNext(v: unknown): v is Next {
  return isObject(v) && isObject(v["next"]);
}
