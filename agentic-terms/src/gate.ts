/**
 * The buyer gate. `confirm` reads the offer, fetches the ATR from the seller's link, compares its SHA-256 with the
 * advertised hash, and only on a match builds the signing request with the hash it computed. `finish` completes the
 * payment with the signature and returns it only when the pairing's `bound` reads the hash of these bytes from the
 * completed payment, or, for a pairing whose proof is the agreement payment, completes it without that reading. `check`
 * confirms a payment held later against kept bytes.
 */
import {
  hash,
  hashEquals,
  isHttpsLink,
  isOtherSchemeLink,
  toBase64Url,
  type AtrHash,
  type Refusal,
} from "@integraledger/lcp/core";
import { fetchedOf, held, isRefusal, jsonSafe, refuse } from "./pairings/common.js";
import { PIECES } from "./pairings/index.js";
import {
  MAX_ATR_BYTES,
  type Binding,
  type BuyerPiece,
  type Chosen,
  type DeclineCode,
  type Declined,
  type Fetch,
  type Inputs,
  type Next,
  type Presented,
  type Read,
  type Signature,
  type Signer,
  type SigningRequest,
} from "./types.js";

/** The binding members the gate calls, whatever the pairing's own types. */
interface Steps {
  id: string;
  read(doc: unknown): Read | Refusal;
  build(choice: unknown, h: AtrHash): Promise<unknown>;
  bound(presented: unknown): Promise<AtrHash | Refusal> | AtrHash | Refusal;
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

/** Whether the pairing's payment is itself a public proof of the hash, so the offer's agreement URL is not paid. */
function isPublicProof(binding: Binding): boolean {
  const pattern: unknown = isObject(binding) ? (binding as { pattern?: unknown }).pattern : undefined;
  return isObject(pattern) && pattern["publicProof"] === true;
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
async function fetchAtr(fetch: Fetch, link: string): Promise<Uint8Array | Declined> {
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
 * Reads the offer, chooses the option, fetches the ATR and compares its SHA-256 with the advertised hash. Only on a
 * match does it build, with the hash it computed. `request` is what the signer is handed, or `null` when nothing is
 * handed to the signer: the pairing has nothing for the buyer to sign, or the build is itself the payment, which
 * `finish` completes with no signature. For a pairing whose payment is not itself a public proof, `chosen.agreement` is
 * the agreement URL the offer names. `inputs` that is not an object is declined `no-payable-option` with
 * `<namespace>/input-malformed` before the offer is read.
 */
export async function confirm(
  doc: unknown,
  binding: Binding,
  account: string,
  fetch: Fetch,
  inputs: Inputs = {},
): Promise<{ chosen: Chosen; request: SigningRequest | null; bytes: Uint8Array; h: AtrHash } | Declined> {
  const piece = pieceOf(binding);
  if (piece === undefined) return unsupported(binding);
  if (!isObject(inputs)) return declined("no-payable-option", `${namespaceOf(binding)}/input-malformed`);
  const b = steps(binding);

  const read = b.read(doc);
  if (isRefusal(read)) return declined("offer-unreadable", read.code);
  const agreement: unknown = isPublicProof(binding) ? undefined : (read as { agreement?: unknown }).agreement;
  if (agreement !== undefined && typeof agreement !== "string") {
    return declined("offer-unreadable", "The offer names an agreement URL that is not a string.");
  }

  const choice = await piece.choose(read, account, inputs, Math.floor(Date.now() / 1000), newRef(), doc);
  if (isRefusal(choice)) return declined("no-payable-option", choice.code);
  const chosen: Chosen = agreement === undefined ? choice : { ...choice, agreement };

  if (!isHttpsLink(read.link)) return declined("link-not-https", linkRefusal(binding, read.link));

  const bytes = await fetchAtr(fetch, read.link);
  if (!(bytes instanceof Uint8Array)) return bytes;

  const computed = await hash(bytes);
  if (!hashEquals(read.h, computed)) {
    return declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.");
  }
  if (!isPublicProof(binding) && agreement === undefined) {
    return declined("agreement-not-offered", "The pairing's payment carries no public proof and the offer names no agreement URL.");
  }

  const unsigned = await buildWith(piece, b, chosen, computed, bytes);
  if (isRefusal(unsigned)) {
    if (NOTHING_TO_SIGN.test(unsigned.code)) return { chosen, request: null, bytes, h: computed };
    return declined("offer-unreadable", unsigned.code);
  }
  const request = piece.request(unsigned);
  if (isRefusal(request)) return declined("offer-unreadable", request.code);
  return { chosen, request, bytes, h: computed };
}

/** The pairing's build over the choice the piece revives from `chosen`. */
async function buildWith(piece: BuyerPiece, b: Steps, chosen: Chosen, h: AtrHash, bytes: Uint8Array): Promise<unknown> {
  const choice = piece.choice(chosen, bytes);
  if (isRefusal(choice)) return choice;
  try {
    return await (piece.build !== undefined ? piece.build(choice, h) : b.build(choice, h));
  } catch {
    return refuse(`${b.id.split("/")[0]}/build-failed`);
  }
}

/**
 * Rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and returns the payment only when the
 * pairing's `bound` reads the hash of these bytes from the completed payment. For a pairing whose payment is not a
 * public proof and whose `bound` finds no signed place for the hash, the proof is the agreement payment, and the
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
): Promise<{ signed: Presented; landed?: unknown; h: AtrHash } | { next: SigningRequest; h: AtrHash } | Declined> {
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
  const unsigned = await buildWith(piece, b, chosen, h, bytes);
  if (isRefusal(unsigned)) return declined("offer-unreadable", unsigned.code);
  const moves = signature !== null && movesWith(piece, unsigned);
  const keep = (d: Declined, signed: unknown): Declined => (moves ? { ...d, moved: { signed, bytes, h } } : d);

  let signed: Presented | Next | Refusal;
  try {
    signed = await piece.complete(unsigned, signature, chosen);
  } catch {
    return keep(declined("signed-not-bound", "The signer's answer did not complete the payment."), signature);
  }
  if (isRefusal(signed)) return keep(declined("signed-not-bound", signed.code), signature);
  if (isNext(signed)) return { next: signed.next, h };

  const sent = piece.sent !== undefined ? piece.sent(signed) : signed;
  const inside = await boundOf(b, signed);
  const onAgreement = !isPublicProof(binding) && isRefusal(inside) && NOTHING_TO_SIGN.test(inside.code);
  if (!onAgreement && (isRefusal(inside) || !hashEquals(inside, h))) {
    return keep(
      declined("signed-not-bound", "The pairing does not read the hash of the compared bytes from the payment."),
      sent,
    );
  }
  const landed = sent !== signed ? jsonSafe(fetchedOf(signed)) : undefined;
  return landed === undefined ? { signed: sent, h } : { signed: sent, landed, h };
}

/** Whether the signer, handed the build's first request, moves the payment itself. */
function movesWith(piece: BuyerPiece, unsigned: unknown): boolean {
  if (piece.moves === undefined) return false;
  const request = piece.request(unsigned);
  return request !== null && !isRefusal(request) && piece.moves(request);
}

/** The binding's `bound`, with a throw read as a refusal. */
async function boundOf(b: Steps, presented: unknown): Promise<AtrHash | Refusal> {
  try {
    return await b.bound(presented);
  } catch {
    return refuse("bound-failed");
  }
}

/**
 * Confirms that the ATR hash the pairing reads from a payment held later is the SHA-256 of the kept bytes, with the
 * `landed` receipt `finish` or `transact` returned beside the payment, where it returned one, held under the payment's
 * own `FETCHED` member as `bound` reads it. The caller passes as `landed` only the receipt its own reader read for the
 * payment, as `finish` or `transact` returned it, never a value another party sent. A `landed` of `null` is no
 * receipt: the payment is read alone, as without one. A payment from which the pairing reads no ATR hash is declined
 * `signed-not-bound`, as is a `landed` receipt that is not a JSON object beside a payment that is one. A `landed`
 * member of the payment's own is not read.
 */
export async function check(
  bytes: Uint8Array,
  presented: unknown,
  binding: Binding,
  landed?: unknown,
): Promise<{ h: AtrHash } | Declined> {
  if (bytes.length > MAX_ATR_BYTES) return tooLarge();
  const read = landed === null ? undefined : landed;
  if (read !== undefined && (!isObject(read) || !isObject(presented))) {
    return declined("signed-not-bound", "The landed receipt is not a JSON object beside the payment.");
  }
  const h = await hash(bytes);
  const b = await boundOf(steps(binding), read === undefined ? presented : held(presented as object, read));
  if (isRefusal(b) || !hashEquals(b, h)) {
    return declined("signed-not-bound", "The pairing does not read the hash of the compared bytes from the payment.");
  }
  return { h };
}

/**
 * Builds and signs the payment `chosen` names, with the hash of `bytes`: the signer is called once, or, for a pairing
 * signed in steps, once per step in order, and the payment is returned only through `finish`. `signed` is null where the
 * pairing has nothing for the buyer to sign.
 */
export async function pay(
  binding: Binding,
  chosen: Chosen,
  signer: Signer,
  bytes: Uint8Array,
): Promise<{ signed: Presented | null; landed?: unknown; h: AtrHash } | Declined> {
  const piece = pieceOf(binding);
  if (piece === undefined) return unsupported(binding);
  const h = await hash(bytes);
  const unsigned = await buildWith(piece, steps(binding), chosen, h, bytes);
  if (isRefusal(unsigned)) {
    if (NOTHING_TO_SIGN.test(unsigned.code)) return { signed: null, h };
    return declined("offer-unreadable", unsigned.code);
  }
  const request = piece.request(unsigned);
  if (isRefusal(request)) return declined("offer-unreadable", request.code);
  return signSteps(binding, chosen, request, signer, bytes, h);
}

/**
 * The signer, once per step in order, then `finish` over its answers. A request of null is a build that is itself the
 * payment: `finish` completes it with no signer call.
 */
export async function signSteps(
  binding: Binding,
  chosen: Chosen,
  first: SigningRequest | null,
  signer: Signer,
  bytes: Uint8Array,
  h: AtrHash,
): Promise<{ signed: Presented | null; landed?: unknown; h: AtrHash } | Declined> {
  if (first === null) {
    const whole = await finish(bytes, chosen, null, binding);
    if ("decline" in whole && NOTHING_TO_SIGN.test(whole.decline.detail)) return { signed: null, h };
    if ("decline" in whole) return whole;
    if ("next" in whole) return declined("signed-not-bound", "The pairing asked for a signature it did not request.");
    return whole;
  }
  const piece = pieceOf(binding)!;
  const moves = piece.moves !== undefined && piece.moves(first);
  const answers: Signature[] = [];
  let request: SigningRequest = first;
  for (let step = 0; step < MAX_STEPS; step++) {
    try {
      answers.push(await signer.sign(request));
    } catch {
      const d = declined("signer-failed", "The signer did not sign.");
      return moves && answers.length > 0 ? { ...d, moved: { signed: answers.length === 1 ? answers[0] : answers, bytes, h } } : d;
    }
    const finished = await finish(bytes, chosen, answers.length === 1 ? answers[0]! : answers, binding);
    if ("decline" in finished) return finished;
    if (!("next" in finished)) return finished;
    request = finished.next;
  }
  const d = declined("signed-not-bound", "The pairing asked for more signatures than a payment takes.");
  return moves ? { ...d, moved: { signed: answers, bytes, h } } : d;
}

function isNext(v: unknown): v is Next {
  return isObject(v) && isObject(v["next"]);
}
