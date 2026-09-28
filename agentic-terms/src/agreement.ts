/**
 * The agreement payment, in two calls. Called without an approved payment, `agree` asks the agreement URL for its
 * challenge and returns the agreement payment for the buyer's agent to approve, signing nothing: the challenge's first
 * option, in document order, that the signer can pay with a pairing whose payment is itself a public proof of the ATR
 * hash. Called with the payment the agent approved, it signs exactly that payment, sends it, and returns the resource's
 * receipt once the payment is recorded. Nothing is signed when the challenge advertises another hash, and nothing is
 * sent unless what was signed carries the hash. Once sent, the same signed payment is sent again after each 202, 5xx
 * or timeout, each paid request bounded by min(`maxTimeoutSeconds`, 120) + 60 + 10 seconds and the whole exchange by
 * the paid option's `maxTimeoutSeconds` + 180 seconds; no second agreement payment is signed, and every decline after
 * it was sent carries it as `moved`. A caller's `signal` ends the exchange at its next step.
 */
import {
  BINDINGS,
  hash,
  hashEquals,
  isHttpsLink,
  isOtherSchemeLink,
  parseJson,
  type AtrHash,
  type Refusal,
} from "@integraledger/lcp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { IDENTITY, isIdentity, newRef, pay, pieceOf, redirected } from "./gate.js";
import { isRefusal } from "./pairings/common.js";
import type {
  AgreeOptions,
  AgreementPayment,
  AgreementReceipt,
  Binding,
  BuyerPiece,
  Chosen,
  DeclineCode,
  Declined,
  Fetch,
  Inputs,
  Presented,
  Read,
  Signer,
  ToApprove,
} from "./types.js";

const UNPAID_DEADLINE_MS = 10_000;
const EXCHANGE_CAP_S = 120;
const SETTLE_S = 60;
const VERIFY_S = 10;
const WINDOW_EXTRA_S = 180;
const MAX_ANSWER_BYTES = 65_536;
const MAX_OPTIONS = 32;
/** The answers whose content the exchange reads: a receipt, and a payment request. */
const READ_STATUSES: readonly number[] = [200, 402];
const RETRY_DEFAULT_S = 2;
const RETRY_MIN_S = 1;
const DECIMAL = /^[0-9]{1,9}$/;

interface Answer {
  status: number;
  paymentRequired: string | null;
  retryAfter: string | null;
  body: Uint8Array | null;
}

/** A request that reached no answer: its deadline passed, the caller's signal ended it, or the URL could not be reached. */
interface Unanswered {
  unanswered: true;
}

function declined(code: DeclineCode, detail: string): Declined {
  return { decline: { code, detail } };
}

const failed = (detail: string): Declined => declined("agreement-failed", detail);
/** Whether the caller's signal has ended the exchange. */
const isEnded = (signal: AbortSignal | undefined): boolean => signal?.aborted === true;
const ended = (): Declined => failed("The caller's signal ended the agreement exchange before the payment was sent.");

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Standard base64 of the UTF-8 bytes of `text`. */
function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** The JSON value a base64 header carries, or undefined when it is not base64 of UTF-8 JSON. */
function fromBase64Json(header: string): unknown {
  if (header.length > MAX_ANSWER_BYTES) return undefined;
  try {
    const binary = atob(header);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
}

/** `retry-after` in whole seconds, at least 1; 2 when absent or not a number of seconds. */
function retrySeconds(header: string | null): number {
  const v = header?.trim();
  if (v === undefined || !DECIMAL.test(v)) return RETRY_DEFAULT_S;
  return Math.max(RETRY_MIN_S, Number(v));
}

/** A 5xx answer to the paid request, which is read as a timeout: the same payment is sent again. */
function isServerError(status: number): boolean {
  return status >= 500 && status <= 599;
}

/** Waits `ms`, or less when the caller's signal ends the wait. */
function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve) => {
    const done = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
    if (signal?.aborted === true) done();
  });
}

/**
 * One GET of the agreement URL, asking for the identity coding, with no redirect followed and a deadline of `ms` over
 * headers and body; the caller's signal ends it as the deadline does. A redirect is `agreement-failed`, and so is a 200
 * or a 402, the answers the exchange reads, whose `Content-Encoding` names any coding. A 200 body is read as sent, up to
 * 64 KiB; any other body is cancelled unread.
 */
async function get(
  fetch: Fetch,
  url: string,
  signature: string | undefined,
  ms: number,
  signal: AbortSignal | undefined,
): Promise<Answer | Unanswered | Declined> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new DOMException("The agreement request passed its deadline.", "TimeoutError")),
    ms,
  );
  const onAbort = (): void => controller.abort(signal?.reason);
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted === true) onAbort();
  const deadline = new Promise<never>((_, reject) => {
    if (controller.signal.aborted) reject(controller.signal.reason);
    controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
  });
  deadline.catch(() => undefined);

  let body: ReadableStream<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let whole = false;
  try {
    const headers: Record<string, string> = { ...IDENTITY };
    if (signature !== undefined) headers["PAYMENT-SIGNATURE"] = signature;
    const init: Parameters<Fetch>[1] = { method: "GET", redirect: "manual", signal: controller.signal, headers };
    const response = await Promise.race([fetch(url, init), deadline]);
    body = response.body;
    if (redirected(response)) return failed("The agreement URL answered with a redirect.");
    const answer: Answer = {
      status: response.status,
      paymentRequired: response.headers.get("payment-required"),
      retryAfter: response.headers.get("retry-after"),
      body: null,
    };
    if (READ_STATUSES.includes(response.status) && !isIdentity(response.headers.get("content-encoding"))) {
      return failed("The agreement URL served a content coding other than identity.");
    }
    if (response.status !== 200) return answer;
    const declared = response.headers.get("content-length")?.trim();
    if (declared !== undefined && /^[0-9]+$/.test(declared) && Number(declared) > MAX_ANSWER_BYTES) {
      return failed("The agreement receipt is larger than 64 KiB.");
    }
    if (body === null) {
      whole = true;
      return { ...answer, body: new Uint8Array(0) };
    }
    reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const next = await Promise.race([reader.read(), deadline]);
      if (next.done) break;
      if (!(next.value instanceof Uint8Array)) return failed("The agreement URL served a non-byte chunk.");
      total += next.value.length;
      if (total > MAX_ANSWER_BYTES) return failed("The agreement receipt is larger than 64 KiB.");
      chunks.push(next.value);
    }
    whole = true;
    const bytes = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      bytes.set(c, at);
      at += c.length;
    }
    return { ...answer, body: bytes };
  } catch {
    return { unanswered: true };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
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

/** The receipt a 200 carries, when it is the agreement receipt for `h`. */
function receiptOf(body: Uint8Array | null, h: AtrHash): { receipt: AgreementReceipt } | Declined {
  let parsed: unknown;
  try {
    parsed = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(body ?? new Uint8Array(0)));
  } catch {
    return failed("The agreement URL answered 200 without a JSON receipt.");
  }
  if (!isObject(parsed)) return failed("The agreement URL answered 200 without a JSON receipt.");
  const { atrHash, agreed, network, transaction } = parsed;
  if (typeof atrHash !== "string" || !hashEquals(atrHash, h)) {
    return failed("The agreement receipt names another ATR hash.");
  }
  if (agreed !== true || typeof network !== "string" || typeof transaction !== "string") {
    return failed("The agreement receipt is not a recorded agreement.");
  }
  return { receipt: { atrHash: atrHash as AtrHash, agreed, network, transaction } };
}

function isPublicProof(binding: Binding): boolean {
  const pattern: unknown = (binding as { pattern?: unknown }).pattern;
  return isObject(pattern) && pattern["publicProof"] === true;
}

/** The x402 pairings the gate pays, in the protocol package's order. */
const X402: readonly Binding[] = (BINDINGS as readonly Binding[]).filter(
  (b) => String(b.id).startsWith("x402/") && pieceOf(b) !== undefined,
);

/** What the gate pays for an agreement: the option, its pairing, the challenge holding only that option, and the choice. */
interface Selected {
  option: PaymentRequirements;
  binding: Binding;
  read: Read;
  chosen: Chosen;
}

/**
 * The option the agreement is paid with, by the main payment's rule: the options in document order, and the first one
 * the signer can pay whose pairing's payment is itself a public proof. An option's pairing is the first x402 pairing,
 * in the protocol package's order, whose read accepts the challenge holding only that option.
 */
async function select(required: Record<string, unknown>, account: string, inputs: Inputs): Promise<Selected | Declined> {
  const accepts = required["accepts"];
  if (!Array.isArray(accepts) || accepts.length === 0) return declined("offer-unreadable", "x402/no-payable-option");
  if (accepts.length > MAX_OPTIONS) return declined("offer-unreadable", "x402/option-malformed");
  const now = Math.floor(Date.now() / 1000);
  let unreadable: string | undefined;
  let unpayable: string | undefined;
  for (const option of accepts) {
    if (!isObject(option)) continue;
    const only = { ...required, accepts: [option] };
    let found: { binding: Binding; read: Read } | undefined;
    for (const binding of X402) {
      const read = (binding as unknown as { read(d: unknown): Read | Refusal }).read(only);
      if (!isRefusal(read)) {
        found = { binding, read };
        break;
      }
      if (read.code !== "x402/no-payable-option") unreadable ??= read.code;
    }
    if (found === undefined || !isPublicProof(found.binding)) continue;
    const piece = pieceOf(found.binding) as BuyerPiece;
    const chosen = await piece.choose(found.read, account, inputs, now, newRef(), only);
    if (isRefusal(chosen)) {
      unpayable ??= chosen.code;
      continue;
    }
    return { option: option as unknown as PaymentRequirements, binding: found.binding, read: found.read, chosen };
  }
  if (unpayable === undefined && unreadable !== undefined) return declined("offer-unreadable", unreadable);
  return declined("no-payable-option", unpayable ?? "x402/no-payable-option");
}

/**
 * The paid request's deadline and the whole exchange's, in seconds, from the option's `maxTimeoutSeconds`: a JSON number
 * with an integral value from 1 to 2^53 - 1.
 */
function bounds(option: PaymentRequirements): { request: number; exchange: number } | undefined {
  const t: unknown = option.maxTimeoutSeconds;
  if (typeof t !== "number" || !Number.isSafeInteger(t) || t <= 0) return undefined;
  return { request: Math.min(t, EXCHANGE_CAP_S) + SETTLE_S + VERIFY_S, exchange: t + WINDOW_EXTRA_S };
}

/** The option chosen from `required` for `h`, with its bounds, once the challenge is found to advertise `h`. */
async function paying(
  required: Record<string, unknown>,
  h: AtrHash,
  account: string,
  inputs: Inputs,
): Promise<{ selected: Selected; limits: { request: number; exchange: number } } | Declined> {
  const selected = await select(required, account, inputs);
  if ("decline" in selected) return selected;
  const limits = bounds(selected.option);
  if (limits === undefined) return declined("offer-unreadable", "x402/option-malformed");
  if (!hashEquals(selected.read.h, h)) {
    return declined("hash-mismatch", "The agreement challenge advertises another ATR hash.");
  }
  return { selected, limits };
}

/** Whether `v` has the form of an agreement payment: an agreement URL, an option and a payment request. */
function isAgreementPayment(v: unknown): v is AgreementPayment {
  return isObject(v) && typeof v["url"] === "string" && isObject(v["option"]) && isObject(v["required"]);
}

/**
 * Without `approved`: asks the agreement URL for its challenge and returns the agreement payment to approve, signing
 * nothing, or the receipt where the agreement is already recorded. With `approved`: signs exactly that payment with
 * `signer`, sends it to `url`, and returns the receipt once recorded. `bytes` are the ATR the gate compared, whose hash
 * the agreement payment carries; `inputs` are the buyer's own chain values; `signal` ends the exchange.
 */
export function agree(
  bytes: Uint8Array,
  url: string,
  signer: Signer,
  fetch: Fetch,
  options?: AgreeOptions,
): Promise<ToApprove | { receipt: AgreementReceipt } | Declined> {
  return exchange(bytes, url, signer, fetch, options ?? {}, undefined);
}

/**
 * `agree`, where `ns` is the namespace of the pairing whose offer named the URL: a refused URL's detail carries it with
 * the protocol package's code.
 */
export async function exchange(
  bytes: Uint8Array,
  url: string,
  signer: Signer,
  fetch: Fetch,
  options: AgreeOptions,
  ns: string | undefined,
): Promise<ToApprove | { receipt: AgreementReceipt } | Declined> {
  if (!isHttpsLink(url)) {
    const fault = isOtherSchemeLink(url) ? "link-not-https" : "legal-context-malformed";
    return declined("link-not-https", ns === undefined ? "The agreement URL is not an https URL." : `${ns}/${fault}`);
  }
  const { approved, signal } = options;
  const inputs: Inputs = isObject(options.inputs) ? options.inputs : {};
  if (approved !== undefined && !isAgreementPayment(approved)) {
    return declined("no-payable-option", `${ns ?? "x402"}/input-malformed`);
  }
  if (isEnded(signal)) return ended();
  const h = await hash(bytes);
  if (approved === undefined) return offer(bytes, h, url, signer, fetch, inputs, signal);
  if (approved.url !== url) return failed("The approved agreement payment names another agreement URL.");

  const found = await paying({ ...approved.required, accepts: [approved.option] }, h, signer.account, inputs);
  if ("decline" in found) return found;
  const { selected, limits } = found;
  const paid = await pay(selected.binding, selected.chosen, signer, bytes);
  if ("decline" in paid) return paid;
  if (paid.signed === null) return declined("offer-unreadable", "The agreement payment gave nothing to sign.");
  if (isEnded(signal)) return ended();
  const signed: Presented = paid.signed;
  const payment = toBase64(JSON.stringify(signed));
  const moved = { signed, bytes, h };
  const keep = (d: Declined): Declined => ({ ...d, moved });
  const pending = (detail: string): Declined => keep(declined("agreement-pending", detail));

  const end = Date.now() + limits.exchange * 1000;
  for (;;) {
    const remaining = end - Date.now();
    if (remaining <= 0) return pending("The agreement payment was sent and is not yet recorded.");
    const answer = await get(fetch, url, payment, Math.min(limits.request * 1000, remaining), signal);
    if (isEnded(signal)) return pending("The caller's signal ended the exchange after the agreement payment was sent.");
    if ("decline" in answer) return keep(answer);
    let wait = RETRY_DEFAULT_S * 1000;
    if (!("unanswered" in answer) && !isServerError(answer.status)) {
      if (answer.status === 200) {
        const r = receiptOf(answer.body, h);
        return "decline" in r ? keep(r) : r;
      }
      if (answer.status !== 202) return keep(failed(`The agreement URL answered status ${answer.status} to the payment.`));
      wait = retrySeconds(answer.retryAfter) * 1000;
    }
    await sleep(Math.max(0, Math.min(wait, end - Date.now())), signal);
    if (isEnded(signal)) return pending("The caller's signal ended the exchange after the agreement payment was sent.");
  }
}

/** The unpaid request: the agreement payment to approve, the receipt of an agreement already recorded, or a decline. */
async function offer(
  bytes: Uint8Array,
  h: AtrHash,
  url: string,
  signer: Signer,
  fetch: Fetch,
  inputs: Inputs,
  signal: AbortSignal | undefined,
): Promise<ToApprove | { receipt: AgreementReceipt } | Declined> {
  const unpaid = await get(fetch, url, undefined, UNPAID_DEADLINE_MS, signal);
  if (isEnded(signal)) return ended();
  if ("decline" in unpaid) return unpaid;
  if ("unanswered" in unpaid) return failed("The agreement URL could not be reached.");
  if (unpaid.status === 200) return receiptOf(unpaid.body, h);
  if (unpaid.status === 202) {
    return declined("agreement-pending", "An agreement payment for this ATR is already settling.");
  }
  if (unpaid.status !== 402) return failed(`The agreement URL answered status ${unpaid.status}.`);

  const required = unpaid.paymentRequired === null ? undefined : fromBase64Json(unpaid.paymentRequired);
  if (!isObject(required)) return failed("The agreement URL answered 402 without a readable PAYMENT-REQUIRED.");
  const found = await paying(required, h, signer.account, inputs);
  if ("decline" in found) return found;
  return { approve: { url, option: found.selected.option, required: required as unknown as PaymentRequired }, bytes, h };
}
