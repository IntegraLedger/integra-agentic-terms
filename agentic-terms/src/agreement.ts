/**
 * The agreement payment. `agree` asks the agreement URL for its challenge, pays it through the buyer piece of the
 * pairing that placed it, a pairing whose payment is itself a public proof of the ATR hash, and returns the resource's
 * receipt once the payment is recorded. Nothing is signed when the challenge advertises another hash, and nothing is
 * sent unless what was signed carries the hash. Once sent, the same signed payment is sent again after each 202, 5xx or
 * timeout, each paid request bounded by min(`maxTimeoutSeconds`, 120) + 60 + 10 seconds and the whole exchange by the
 * agreement option's `maxTimeoutSeconds` + 180 seconds; no second agreement payment is signed, and every decline after
 * it was sent carries it as `moved`.
 */
import { BINDINGS, hashEquals, isHttpsLink, isOtherSchemeLink, pairingOf, parseJson, type AtrHash, type Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import { pay, redirected } from "./gate.js";
import type { AgreementReceipt, Binding, DeclineCode, Declined, Fetch, Inputs, Presented, Signer } from "./types.js";

const UNPAID_DEADLINE_MS = 10_000;
const EXCHANGE_CAP_S = 120;
const SETTLE_S = 60;
const VERIFY_S = 10;
const WINDOW_EXTRA_S = 180;
const MAX_ANSWER_BYTES = 65_536;
const RETRY_DEFAULT_S = 2;
const RETRY_MIN_S = 1;
const DECIMAL = /^[0-9]{1,9}$/;

interface Answer {
  status: number;
  paymentRequired: string | null;
  retryAfter: string | null;
  body: Uint8Array | null;
}

/** A request that reached no answer: its deadline passed, or the URL could not be reached. */
interface Unanswered {
  unanswered: true;
}

function declined(code: DeclineCode, detail: string): Declined {
  return { decline: { code, detail } };
}

const failed = (detail: string): Declined => declined("agreement-failed", detail);

function isRefusal(v: unknown): v is Refusal {
  return typeof v === "object" && v !== null && (v as { refused?: unknown }).refused === true;
}

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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * One GET of the agreement URL, with no redirect followed and a deadline of `ms` over headers and body. A redirect is
 * `agreement-failed`. A 200 body is read up to 64 KiB; any other body is cancelled unread.
 */
async function get(
  fetch: Fetch,
  url: string,
  signature: string | undefined,
  ms: number,
): Promise<Answer | Unanswered | Declined> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new DOMException("The agreement request passed its deadline.", "TimeoutError")),
    ms,
  );
  const deadline = new Promise<never>((_, reject) => {
    controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
  });
  deadline.catch(() => undefined);

  let body: ReadableStream<Uint8Array> | null = null;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let whole = false;
  try {
    const init: Parameters<Fetch>[1] = { method: "GET", redirect: "manual", signal: controller.signal };
    if (signature !== undefined) init.headers = { "PAYMENT-SIGNATURE": signature };
    const response = await Promise.race([fetch(url, init), deadline]);
    body = response.body;
    if (redirected(response)) return failed("The agreement URL answered with a redirect.");
    const answer: Answer = {
      status: response.status,
      paymentRequired: response.headers.get("payment-required"),
      retryAfter: response.headers.get("retry-after"),
      body: null,
    };
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

/** The pairing that placed the agreement option, when its payment is itself a public proof, with that option. */
function agreementPairing(required: unknown): { binding: Binding; option: PaymentRequirements } | Declined {
  const accepts = isObject(required) ? required["accepts"] : undefined;
  if (!Array.isArray(accepts) || accepts.length === 0 || !isObject(accepts[0])) {
    return declined("offer-unreadable", "x402/no-payable-option");
  }
  const option = accepts[0] as unknown as PaymentRequirements;
  const id = pairingOf(option);
  const binding = id === undefined ? undefined : (BINDINGS.find((b) => b.id === id) as Binding | undefined);
  if (binding === undefined) return declined("pairing-not-supported", "The agreement option names no pairing the gate serves.");
  if (!isPublicProof(binding)) {
    return declined("pairing-not-supported", `The agreement pairing ${String(id)} is not itself a public proof.`);
  }
  return { binding, option };
}

/** The paid request's deadline and the whole exchange's, in seconds, from the agreement option's `maxTimeoutSeconds`. */
function bounds(option: PaymentRequirements): { request: number; exchange: number } | undefined {
  const t: unknown = option.maxTimeoutSeconds;
  if (typeof t !== "number" || !Number.isSafeInteger(t) || t <= 0) return undefined;
  return { request: Math.min(t, EXCHANGE_CAP_S) + SETTLE_S + VERIFY_S, exchange: t + WINDOW_EXTRA_S };
}

/**
 * Pays the agreement for `h` at `url` with `signer`, and returns the receipt. `bytes` are the ATR the gate compared,
 * for a pairing whose build reads them; `inputs` are the buyer's own chain values; `ns` is the namespace of the pairing
 * whose offer named the URL, which a refused URL's detail carries with the protocol package's code.
 */
export async function agree(
  h: AtrHash,
  url: string,
  signer: Signer,
  fetch: Fetch,
  held: { bytes: Uint8Array; inputs?: Inputs; ns?: string },
): Promise<{ receipt: AgreementReceipt } | Declined> {
  if (!isHttpsLink(url)) {
    const fault = isOtherSchemeLink(url) ? "link-not-https" : "legal-context-malformed";
    return declined("link-not-https", held.ns === undefined ? "The agreement URL is not an https URL." : `${held.ns}/${fault}`);
  }
  const { bytes } = held;
  const inputs = held.inputs ?? {};

  const unpaid = await get(fetch, url, undefined, UNPAID_DEADLINE_MS);
  if ("decline" in unpaid) return unpaid;
  if ("unanswered" in unpaid) return failed("The agreement URL could not be reached.");
  if (unpaid.status === 200) return receiptOf(unpaid.body, h);
  if (unpaid.status === 202) {
    return declined("agreement-pending", "An agreement payment for this ATR is already settling.");
  }
  if (unpaid.status !== 402) return failed(`The agreement URL answered status ${unpaid.status}.`);

  const required = unpaid.paymentRequired === null ? undefined : fromBase64Json(unpaid.paymentRequired);
  if (required === undefined) return failed("The agreement URL answered 402 without a readable PAYMENT-REQUIRED.");
  const found = agreementPairing(required);
  if ("decline" in found) return found;
  const limits = bounds(found.option);
  if (limits === undefined) return declined("offer-unreadable", "x402/option-malformed");
  const read = (found.binding as unknown as { read(d: unknown): { h: AtrHash; link: string } | Refusal }).read(required);
  if (isRefusal(read)) return declined("offer-unreadable", read.code);
  if (!hashEquals(read.h, h)) {
    return declined("hash-mismatch", "The agreement challenge advertises another ATR hash.");
  }

  const paid = await pay(found.binding, read, required, signer, inputs, bytes);
  if ("decline" in paid) return paid;
  if (paid.signed === null) return declined("offer-unreadable", "The agreement payment gave nothing to sign.");
  const signed: Presented = paid.signed;
  const payment = toBase64(JSON.stringify(signed));
  const moved = { signed, bytes, h };
  const keep = (d: Declined): Declined => ({ ...d, moved });

  const end = Date.now() + limits.exchange * 1000;
  for (;;) {
    const remaining = end - Date.now();
    if (remaining <= 0) return keep(declined("agreement-pending", "The agreement payment was sent and is not yet recorded."));
    const answer = await get(fetch, url, payment, Math.min(limits.request * 1000, remaining));
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
    await sleep(Math.max(0, Math.min(wait, end - Date.now())));
  }
}
