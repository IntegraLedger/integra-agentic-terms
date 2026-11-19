/**
 * The agreement payment, in two calls. Called without an approved payment, `agree` asks the agreement URL for its
 * challenge and returns the agreement payment for the buyer's agent to approve, signing nothing: the challenge's first
 * option, in document order, that the signer can pay with a pairing whose payment can itself be an agreement (its data
 * holds `agreement`) and that the charge's `agreementOn` admits, where the charge is given; where the agreement URL's 402
 * offers no x402 option and MPP agreement challenges, it returns those, which terms builds no credential for, for the
 * caller's own MPP client. Called with the payment the agent approved, it builds exactly that payment as the act
 * `agreement`, holds it to its summary and its own pairing's ceiling, signs it, sends it, and returns the resource's
 * receipt once the payment is recorded. Nothing is signed when the challenge advertises another hash, and nothing is
 * sent unless the pairing reads the hash from the completed payment. Once sent, the same signed payment is sent again
 * after each 202, 5xx or timeout, each paid request bounded by min(`maxTimeoutSeconds`, 120) + 60 + 10 seconds and the
 * whole exchange by the paid option's `maxTimeoutSeconds` + 180 seconds; no second agreement payment is signed, and
 * every decline after it was sent carries it as `moved`. A caller's `signal` ends the exchange at its next step.
 */
import {
  BINDINGS,
  canonicalJson,
  fromBase64,
  hash,
  hashEquals,
  isHttpsLink,
  isOtherSchemeLink,
  parseJson,
  servesOf,
  toBase64,
  type AtrHash,
  type Refusal,
} from "@integraledger/lcp";
import { network as mppNetwork, parseChallenges, read as mppRead, type MppChallenge } from "@integraledger/lcp/mpp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import type { Approval } from "./checks.js";
import { hasAccount, IDENTITY, isAgreementPairing, isIdentity, newRef, pay, pieceOf, redirected, trimHttpWhitespace } from "./gate.js";
import { isRefusal } from "./pairings/common.js";
import type {
  AgreeOptions,
  AgreementChallenges,
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
  /** The `WWW-Authenticate` field's value, its lines joined with ", " as Fetch joins them. */
  wwwAuthenticate: string | null;
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

/**
 * The JSON text `JSON.stringify` writes for the agreement payment, which the protocol package reads back: nested at
 * most 64 levels. Undefined when it nests deeper, or `JSON.stringify` writes nothing for it or throws.
 */
function paymentText(signed: unknown): string | undefined {
  try {
    const text = JSON.stringify(signed);
    return text !== undefined && parseJson(text) !== undefined ? text : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The JSON value a header of at most 64 KiB carries as padded standard base64 (RFC 4648 section 4) whose final
 * character's unused bits are zero, of UTF-8 JSON text nested at most 64 levels deep whose leading byte order mark is
 * kept as a character; undefined for anything else.
 */
function fromBase64Json(header: string): unknown {
  const bytes = header.length > MAX_ANSWER_BYTES ? null : fromBase64(header);
  if (bytes === null) return undefined;
  try {
    return parseJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    return undefined;
  }
}

/**
 * `retry-after` as one to nine decimal digits of seconds, surrounding spaces, tabs, CRs and LFs aside, at least 1; 2
 * for any other value or none.
 */
function retrySeconds(header: string | null): number {
  const v = header === null ? undefined : trimHttpWhitespace(header);
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
      wwwAuthenticate: response.headers.get("www-authenticate"),
      retryAfter: response.headers.get("retry-after"),
      body: null,
    };
    if (READ_STATUSES.includes(response.status) && !isIdentity(response.headers.get("content-encoding"))) {
      return failed("The agreement URL served a content coding other than identity.");
    }
    if (response.status !== 200) return answer;
    const length = response.headers.get("content-length");
    const declared = length === null ? undefined : trimHttpWhitespace(length);
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

/**
 * The receipt a 200 carries, read as UTF-8 JSON text whose leading byte order mark is kept as a character, when it is
 * the agreement receipt for `h`: its form (`agreed: true`, string `network` and `transaction`) and its `atrHash` are
 * checked, and the transaction it names is not read. `unpaid`, where the 200 answered the unpaid request, marks the
 * receipt `unpaid: true`: this call made no agreement payment and read none.
 */
function receiptOf(body: Uint8Array | null, h: AtrHash, unpaid = false): { receipt: AgreementReceipt } | Declined {
  let parsed: unknown;
  try {
    parsed = parseJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body ?? new Uint8Array(0)));
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
  const receipt: AgreementReceipt = { atrHash: atrHash as AtrHash, agreed, network, transaction };
  return { receipt: unpaid ? { ...receipt, unpaid: true } : receipt };
}

/** Whether an agreement option, paid with the pairing `agreement`, is one the charge can follow. */
type Admits = (agreement: Binding, option: Record<string, unknown>) => boolean;

const ANY: Admits = () => true;

/**
 * The network the charge `chosen` pays on, as its choice names it: an x402 choice's `accepted.network`, or the network
 * the protocol package's `network` reads from an MPP choice's `challenge`; undefined where the choice names neither.
 */
function chargeNetwork(chosen: Chosen): string | undefined {
  const choice: unknown = isObject(chosen) ? chosen.choice : undefined;
  if (!isObject(choice)) return undefined;
  const accepted = choice["accepted"];
  if (isObject(accepted)) return typeof accepted["network"] === "string" ? accepted["network"] : undefined;
  const challenge = choice["challenge"];
  if (!isObject(challenge)) return undefined;
  try {
    const n: unknown = mppNetwork(challenge as unknown as MppChallenge);
    return typeof n === "string" ? n : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The agreement options the charge paid through `binding` as `chosen` can follow, by the `agreementOn` of the
 * pairing's data: `any`, or none stated, any option; `same-network`, an option on the charge's own network; a pairing
 * id, an option of that pairing on that network. A charge whose network its choice does not name follows none but
 * under `any`.
 */
function admitting(binding: Binding, chosen: Chosen): Admits {
  const data: unknown = (binding as { data?: unknown }).data;
  const on: unknown = isObject(data) ? data["agreementOn"] : undefined;
  if (on === undefined || on === "any") return ANY;
  const network = chargeNetwork(chosen);
  return (agreement, option) =>
    network !== undefined && option["network"] === network && (on === "same-network" || agreement.id === on);
}

/** The x402 pairings the gate pays, in the protocol package's order. */
const X402: readonly Binding[] = (BINDINGS as readonly Binding[]).filter(
  (b) => String(b.id).startsWith("x402/") && pieceOf(b) !== undefined,
);

/**
 * What the gate pays for an agreement: the option, its pairing, the challenge holding only that option, the choice, and
 * the deadlines the option's `maxTimeoutSeconds` gives.
 */
interface Selected {
  option: PaymentRequirements;
  binding: Binding;
  read: Read;
  chosen: Chosen;
  limits: { request: number; exchange: number };
}

/**
 * The option the agreement is paid with, by the main payment's rule: the options in document order, and the first one
 * the signer can pay whose pairing's payment can itself be an agreement (`isAgreementPairing`) and which the charge
 * can follow (`admits`). An option's pairing is the first x402 pairing,
 * in the protocol package's order, whose read accepts the challenge holding only that option. An option whose
 * `maxTimeoutSeconds` gives no deadline (`bounds`) is not payable, whichever pairing reads it. An `accepts` that is
 * not a list, holds more than 32 entries or holds no object serves no option, and is declined `offer-unreadable` with
 * the code the read gives the whole challenge (`unservedCode`). With `approved`, the challenge is checked whole in the
 * same way and for a fault of its own (`challengeFault`), declined `offer-unreadable` with that code; then `approved`
 * must be one of `accepts` (`isOffered`), else it is declined `offer-unreadable` with `x402/option-not-in-document`;
 * and it is the one option read and chosen.
 */
async function select(
  required: Record<string, unknown>,
  account: string,
  inputs: Inputs,
  admits: Admits,
  approved?: PaymentRequirements,
): Promise<Selected | Declined> {
  const accepts = required["accepts"];
  if (!Array.isArray(accepts) || accepts.length > MAX_OPTIONS || !accepts.some((option) => isObject(option))) {
    return declined("offer-unreadable", unservedCode(required));
  }
  if (approved !== undefined) {
    const fault = challengeFault(required);
    if (fault !== undefined) return declined("offer-unreadable", fault);
    if (!isOffered(accepts, approved)) return declined("offer-unreadable", "x402/option-not-in-document");
  }
  const now = Math.floor(Date.now() / 1000);
  let unreadable: string | undefined;
  let unpayable: string | undefined;
  for (const option of approved === undefined ? accepts : [approved]) {
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
    if (found === undefined || !isAgreementPairing(found.binding) || !admits(found.binding, option)) continue;
    const limits = bounds(option as unknown as PaymentRequirements);
    if (limits === undefined) continue;
    const piece = pieceOf(found.binding) as BuyerPiece;
    const chosen = await piece.choose(found.read, account, inputs, now, newRef(), only);
    if (isRefusal(chosen)) {
      unpayable ??= chosen.code;
      continue;
    }
    return { option: option as unknown as PaymentRequirements, binding: found.binding, read: found.read, chosen, limits };
  }
  if (unpayable === undefined && unreadable !== undefined) return declined("offer-unreadable", unreadable);
  return declined("no-payable-option", unpayable ?? "x402/no-payable-option");
}

/**
 * The code the x402 reads give a challenge that serves no option: the first refusal, in the protocol package's order,
 * that is not `x402/no-payable-option` (a fault of the whole challenge, such as its version or legal context, or an
 * `accepts` that is not a list of at most 32 entries), else `x402/no-payable-option`.
 */
function unservedCode(required: Record<string, unknown>): string {
  for (const binding of X402) {
    const read = (binding as unknown as { read(d: unknown): Read | Refusal }).read(required);
    if (isRefusal(read) && read.code !== "x402/no-payable-option") return read.code;
  }
  return "x402/no-payable-option";
}

/**
 * The code the x402 reads give a challenge that none of them serves for a fault of its own beside its options, such as
 * its version, legal context or agreement URL (`unservedCode`); undefined when a read serves it, or when none refuses it
 * with a code other than `x402/no-payable-option`.
 */
function challengeFault(required: Record<string, unknown>): string | undefined {
  if (X402.some((binding) => !isRefusal((binding as unknown as { read(d: unknown): Read | Refusal }).read(required)))) {
    return undefined;
  }
  const code = unservedCode(required);
  return code === "x402/no-payable-option" ? undefined : code;
}

/**
 * Whether `option` is one of `accepts`, by identity or by equal RFC 8785 form (`canonicalJson`), as the protocol
 * package's build holds a chosen option to the document's: member order is not compared, and a number is its JSON
 * value.
 */
function isOffered(accepts: readonly unknown[], option: unknown): boolean {
  return accepts.some((a) => {
    if (a === option) return true;
    const text = canonicalJson(a);
    return typeof text === "string" && text === canonicalJson(option);
  });
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

/**
 * The option chosen from `required` for `h`, `approved` when given, with its bounds, once the challenge is found to
 * advertise `h`.
 */
async function paying(
  required: Record<string, unknown>,
  h: AtrHash,
  account: string,
  inputs: Inputs,
  admits: Admits,
  approved?: PaymentRequirements,
): Promise<{ selected: Selected; limits: { request: number; exchange: number } } | Declined> {
  const selected = await select(required, account, inputs, admits, approved);
  if ("decline" in selected) return selected;
  if (!hashEquals(selected.read.h, h)) {
    return declined("hash-mismatch", "The agreement challenge advertises another ATR hash.");
  }
  return { selected, limits: selected.limits };
}

/**
 * The agreement options of a first response that offers the agreement and no charge option (the protocol package's
 * profile `legal-context-return.md`): each option of `accepts`, in document order, with the charges it names as those
 * it serves (`servesOf`) and the read of the response holding only that option by the first x402 pairing, in the
 * protocol package's order, that reads it. Undefined unless `accepts` is a list of 1 to 32 options each of which names
 * the charges it serves and is read by such a pairing. A response none of whose options lacks the member, and one of
 * whose options `servesOf` refuses, is declined `offer-unreadable` with that refusal's code: it offers no charge, and
 * an agreement option that names its charges in no admitted form is never read as a charge. The names are read here
 * without the ATR, whose link this read gives; `transact` resolves them against the ATR's bytes once it has fetched them.
 */
export function agreementOptions(
  required: unknown,
): { option: PaymentRequirements; read: Read; serves: readonly string[] }[] | Declined | undefined {
  const accepts = isObject(required) ? required["accepts"] : undefined;
  if (!Array.isArray(accepts) || accepts.length === 0 || accepts.length > MAX_OPTIONS) return undefined;
  const served = accepts.map((option) => servesOf(option));
  if (served.some((s) => s === undefined)) return undefined;
  const malformed = served.find((s) => isRefusal(s));
  if (malformed !== undefined && isRefusal(malformed)) return declined("offer-unreadable", malformed.code);
  const out: { option: PaymentRequirements; read: Read; serves: readonly string[] }[] = [];
  for (const [i, option] of accepts.entries()) {
    const serves = served[i];
    if (serves === undefined || isRefusal(serves)) return undefined;
    const only = { ...(required as object), accepts: [option] };
    const read = X402.map((b) => (b as unknown as { read(d: unknown): Read | Refusal }).read(only)).find((r) => !isRefusal(r));
    if (read === undefined || isRefusal(read)) return undefined;
    out.push({ option: option as PaymentRequirements, read, serves });
  }
  return out;
}

/**
 * The agreement challenges of an MPP first response that offers the agreement and no charge challenge (the protocol
 * package's profile `legal-context-return.md`): each challenge, in the seller's order, with the charges it names as
 * those it serves (`servesOf`, its `opaque` member `legalContextServes`) and the protocol package's MPP `read` of the
 * response. Undefined unless the response is a list of 1 to 32 challenges each of which names the charges it serves and
 * all of which `read` finds placed for one H. A response none of whose challenges lacks the member, and one of whose
 * challenges `servesOf` refuses, is declined `offer-unreadable` with that refusal's code. The names are read here
 * without the ATR, whose link this read gives; `transact` resolves them against the ATR's bytes once it has fetched them.
 */
export function mppAgreementOptions(
  challenges: unknown,
): { option: MppChallenge; read: Read; serves: readonly string[] }[] | Declined | undefined {
  if (!Array.isArray(challenges) || challenges.length === 0 || challenges.length > MAX_OPTIONS) return undefined;
  const served = challenges.map((c) => servesOf(c));
  if (served.some((s) => s === undefined)) return undefined;
  const malformed = served.find((s) => isRefusal(s));
  if (malformed !== undefined && isRefusal(malformed)) return declined("offer-unreadable", malformed.code);
  const read = mppRead(challenges as MppChallenge[]);
  if (isRefusal(read) || read.offer.challenges.length !== challenges.length) return undefined;
  return challenges.map((c, i) => ({ option: c as MppChallenge, read: read as Read, serves: served[i] as readonly string[] }));
}

/** Whether `v` has the form of an agreement payment: an agreement URL, an option and a payment request. */
function isAgreementPayment(v: unknown): v is AgreementPayment {
  return isObject(v) && typeof v["url"] === "string" && isObject(v["option"]) && isObject(v["required"]);
}

/**
 * Without `approved`: asks the agreement URL for its challenge and returns the agreement payment to approve, signing
 * nothing, or, where the agreement URL answers that unpaid request with a receipt, that receipt, marked `unpaid: true`:
 * no agreement payment was made or read, and the receipt is the agreement URL's statement alone (terms' profile
 * `buyer-gate.md`, rule 18). With `approved`: signs exactly that payment with
 * `signer`, sends it to `url`, and returns the receipt once recorded; a payment whose challenge the protocol package's
 * read refuses for a fault of its own (its version, legal context or agreement URL, or an `accepts` that is not a list
 * of at most 32 entries holding an object) is declined as the unpaid request declines that challenge, and one whose
 * option is not one of that challenge's `accepts`, by RFC 8785 form, is declined `offer-unreadable` with
 * `x402/option-not-in-document`, each before any fetch or signer call. Before the signer is called, the agreement
 * payment is held to its summary and its own pairing's ceiling, as `transact` holds it (terms' profile `buyer-gate.md`,
 * checks 9 to 11, rule 12): a request the gate has no summary for is declined `summary-missing`, one payable past the
 * ceiling `past-ceiling` or `no-end`, and a wallet that picks its expiry is handed the latest deadline it may sign and
 * held to it. `ceilings` raises that ceiling as it does in `transact`. `agree` calls no approver: showing the agreement
 * payment before it is approved is the caller's step.
 * `bytes` are the ATR the gate compared, whose hash the agreement payment carries; `inputs` are the buyer's own chain
 * values; `signal` ends the exchange; `chosen` is the charge the agreement is for, exactly as `confirm` returned it,
 * and only an option its pairing's `agreementOn` admits is paid (any option where `chosen` is not given). Options
 * holding anything but `approved`, `inputs`, `ceilings`, `signal` and `chosen`, a `signal` that is not an
 * `AbortSignal`, an `approved` that is not of the agreement payment's form, `inputs` or `ceilings` that is not an
 * object, a `chosen` that does not name a pairing of the protocol package, or a signer whose `account` is not a string,
 * is declined `no-payable-option` with `x402/input-malformed` before any fetch or signer call; a `ceilings` value not of
 * the profile's rule 8 form for the pairing paid is declined so before the signer is called. A `url` that is not an https URL is declined `link-not-https` with `x402/link-not-https` for an
 * absolute URL of another scheme and `x402/legal-context-malformed` for any other value, before any fetch.
 */
export function agree(
  bytes: Uint8Array,
  url: string,
  signer: Signer,
  fetch: Fetch,
  options?: AgreeOptions,
): Promise<ToApprove | AgreementChallenges | { receipt: AgreementReceipt } | Declined> {
  return exchange(bytes, url, signer, fetch, options === undefined ? {} : options, undefined);
}

const OPTION_KEYS: readonly string[] = ["approved", "inputs", "ceilings", "signal", "chosen"];

/**
 * Whether `agree`'s options are an object holding only `approved`, `inputs`, `ceilings`, `signal` and `chosen`, the
 * signal an `AbortSignal` and `ceilings` an object, whose value for the pairing paid is read when it is paid.
 */
function optionsOk(options: unknown): options is AgreeOptions {
  if (!isObject(options) || !Object.keys(options).every((k) => OPTION_KEYS.includes(k))) return false;
  const { signal, ceilings } = options;
  return (signal === undefined || signal instanceof AbortSignal) && (ceilings === undefined || isObject(ceilings));
}

/** The protocol package's pairing `chosen` names, or undefined. */
function chargeBinding(chosen: unknown): Binding | undefined {
  const id: unknown = isObject(chosen) ? chosen["pairing"] : undefined;
  return typeof id === "string" ? (BINDINGS as readonly Binding[]).find((b) => b.id === id) : undefined;
}

/**
 * `agree`, where `ns` is the namespace of the pairing whose offer named the URL, x402 when none did: a refused URL
 * declines `link-not-https`, its detail the protocol package's code in that namespace, `link-not-https` for an absolute
 * URL of another scheme and `legal-context-malformed` for any other value. `charge` is the binding the charge in
 * `options.chosen` is paid through, where the caller holds it; else the protocol package's pairing `chosen` names. The
 * agreement payment is held to its summary and its own pairing's ceiling before it is signed, `ceilings` raising it:
 * `approval`'s, `transact`'s, which also asks its approver, as the act `agreement`; else `options.ceilings`, `agree`'s,
 * with no approver.
 */
export async function exchange(
  bytes: Uint8Array,
  url: string,
  signer: Signer,
  fetch: Fetch,
  options: AgreeOptions,
  ns: string | undefined,
  charge?: Binding,
  approval?: Approval,
): Promise<ToApprove | AgreementChallenges | { receipt: AgreementReceipt } | Declined> {
  if (!isHttpsLink(url)) {
    const fault = isOtherSchemeLink(url) ? "link-not-https" : "legal-context-malformed";
    return declined("link-not-https", `${ns ?? "x402"}/${fault}`);
  }
  if (!optionsOk(options)) return declined("no-payable-option", `${ns ?? "x402"}/input-malformed`);
  const { approved, signal, inputs = {}, ceilings, chosen } = options;
  const through = chosen === undefined ? undefined : (charge ?? chargeBinding(chosen));
  if (
    (approved !== undefined && !isAgreementPayment(approved)) ||
    !isObject(inputs) ||
    !hasAccount(signer) ||
    (chosen !== undefined && through === undefined)
  ) {
    return declined("no-payable-option", `${ns ?? "x402"}/input-malformed`);
  }
  const admits = chosen === undefined || through === undefined ? ANY : admitting(through, chosen);
  if (isEnded(signal)) return ended();
  const h = await hash(bytes);
  if (approved === undefined) return offer(bytes, h, url, signer, fetch, inputs, admits, signal);
  if (approved.url !== url) return failed("The approved agreement payment names another agreement URL.");

  const found = await paying(approved.required, h, signer.account, inputs, admits, approved.option);
  if ("decline" in found) return found;
  const { selected, limits } = found;
  const held: Approval = { ...(approval ?? { ceilings }), inputs };
  const paid = await pay(selected.binding, selected.chosen, signer, bytes, "agreement", held);
  if ("decline" in paid) return paid;
  if (paid.signed === null) return declined("offer-unreadable", "The agreement payment gave nothing to sign.");
  if (isEnded(signal)) return ended();
  const signed: Presented = paid.signed;
  const text = paymentText(signed);
  if (text === undefined) return declined("signed-not-bound", "The agreement payment is not plain JSON.");
  const payment = toBase64(new TextEncoder().encode(text));
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

/**
 * The agreement resource's MPP agreement challenges, where its 402 carries no `PAYMENT-REQUIRED`: its
 * `WWW-Authenticate` field read by the protocol package's `parseChallenges`, and the `Payment` challenges its MPP `read`
 * finds placed for one H, in the seller's order, returned for the caller's own MPP client to pay; terms builds no MPP
 * credential, so it signs none of them. A field `parseChallenges` refuses, or challenges `read` refuses, is
 * `offer-unreadable` with that code; challenges placed for another H are `hash-mismatch`; a field with no `Payment`
 * challenge is read as a 402 with no payment request.
 */
function mppOnly(field: string, bytes: Uint8Array, h: AtrHash): AgreementChallenges | Declined {
  const parsed = parseChallenges([field]);
  if (isRefusal(parsed)) return declined("offer-unreadable", parsed.code);
  if (parsed.length === 0) return failed("The agreement URL answered 402 without a readable PAYMENT-REQUIRED.");
  const read = mppRead(parsed);
  if (isRefusal(read)) return declined("offer-unreadable", read.code);
  if (!hashEquals(read.h, h)) return declined("hash-mismatch", "The agreement challenge advertises another ATR hash.");
  return { agreementChallenges: read.offer.challenges, bytes, h };
}

/**
 * The unpaid request: the agreement payment to approve; the receipt the agreement URL answered it with, `unpaid: true`,
 * no agreement payment having been made or read; or a decline.
 */
async function offer(
  bytes: Uint8Array,
  h: AtrHash,
  url: string,
  signer: Signer,
  fetch: Fetch,
  inputs: Inputs,
  admits: Admits,
  signal: AbortSignal | undefined,
): Promise<ToApprove | AgreementChallenges | { receipt: AgreementReceipt } | Declined> {
  const unpaid = await get(fetch, url, undefined, UNPAID_DEADLINE_MS, signal);
  if (isEnded(signal)) return ended();
  if ("decline" in unpaid) return unpaid;
  if ("unanswered" in unpaid) return failed("The agreement URL could not be reached.");
  // A 200 to the unpaid request is the agreement URL's statement alone: no agreement payment was made or read.
  if (unpaid.status === 200) return receiptOf(unpaid.body, h, true);
  if (unpaid.status === 202) {
    return declined("agreement-pending", "An agreement payment for this ATR is already settling.");
  }
  if (unpaid.status !== 402) return failed(`The agreement URL answered status ${unpaid.status}.`);
  if (unpaid.paymentRequired === null && unpaid.wwwAuthenticate !== null) return mppOnly(unpaid.wwwAuthenticate, bytes, h);

  const required = unpaid.paymentRequired === null ? undefined : fromBase64Json(unpaid.paymentRequired);
  if (!isObject(required)) return failed("The agreement URL answered 402 without a readable PAYMENT-REQUIRED.");
  const found = await paying(required, h, signer.account, inputs, admits);
  if ("decline" in found) return found;
  return { approve: { url, option: found.selected.option, required: required as unknown as PaymentRequired }, bytes, h };
}
