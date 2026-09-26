/**
 * The buyer's channel steps. One ATR covers a whole channel: the gate compares it once, at the opening, and the caller
 * keeps the result as a `ChannelHold`, the ATR's bytes together with the signed opening and the channel it names.
 * `within` signs a later voucher only for a channel held this way, re-deriving everything from the hold and never from
 * the new challenge, and only when that challenge advertises the held ATR's hash. It serves x402's batch channels and
 * MPP's sessions through the binding's `buildWithin`. `recordCharge` records the server's cumulative charge, bounded by
 * what was signed.
 */
import { fromLcpString, hash, hashEquals, parseJson, type AtrHash, type Json, type Refusal } from "@integraledger/lcp";
import { network as mppNetwork, sessionResume, type MppChallenge } from "@integraledger/lcp/mpp";
import { offers, requestOf } from "./pairings/mpp.js";
import { withPaymentIdentifier } from "./pairings/common.js";
import {
  MAX_ATR_BYTES,
  type Binding,
  type DeclineCode,
  type Declined,
  type Inputs,
  type Presented,
  type Read,
  type Signature,
  type Signer,
  type SigningRequest,
} from "./types.js";

/** A channel the buyer opened for an ATR it compared, as JSON the caller keeps and hands back. */
export interface ChannelHold {
  pairing: string;
  network: string;
  channel: string;
  h: AtrHash;
  /** Base64 of the ATR bytes the opening compared. */
  atr: string;
  /** The signed opening payment, exactly as the gate returned it. */
  opening: Json;
  /** The server's cumulative charge last recorded, decimal; "0" at the opening. */
  charged: string;
  /** The largest `maxClaimableAmount` signed in this channel, decimal. */
  signedMax: string;
}

type Kind = "open" | "within" | "close";

/** The binding members the channel steps call, whatever the pairing's own types. */
interface ChannelSteps {
  id: string;
  read(doc: unknown): Read | Refusal;
  bound(presented: unknown): Promise<AtrHash | Refusal> | AtrHash | Refusal;
  buildWithin?(w: unknown, h: AtrHash): Promise<unknown>;
  channel?: {
    kind(presented: unknown): Kind | Refusal;
    ref(presented: unknown): Promise<{ network: string; channel: string } | Refusal>;
    boundWithin(presented: unknown): Promise<AtrHash | Refusal>;
  };
}

interface Batch {
  requests: readonly { kind: string; typedData?: unknown }[];
  complete(signatures: readonly string[]): unknown;
}

const DECIMAL = /^[0-9]{1,78}$/;
/** At most this many challenges of a within document are looked at, as the MPP entry point reads a document. */
const MAX_CHALLENGES = 32;
/** An `opaque` of at most this many base64url characters, 8 KiB decoded, is read. */
const MAX_OPAQUE = 10_924;
const NOT_BOUND_WITHIN = /\/not-bound-within$/;
const REF_BYTES = 24;
const HOLD_KEYS = ["pairing", "network", "channel", "h", "atr", "charged", "signedMax"] as const;

function declined(code: DeclineCode, detail: string): Declined {
  return { decline: { code, detail } };
}

function isRefusal(v: unknown): v is Refusal {
  return typeof v === "object" && v !== null && (v as { refused?: unknown }).refused === true;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const stepsOf = (binding: Binding): ChannelSteps => binding as unknown as ChannelSteps;

/** Calls a binding member, reading a throw as a refusal. */
async function guarded<T>(run: () => Promise<T> | T): Promise<T | Refusal> {
  try {
    return await run();
  } catch {
    return { refused: true, code: "member-failed" };
  }
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromBase64(s: string): Uint8Array | undefined {
  try {
    const binary = atob(s);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/** A value as plain JSON, or undefined when it holds anything JSON does not carry. */
function asJson(v: unknown): Json | undefined {
  try {
    const text = JSON.stringify(v);
    return text === undefined ? undefined : (JSON.parse(text) as Json);
  } catch {
    return undefined;
  }
}

function isHold(v: unknown): v is ChannelHold {
  return (
    isObject(v) &&
    HOLD_KEYS.every((k) => typeof v[k] === "string") &&
    DECIMAL.test(v["charged"] as string) &&
    DECIMAL.test(v["signedMax"] as string) &&
    isObject(v["opening"])
  );
}

/**
 * The buyer's own chain values a refund's build takes: a Solana `request_close` needs a recent blockhash when the option
 * names none, and may take the Compute Budget values.
 */
function refundInputs(inputs: Inputs): { recentBlockhash?: string; computeUnitLimit?: number; computeUnitPrice?: bigint } {
  const out: { recentBlockhash?: string; computeUnitLimit?: number; computeUnitPrice?: bigint } = {};
  const { recentBlockhash, computeUnitLimit, computeUnitPrice } = inputs;
  if (typeof recentBlockhash === "string") out.recentBlockhash = recentBlockhash;
  if (typeof computeUnitLimit === "number" && Number.isSafeInteger(computeUnitLimit)) out.computeUnitLimit = computeUnitLimit;
  if (typeof computeUnitPrice === "string" && DECIMAL.test(computeUnitPrice)) out.computeUnitPrice = BigInt(computeUnitPrice);
  return out;
}

/** 24 random bytes as unpadded base64url: 32 characters from `[A-Za-z0-9_-]`. */
function newRef(): string {
  return toBase64(crypto.getRandomValues(new Uint8Array(REF_BYTES))).replace(/\+/g, "-").replace(/\//g, "_");
}

/** The opening voucher's `maxClaimableAmount`, where the payment carries one, else "0". */
function openingMax(signed: unknown): string {
  const payload = isObject(signed) ? signed["payload"] : undefined;
  const voucher = isObject(payload) ? payload["voucher"] : undefined;
  const max = isObject(voucher) ? voucher["maxClaimableAmount"] : undefined;
  return typeof max === "string" && DECIMAL.test(max) ? max : "0";
}

/**
 * Takes a channel pairing's signed opening and the ATR bytes the gate compared for it, with the landed receipt
 * `transact` returned beside the opening, where it returned one. The opening, with that receipt, must be of kind `open`,
 * carry the hash of these bytes, and name its channel; the hold keeps all three together.
 */
export async function openChannel(
  bytes: Uint8Array,
  opened: Presented,
  binding: Binding,
  landed?: unknown,
): Promise<ChannelHold | Declined> {
  const b = stepsOf(binding);
  if (!isObject(b) || typeof b.id !== "string" || !isObject(b.channel)) {
    return declined("pairing-not-supported", "The pairing has no channel.");
  }
  if (landed !== undefined && (!isObject(landed) || !isObject(opened))) {
    return declined("signed-not-bound", "The landed receipt is not a JSON object beside the opening.");
  }
  const signed = (landed === undefined ? opened : { ...(opened as object), landed }) as Presented;
  if (!(bytes instanceof Uint8Array)) return declined("signed-not-bound", "The ATR bytes are missing.");
  if (bytes.length > MAX_ATR_BYTES) return declined("atr-too-large", `The ATR is larger than ${MAX_ATR_BYTES} bytes.`);
  const channel = b.channel;
  const kind = await guarded(() => channel.kind(signed));
  if (kind !== "open") return declined("signed-not-bound", "The payment does not open a channel.");
  const h = await hash(bytes);
  const inside = await guarded(() => b.bound(signed));
  if (isRefusal(inside) || !hashEquals(inside, h)) {
    return declined("signed-not-bound", "The opening does not carry the hash of these bytes.");
  }
  const ref = await guarded(() => channel.ref(signed));
  if (isRefusal(ref)) return declined("signed-not-bound", ref.code);
  const opening = asJson(signed);
  if (!isObject(opening)) return declined("signed-not-bound", "The opening is not plain JSON.");
  return {
    pairing: b.id,
    network: ref.network,
    channel: ref.channel,
    h,
    atr: toBase64(bytes),
    opening,
    charged: "0",
    signedMax: openingMax(signed),
  };
}

/**
 * Signs one later voucher, or a refund, in a held channel. The ATR bytes, the opening's hash and the opening's
 * channel are re-derived from the hold, and the challenge must advertise the held hash. A voucher's
 * `maxClaimableAmount` is the recorded charge plus the option's amount; a refund's is the recorded charge. `inputs`
 * are the buyer's own chain values a refund's build takes. What was signed must be of the expected kind and belong to
 * the held channel, or it is dropped.
 */
export async function within(
  doc: unknown,
  hold: ChannelHold,
  binding: Binding,
  signer: Signer,
  refund?: { amount?: string },
  inputs: Inputs = {},
): Promise<{ signed: Presented; hold: ChannelHold } | Declined> {
  const b = stepsOf(binding);
  if (!isObject(b) || typeof b.id !== "string" || !isObject(b.channel)) {
    return declined("pairing-not-supported", "The pairing has no channel.");
  }
  if (typeof b.buildWithin !== "function") {
    return declined("pairing-not-supported", `The pairing ${b.id} has no in-channel payment.`);
  }
  if (!isHold(hold)) return declined("signed-not-bound", "The channel hold is malformed.");
  if (hold.pairing !== b.id) return declined("pairing-not-supported", `The hold is not for the pairing ${b.id}.`);
  const ns = b.id.split("/")[0]!;
  let refundAmount: bigint | undefined;
  if (refund !== undefined) {
    if (!isObject(refund) || (refund.amount !== undefined && !DECIMAL.test(refund.amount))) {
      return declined("no-payable-option", `${ns}/input-missing`);
    }
    refundAmount = refund.amount === undefined ? undefined : BigInt(refund.amount);
  }
  const channel = b.channel;

  const bytes = fromBase64(hold.atr);
  if (bytes === undefined || bytes.length > MAX_ATR_BYTES) return declined("signed-not-bound", "The held ATR is unreadable.");
  const h = await hash(bytes);
  if (!hashEquals(hold.h, h)) return declined("hash-mismatch", "The held ATR does not hash to the held hash.");
  const opened = await guarded(() => b.bound(hold.opening));
  if (isRefusal(opened) || !hashEquals(opened, h)) {
    return declined("signed-not-bound", "The held opening does not carry the held ATR's hash.");
  }
  const openedRef = await guarded(() => channel.ref(hold.opening));
  if (isRefusal(openedRef) || openedRef.network !== hold.network || openedRef.channel !== hold.channel) {
    return declined("signed-not-bound", "The held opening does not name the held channel.");
  }

  if (ns === "mpp") return sessionWithin(b, doc, hold, h, signer, refund);
  const read = await guarded(() => b.read(doc));
  if (isRefusal(read)) return declined("offer-unreadable", read.code);
  if (!hashEquals(read.h, h)) {
    return declined("hash-mismatch", "The challenge advertises another ATR's hash than the one this channel opened for.");
  }
  const offer = read.offer;
  const options = isObject(offer) && Array.isArray(offer["options"]) ? (offer["options"] as unknown[]) : [];
  const accepted = options.find((o) => isObject(o) && o["network"] === hold.network) as Record<string, unknown> | undefined;
  if (accepted === undefined) return declined("no-payable-option", `${ns}/no-payable-option`);
  if (typeof accepted["amount"] !== "string" || !DECIMAL.test(accepted["amount"])) {
    return declined("offer-unreadable", `${ns}/option-malformed`);
  }
  const maxClaimableAmount =
    refund !== undefined ? BigInt(hold.charged) : BigInt(hold.charged) + BigInt(accepted["amount"]);
  const payload = (hold.opening as Record<string, unknown>)["payload"];
  const channelConfig = isObject(payload) ? payload["channelConfig"] : undefined;
  const required = isObject(offer) ? offer["required"] : undefined;

  const unsigned = await guarded(() =>
    b.buildWithin!(
      {
        required,
        accepted,
        channelConfig,
        maxClaimableAmount,
        ...(refund !== undefined ? { refund: refundAmount === undefined ? {} : { amount: refundAmount } } : {}),
        ...(refund !== undefined ? refundInputs(isObject(inputs) ? inputs : {}) : {}),
      },
      h,
    ),
  );
  if (isRefusal(unsigned)) return declined("offer-unreadable", unsigned.code);
  const batch = unsigned as Batch;
  const request = {
    kind: "batch",
    requests: batch.requests,
  } as SigningRequest;

  let answer: Signature;
  try {
    answer = await signer.sign(request);
  } catch {
    return declined("signer-failed", "The signer did not sign.");
  }
  if (!Array.isArray(answer) || answer.length !== batch.requests.length || !answer.every((s) => typeof s === "string")) {
    return declined("signed-not-bound", "The signer's answer did not complete the payment.");
  }
  const completed = await guarded(() => batch.complete(answer as string[]));
  if (isRefusal(completed)) return declined("signed-not-bound", completed.code);
  const signed = withPaymentIdentifier(completed as Presented, required, newRef());
  if (isRefusal(signed)) return declined("signed-not-bound", signed.code);

  const expected: Kind = refund !== undefined && refundAmount === undefined ? "close" : "within";
  const kind = await guarded(() => channel.kind(signed));
  if (kind !== expected) return declined("signed-not-bound", `The signed payment is not a ${expected} payment.`);
  const inside = await guarded(() => channel.boundWithin(signed));
  if (isRefusal(inside) ? !NOT_BOUND_WITHIN.test(inside.code) : !hashEquals(inside, h)) {
    return declined("signed-not-bound", "The signed voucher does not commit to the held ATR's hash.");
  }
  const ref = await guarded(() => channel.ref(signed));
  if (isRefusal(ref) || ref.network !== hold.network || ref.channel !== hold.channel) {
    return declined("signed-not-bound", "The signed voucher does not name the held channel.");
  }
  const signedMax = BigInt(hold.signedMax) > maxClaimableAmount ? hold.signedMax : maxClaimableAmount.toString();
  return { signed, hold: { ...hold, signedMax } };
}

/**
 * One voucher, or the close, in a held MPP session. The within challenge is the first of the document that either
 * offers the pairing on the held network, or names a channel of the pairing on the held network, as `sessionResume`
 * reads it for the pairing's method. A named channel must be the held one, and a legal context in
 * the challenge's `opaque` must name the held hash; either is checked before the signer is called. The voucher's
 * cumulative amount is the recorded charge plus the challenge's amount, and the close's is the recorded charge. Every
 * channel value comes from the held opening, through the binding's `buildWithin`.
 */
async function sessionWithin(
  b: ChannelSteps,
  doc: unknown,
  hold: ChannelHold,
  h: AtrHash,
  signer: Signer,
  refund: { amount?: string } | undefined,
): Promise<{ signed: Presented; hold: ChannelHold } | Declined> {
  if (refund !== undefined && refund.amount !== undefined) {
    return declined("pairing-not-supported", "mpp/within-action-not-built");
  }
  const channel = b.channel!;
  const challenges = Array.isArray(doc) ? doc.slice(0, MAX_CHALLENGES) : [];
  let challenge: MppChallenge | undefined;
  for (const each of challenges) {
    if (!isObject(each)) continue;
    const c = each as unknown as MppChallenge;
    const named = namedChannel(c, b.id);
    if (named === undefined) {
      if (offers(c, b.id) && mppNetwork(c) === hold.network) {
        challenge = c;
        break;
      }
      continue;
    }
    if (named === null) continue;
    if (named.network !== hold.network) continue;
    if (named.channel !== hold.channel) {
      return declined("no-payable-option", "The challenge names a channel this hold did not open.");
    }
    challenge = c;
    break;
  }
  if (challenge === undefined) return declined("no-payable-option", "mpp/no-payable-option");
  const named = legalContextOf(challenge);
  if (named === "malformed") return declined("offer-unreadable", "mpp/legal-context-malformed");
  if (named !== undefined && !hashEquals(named, h)) {
    return declined("hash-mismatch", "The challenge names another ATR's hash than the one this channel opened for.");
  }
  const amount = requestOf(challenge)?.["amount"];
  if (typeof amount !== "string" || !DECIMAL.test(amount)) return declined("offer-unreadable", "mpp/request-malformed");
  const action = refund !== undefined ? "close" : "voucher";
  const cumulativeAmount = action === "close" ? BigInt(hold.charged) : BigInt(hold.charged) + BigInt(amount);

  const unsigned = await guarded(() => b.buildWithin!({ challenge, opening: hold.opening, cumulativeAmount, action }, h));
  if (isRefusal(unsigned)) {
    const code = unsigned.code.endsWith("/within-action-not-built") ? "pairing-not-supported" : "offer-unreadable";
    return declined(code, unsigned.code);
  }
  const batch = unsigned as Batch;
  let answer: Signature;
  try {
    answer = await signer.sign({ kind: "batch", requests: batch.requests } as SigningRequest);
  } catch {
    return declined("signer-failed", "The signer did not sign.");
  }
  if (!Array.isArray(answer) || answer.length !== batch.requests.length || !answer.every((s) => typeof s === "string")) {
    return declined("signed-not-bound", "The signer's answer did not complete the payment.");
  }
  const signed = await guarded(() => batch.complete(answer as string[]));
  if (isRefusal(signed)) return declined("signed-not-bound", signed.code);

  const expected: Kind = action === "close" ? "close" : "within";
  const kind = await guarded(() => channel.kind(signed));
  if (kind !== expected) return declined("signed-not-bound", `The signed payment is not a ${expected} payment.`);
  const inside = await guarded(() => channel.boundWithin(signed));
  if (isRefusal(inside) ? !NOT_BOUND_WITHIN.test(inside.code) : !hashEquals(inside, h)) {
    return declined("signed-not-bound", "The signed voucher does not commit to the held ATR's hash.");
  }
  const ref = await guarded(() => channel.ref(signed));
  if (isRefusal(ref) || ref.network !== hold.network || ref.channel !== hold.channel) {
    return declined("signed-not-bound", "The signed voucher does not name the held channel.");
  }
  const signedMax = BigInt(hold.signedMax) > cumulativeAmount ? hold.signedMax : cumulativeAmount.toString();
  return { signed: signed as Presented, hold: { ...hold, signedMax } };
}

/**
 * The channel a challenge of the pairing names for the client to resume: undefined when it names none, null when the
 * challenge is not of the pairing, and otherwise `sessionResume`'s network and channel, spelled as the pairing's
 * `channel.ref` spells a held channel. A named channel that `sessionResume` cannot read names a channel no hold opened.
 */
function namedChannel(c: MppChallenge, pairing: string): { network: string; channel: string } | null | undefined {
  const r = sessionResume(c);
  if (r === null) return undefined;
  if (`mpp/${String(c.intent)}/${String(c.method)}` !== pairing) return null;
  return isRefusal(r) ? { network: "", channel: "" } : r;
}

/**
 * The hash a challenge's `opaque` names as its legal context: undefined when there is no `opaque` or it has no
 * `legalContext` member, "malformed" when either cannot be read.
 */
function legalContextOf(c: MppChallenge): AtrHash | "malformed" | undefined {
  if (c.opaque === undefined) return undefined;
  const map = typeof c.opaque === "string" ? base64UrlJson(c.opaque) : undefined;
  if (!isObject(map)) return "malformed";
  const lc = map["legalContext"];
  if (lc === undefined) return undefined;
  const named = typeof lc === "string" ? fromLcpString(lc) : null;
  return named ?? "malformed";
}

/** A base64url string's bytes read as one JSON value, or undefined. */
function base64UrlJson(s: string): unknown {
  if (s.length > MAX_OPAQUE || !/^[A-Za-z0-9_-]*$/.test(s)) return undefined;
  try {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    return parseJson(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(binary, (ch) => ch.charCodeAt(0))));
  } catch {
    return undefined;
  }
}

/**
 * Records the server's cumulative charge for the channel. It must be a decimal no lower than the charge last recorded
 * and no higher than the largest amount signed in the channel.
 */
export function recordCharge(hold: ChannelHold, chargedCumulativeAmount: string): ChannelHold | Declined {
  if (!isHold(hold)) return declined("signed-not-bound", "The channel hold is malformed.");
  if (typeof chargedCumulativeAmount !== "string" || !DECIMAL.test(chargedCumulativeAmount)) {
    return declined("offer-unreadable", "The charged amount is not a decimal.");
  }
  const charged = BigInt(chargedCumulativeAmount);
  if (charged < BigInt(hold.charged)) {
    return declined("offer-unreadable", "The charged amount is below the charge already recorded.");
  }
  if (charged > BigInt(hold.signedMax)) {
    return declined("offer-unreadable", "The charged amount is above the largest amount signed in the channel.");
  }
  return { ...hold, charged: charged.toString() };
}
