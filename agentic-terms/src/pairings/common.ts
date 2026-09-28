/**
 * What the buyer pieces share: the CAIP-10 account, the first x402 option on the account's network, the payment
 * identifier the x402 client writes, and the JSON forms of byte strings and integers.
 */
import { isRefusal as isLcpRefusal, type Json, type Refusal } from "@integraledger/lcp";
import type { PaymentRequired, PaymentRequirements, X402Offer } from "@integraledger/lcp/x402";
import type { Chosen, Inputs, Read } from "../types.js";

const CAIP10 = /^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32}):([-.%a-zA-Z0-9]{1,128})$/;
const PAYMENT_IDENTIFIER = "payment-identifier";
const HEX = /^0x(?:[0-9a-fA-F]{2})*$/;
const DECIMAL = /^[0-9]{1,78}$/;

/** Every refusal the gate makes. Membership, not shape, is what makes a value one of them. */
const made = new WeakSet<object>();

/** A refusal with `code`, made by the gate. */
export function refuse(code: string): Refusal {
  const r = { refused: true as const, code };
  made.add(r);
  return r;
}

/**
 * True for a refusal the protocol package made (its `isRefusal`) or the gate made (`refuse`). A value from a seller,
 * a signer or a caller that is shaped `{ refused: true, … }` is neither, so it is never passed on as a refusal.
 */
export function isRefusal(v: unknown): v is Refusal {
  return isLcpRefusal(v) || (typeof v === "object" && v !== null && made.has(v));
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * A CAIP-10 account's namespace, its CAIP-2 network and its address, percent-decoded (CAIP-10's escape). An `eip155`
 * address is taken as written: the gate's account form for EVM is `^eip155:([0-9]+):(0x[0-9a-fA-F]{40})$`, which has no escape.
 */
export function accountOf(account: unknown): { namespace: string; network: string; address: string } | undefined {
  const m = typeof account === "string" ? CAIP10.exec(account) : null;
  if (m === null) return undefined;
  if (m[1] === "eip155") return { namespace: m[1], network: `${m[1]}:${m[2]!}`, address: m[3]! };
  let address: string;
  try {
    address = decodeURIComponent(m[3]!);
  } catch {
    return undefined;
  }
  return { namespace: m[1]!, network: `${m[1]!}:${m[2]!}`, address };
}

/** True when the request tells the signer to broadcast what it signs. */
export function broadcasts(request: unknown): boolean {
  return isObject(request) && request["broadcast"] === true;
}

/** The offer a binding's `read` gives for x402, or undefined. */
export function x402OfferOf(read: Read): X402Offer | undefined {
  const offer = read.offer;
  if (!isObject(offer) || !isObject(offer["required"]) || !Array.isArray(offer["options"])) return undefined;
  return offer as unknown as X402Offer;
}

/**
 * The first of the offer's options, in document order, whose network is the account's, with the account parsed. The
 * buyer chooses among options by removing the others from `accepts` first.
 */
export function firstOption(
  read: Read,
  account: string,
  ns: string,
  pairing: string,
  address?: RegExp,
): { required: PaymentRequired; accepted: PaymentRequirements; address: string } | Refusal {
  const a = accountOf(account);
  const offer = x402OfferOf(read);
  if (a === undefined || a.namespace !== ns || (address !== undefined && !address.test(a.address))) {
    return refuse(`${pairing.split("/")[0]}/no-payable-option`);
  }
  if (offer === undefined) return refuse("x402/no-payable-option");
  const accepted = offer.options.find((o) => isObject(o) && o.network === a.network);
  if (accepted === undefined) return refuse("x402/no-payable-option");
  return { required: offer.required, accepted, address: a.address };
}

/** `chosen` for an x402 pairing, with the choice as plain JSON. */
export function x402Chosen(pairing: string, choice: Record<string, Json>, ref: string): Chosen {
  return { pairing, choice, ref };
}

/**
 * The completed payment with `id` = `ref` appended to the echoed `payment-identifier` info, where the challenge
 * advertises that extension. An `info` that is not an object, or that already holds `id`, cannot take it without
 * overwriting, and is refused.
 */
export function withPaymentIdentifier<P>(signed: P, required: unknown, ref: string): P | Refusal {
  const advertised = isObject(required) ? required["extensions"] : undefined;
  if (!isObject(advertised) || !Object.hasOwn(advertised, PAYMENT_IDENTIFIER)) return signed;
  const extensions = isObject(signed) ? signed["extensions"] : undefined;
  const extension: unknown = isObject(extensions) ? extensions[PAYMENT_IDENTIFIER] : undefined;
  const info: unknown = isObject(extension) ? extension["info"] : undefined;
  if (!isObject(extensions) || !isObject(extension) || !isObject(info) || Object.hasOwn(info, "id")) {
    return refuse("x402/payment-identifier-unwritable");
  }
  return {
    ...(signed as object),
    extensions: { ...extensions, [PAYMENT_IDENTIFIER]: { ...extension, info: { ...info, id: ref } } },
  } as P;
}

/** The bytes of `0x` hex, of the given length when one is named, or undefined. */
export function bytesOf(s: unknown, length?: number): Uint8Array | undefined {
  if (typeof s !== "string" || !HEX.test(s)) return undefined;
  const out = new Uint8Array((s.length - 2) / 2);
  if (length !== undefined && out.length !== length) return undefined;
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

/** `0x` and the lowercase hex of the bytes. */
export function hexOf(b: Uint8Array): `0x${string}` {
  let s = "0x";
  for (const x of b) s += (x < 16 ? "0" : "") + x.toString(16);
  return s as `0x${string}`;
}

/** A decimal string of at most 78 digits as a bigint, or undefined. */
export function bigintOf(v: unknown): bigint | undefined {
  return typeof v === "string" && DECIMAL.test(v) ? BigInt(v) : undefined;
}

/** A non-negative safe integer, or undefined. */
export function uintOf(v: unknown): number | undefined {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : undefined;
}

/** The named inputs, present and of the given kinds, as JSON; or the refusal naming the first missing one. */
export function inputsOf(
  inputs: Inputs,
  pairing: string,
  spec: { readonly [k: string]: "string" | "decimal" | "uint" | "hex" | "object" | "optional-string" | "optional-uint" | "optional-decimal" | "optional-hex" | "optional-object" },
): Record<string, Json> | Refusal {
  const out: Record<string, Json> = {};
  for (const [k, kind] of Object.entries(spec)) {
    const v = inputs[k];
    const optional = kind.startsWith("optional-");
    if (v === undefined && optional) continue;
    const base = optional ? kind.slice("optional-".length) : kind;
    const ok =
      (base === "string" && typeof v === "string" && v !== "") ||
      (base === "decimal" && bigintOf(v) !== undefined) ||
      (base === "uint" && uintOf(v) !== undefined) ||
      (base === "hex" && typeof v === "string" && HEX.test(v)) ||
      (base === "object" && isObject(v));
    if (!ok) return refuse(`${pairing.split("/")[0]}/input-missing`);
    out[k] = v as Json;
  }
  return out;
}

/** The choice object of `chosen`, or undefined. */
export function choiceOf(chosen: Chosen): Record<string, unknown> | undefined {
  return isObject(chosen) && isObject(chosen.choice) ? chosen.choice : undefined;
}
