/**
 * The requests of the checkout protocols (profile `buyer-gate.md`, rule 13): AP2's closed Checkout Mandate over the
 * merchant's `checkout_jwt` (`ap2-checkout-mandate`), the UCP checkout a mandate issuer signs over (`ucp-checkout`), the
 * UCP checkout a platform's signed request completes with the `legal_context` member (`ucp-legal-context`), and ACP's
 * delegated-payment allowance (`acp-allowance`). Each authorises a charge the seller's own processor makes, in a
 * currency's minor units; none names a network, so the summary's is the signer's account's.
 */
import { jwsPayload } from "@integraledger/lcp/ap2";
import { disclosureDigest } from "@integraledger/lcp/card";
import { isRefusal } from "@integraledger/lcp/core";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { isObject } from "./evm-fields.js";

/** The longest currency, merchant or account text read. */
const MAX_TEXT = 256;
/** The longest checkout JWT read: 1 MiB, the protocol package's bound on it. */
const MAX_JWT = 1_048_576;
const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const CHECKOUT_VCT = "mandate.checkout.1";
const NO_END = { notBefore: null, notAfter: null, unit: "seconds" } as const;

const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;
const amountOf = (v: unknown): string | undefined =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? String(v) : undefined;

/** The amount of a checkout's one `totals` entry of `type` `total`, as a decimal string; else undefined. */
function totalOf(totals: unknown): string | undefined {
  if (!Array.isArray(totals)) return undefined;
  const found = totals.filter((t) => isObject(t) && t["type"] === "total");
  return found.length === 1 ? amountOf((found[0] as Record<string, unknown>)["amount"]) : undefined;
}

/**
 * A checkout's charge: the amount of its one `total`, in `currency`'s minor units, paid to the merchant `merchant.id`
 * names where `named` reads one, to no payee the request names otherwise. The checkout names no expiry, and no network:
 * the network is the signer's account's.
 */
function checkoutShown(c: unknown, network: unknown, named: boolean): Shown | undefined {
  if (!isObject(c) || typeof network !== "string" || !CAIP2.test(network)) return undefined;
  const amount = totalOf(c["totals"]);
  const currency = c["currency"];
  if (amount === undefined || !text(currency)) return undefined;
  let payees: Shown["payees"] = [];
  if (named && c["merchant"] !== undefined) {
    const merchant = c["merchant"];
    if (!isObject(merchant) || !text(merchant["id"])) return undefined;
    payees = [{ account: merchant["id"], amount }];
  }
  return { amount, payees, asset: currency, network, validity: NO_END };
}

/**
 * `ap2-checkout-mandate`: the closed Checkout Mandate's claims, `content`, which commit to the checkout by
 * `checkout_hash`: its `checkout_jwt` is read only where `checkout_hash` is that JWT's hash, the base64url of its
 * SHA-256, and its payload is the checkout read, the merchant `merchant.id` where it names one.
 */
export async function ap2CheckoutMandate(request: SigningRequest, network?: string): Promise<Shown | undefined> {
  const r = request as { kind?: unknown; content?: unknown };
  if (r.kind !== "ap2-checkout-mandate" || !isObject(r.content) || r.content["vct"] !== CHECKOUT_VCT) return undefined;
  const jwt = r.content["checkout_jwt"];
  if (typeof jwt !== "string" || jwt.length > MAX_JWT || (await disclosureDigest(jwt)) !== r.content["checkout_hash"]) {
    return undefined;
  }
  const payload = jwsPayload(jwt);
  return isRefusal(payload) ? undefined : checkoutShown(payload, network, true);
}

/** `ucp-checkout`: the checkout the mandate issuer signs over. */
export function ucpCheckout(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; checkout?: unknown };
  return r.kind === "ucp-checkout" ? checkoutShown(r.checkout, network, false) : undefined;
}

/** `ucp-legal-context`: the checkout the platform's signed request completes, with the member `{type, value}`. */
export function ucpLegalContext(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; checkout?: unknown; legal_context?: unknown };
  if (r.kind !== "ucp-legal-context" || !isObject(r.legal_context)) return undefined;
  const { type, value } = r.legal_context;
  if (type !== "sha256" || typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) return undefined;
  return checkoutShown(r.checkout, network, false);
}

/** Days from 1970-01-01 to the civil date, in the proleptic Gregorian calendar. */
function daysFromCivil(y: number, m: number, d: number): number {
  const year = m <= 2 ? y - 1 : y;
  const era = Math.floor(year / 400);
  const yoe = year - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;

/**
 * An RFC 3339 `date-time` (section 5.6) as Unix seconds, a fraction of a second rounded up so the end is never read
 * early; undefined for another text, a field out of its range, or a time before 1970.
 */
function unixSeconds(s: unknown): string | undefined {
  const m = typeof s === "string" && s.length <= 64 ? RFC3339.exec(s) : null;
  if (m === null) return undefined;
  const [y, mo, d, hh, mi, ss] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i]));
  const leap = y! % 4 === 0 && (y! % 100 !== 0 || y! % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo! - 1];
  if (days === undefined || d! < 1 || d! > days || hh! > 23 || mi! > 59 || ss! > 60) return undefined;
  let offset = 0;
  if (m[8] !== undefined) {
    const [oh, om] = [Number(m[9]), Number(m[10])];
    if (oh > 23 || om > 59) return undefined;
    offset = (m[8] === "-" ? -1 : 1) * (oh * 3600 + om * 60);
  }
  const fraction = m[7] !== undefined && /[1-9]/.test(m[7]) ? 1 : 0;
  const t = daysFromCivil(y!, mo!, d!) * 86_400 + hh! * 3600 + mi! * 60 + ss! - offset + fraction;
  return t >= 0 && Number.isSafeInteger(t) ? String(t) : undefined;
}

/**
 * `acp-allowance`: ACP's allowance, the most the merchant may charge: `max_amount`, in `currency`'s minor units, to
 * `merchant_id`, until `expires_at`.
 */
export function acpAllowance(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; allowance?: unknown };
  if (r.kind !== "acp-allowance" || !isObject(r.allowance)) return undefined;
  const a = r.allowance;
  const maximum = amountOf(a["max_amount"]);
  const until = unixSeconds(a["expires_at"]);
  const { currency, merchant_id: merchant } = a;
  if (maximum === undefined || until === undefined || !text(currency) || !text(merchant)) return undefined;
  if (typeof network !== "string" || !CAIP2.test(network)) return undefined;
  return {
    maximum,
    payees: [{ account: merchant, amount: maximum }],
    asset: currency,
    network,
    validity: { notBefore: null, notAfter: until, unit: "seconds" },
  };
}
