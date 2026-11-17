/**
 * The card requests (profile `buyer-gate.md`, rule 13): `tap-field`, `vic-reference`, `vi-checkout` and
 * `vi-checkout-mandate`. None signs a transfer of value: the card charge is the seller's, made through the card network,
 * so the payment moves on no ledger and the summary's network is null; nothing in the request names the charge's amount,
 * its payee or its currency, so the summary names no amount and no payee, and its asset is the empty string. Nor does the request name an expiry: the agent's signer or the
 * user's wallet sets the signature's own, so the request signs no end. A Verifiable Intent request grants the checkout
 * its signature binds, shown as `grant`: the agent's checkout payload, or the payload of the `checkout_jwt` the checkout
 * mandate names.
 */
import type { Json } from "@integraledger/lcp/core";
import { fromBase64Url } from "@integraledger/lcp/core";
import { MAX_CHECKOUT_JWT } from "@integraledger/lcp/card";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { isObject } from "./evm-fields.js";

/** What every card request shows, made anew for each: no amount, payee or currency named, no ledger, and no end signed. */
const nothingNamed = (): Shown => ({
  payees: [],
  asset: "",
  network: null,
  validity: { notBefore: null, notAfter: null, unit: "seconds" },
});

/** The longest member read: the longest `checkout_jwt` the protocol package reads. */
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_CHECKOUT_JWT;

/** `tap-field`, the nonce for the agent's message signatures: `card/visa-tap`, `card/mastercard-agent-pay`. */
export function tapField(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; nonce?: unknown };
  return r.kind === "tap-field" && text(r.nonce) ? nothingNamed() : undefined;
}

/** `vic-reference`, the transaction reference for the agent's credential request: `card/visa-vic`. */
export function vicReference(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; transactionReferenceId?: unknown };
  return r.kind === "vic-reference" && text(r.transactionReferenceId) ? nothingNamed() : undefined;
}

/** `vi-checkout`, the agent's checkout payload for its `checkout_jwt`: its grant is the payload. */
export function viCheckout(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; checkout?: unknown };
  if (r.kind !== "vi-checkout" || !isObject(r.checkout)) return undefined;
  // A copy: nothing the approver does to the summary reaches the request the signer is handed.
  return { ...nothingNamed(), grant: structuredClone(r.checkout) as Json };
}

/** The payload of a compact JWS, its second segment as canonical base64url of UTF-8 JSON naming an object; else undefined. */
function payloadOf(jws: string): Json | undefined {
  const parts = jws.split(".");
  if (parts.length !== 3) return undefined;
  const bytes = fromBase64Url(parts[1]!);
  if (bytes === null) return undefined;
  try {
    const payload: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return isObject(payload) ? (payload as Json) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * `vi-checkout-mandate`, the checkout mandate for the user's L2 or the agent's L3b: its grant is the payload of the
 * `checkout_jwt` it names.
 */
export function viCheckoutMandate(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; checkoutMandate?: unknown; transactionId?: unknown };
  if (r.kind !== "vi-checkout-mandate" || !isObject(r.checkoutMandate) || !text(r.transactionId)) return undefined;
  const m = r.checkoutMandate;
  if (m["vct"] !== "mandate.checkout.1" || !text(m["checkout_jwt"]) || !text(m["checkout_hash"])) return undefined;
  const grant = payloadOf(m["checkout_jwt"]);
  return grant === undefined ? undefined : { ...nothingNamed(), grant };
}
