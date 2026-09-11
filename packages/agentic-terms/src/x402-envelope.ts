/**
 * ⛔⛔ **THE BUYER HALF OF THE x402 WIRE, DERIVED FROM THE CHALLENGE INSTEAD OF RESTATED BESIDE IT.**
 *
 * x402 §6.1: a payment ANSWERS ONE OFFER. The `accepted` entry a payer presents is the entry it was
 * served — a conformant resource server re-derives its own advertisement and rejects a combination it
 * never made. So the envelope is not a form to fill in; it is an echo of the offer, plus the payer's own
 * signed instrument.
 *
 * ## Why this is the last piece, and why it is small
 *
 * The payment primitive is already public: `@integraledger/lcp-binding-evm-x402` builds the EIP-3009
 * authorization with `nonce = atrHash`, which is the weld. What was never public is the ENVELOPE — the
 * `PAYMENT-SIGNATURE` value that carries that authorization back to the seller in the shape x402 defines.
 * With it, a stock x402 client plus this one package completes 402 → pay → 200 against a seller serving
 * Legal Context Protocol terms. Without it, every buyer wrote the envelope by hand.
 *
 * ## ⛔ A payment must not be constructible from nothing, and that is this module's shape
 *
 * {@link x402PaymentHeader} takes the challenge as a REQUIRED argument and derives the `accepted` entry
 * from it here. A caller therefore cannot build a payment without having been served an offer. Buyers that
 * hand-built the entry from a local template — no `scheme`, no `network`, no `payTo`, no `asset`, no
 * `amount` — presented payments answering an offer nobody had made, and the seller compared them to
 * nothing for as long as the seller was equally lax.
 *
 * ⭐ **The repair is not to write the missing fields down here.** A second copy of the advertisement in
 * the buyer is the same defect one layer over: it agrees with the seller on the day it is written and
 * drifts silently after. The entry is READ OFF THE 402 THIS BUYER WAS SERVED, so there is no constant to
 * go stale — a field added to the advertisement is echoed from the moment it is added, and a field changed
 * is echoed changed.
 *
 * ⚠️ **The wire is read as `unknown` and validated.** A buyer is a counterparty; it does not get to assume
 * the seller's types. Every refusal here is loud and says which part of the challenge could not be read —
 * never a default that papers over a challenge this buyer could not parse, because that is how a payment
 * gets built against an offer nobody made.
 *
 * ## Runtime neutrality
 *
 * Base64 goes through `btoa`/`atob` over `TextEncoder`/`TextDecoder` rather than through `Buffer`, so this
 * module runs unchanged on every runtime this package supports. `atob` alone is not enough: it yields
 * latin-1 code units, and a terms document with a non-ASCII character in the advertisement would decode to
 * mojibake and then re-encode to bytes the seller never signed.
 */

/** A record whose own keys are its own — never a value reached through the prototype. */
function ownRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** UTF-8 bytes, then standard padded base64. Not `btoa(text)`, which mangles anything above U+00FF. */
function utf8ToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** The inverse: base64 to bytes, bytes to UTF-8 text. */
function base64ToUtf8(encoded: string): string {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/**
 * Decode the 402 the way a conformant client does: standard padded base64 JSON off `payment-required`.
 *
 * ⚠️ The HEADER rather than the body, deliberately — it is the carrier the host protocol defines, the body
 * is a convenience, and reading the body would consume a stream the caller may still want. Fail fast when
 * the header is absent: a 402 without it is not a challenge this buyer can answer.
 *
 * The return is `unknown` on purpose. It is a counterparty's document; everything downstream validates it
 * rather than trusting it, and handing back a typed shape would be asserting one this function cannot
 * check.
 */
export function decodeX402Challenge(response: Response): unknown {
  const header = response.headers.get("payment-required");
  if (header === null)
    throw new Error(
      "the 402 carried no `payment-required` header — there is no advertisement to answer, and a payment built without one answers no offer",
    );
  return JSON.parse(base64ToUtf8(header)) as unknown;
}

/**
 * The `accepted` entry to present: `accepts[0]` EXACTLY AS SERVED, plus the one field the presentation
 * owns.
 *
 * ⚠️ `assetTransferMethod` is merged into `extra` rather than echoed, because the seller does not advertise
 * one — it is a property of how this buyer chose to pay. Everything else is the seller's own text, returned
 * unaltered: a conformant server compares `payTo` and the asset fields as STRINGS, so even a re-casing is a
 * different offer.
 *
 * ⛔ Not a merge over a local template — a copy of the served entry. Anything this function added beyond
 * `extra.assetTransferMethod` would be a claim the seller never made.
 */
export function x402AcceptedEntry(
  challenge: unknown,
  presentation: { readonly assetTransferMethod: string },
): Record<string, unknown> {
  const document = ownRecord(challenge);
  if (document === null)
    throw new Error(
      "the x402 challenge is not a JSON object — nothing on it can be answered",
    );
  const accepts = document["accepts"];
  if (!Array.isArray(accepts) || accepts.length === 0)
    throw new Error(
      "the x402 challenge carried no `accepts[]` — this seller advertised no offer to answer",
    );
  const entry = ownRecord(accepts[0]);
  if (entry === null)
    throw new Error(
      "the x402 challenge's `accepts[0]` is not a readable object — there is no entry to echo",
    );
  const extra = ownRecord(entry["extra"]);
  if (extra === null)
    throw new Error(
      "the x402 challenge's `accepts[0].extra` is not a readable object — the EIP-712 domain and the legal-context carrier both live there",
    );
  return {
    ...entry,
    extra: { ...extra, assetTransferMethod: presentation.assetTransferMethod },
  };
}

/**
 * The buyer's OWN instrument, stated structurally rather than imported.
 *
 * This is the payload the payer authored and the token contract will read — not a restatement of anything
 * the seller advertised. `nonce` is where the weld rides: on this rail the EIP-3009 nonce IS the `atrHash`,
 * which is why a payment can commit to a terms document without the token contract knowing what one is.
 *
 * Declared here rather than imported from a rail binding: this package halts before a signing key is
 * invoked and holds no chain SDK, so the shape it describes is the one it accepts from the caller.
 */
export interface X402Authorization {
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
}

/** Everything {@link x402PaymentHeader} needs, and nothing it could invent. */
export interface X402PaymentInput {
  /** The decoded 402 this payment answers. REQUIRED — see the module note. */
  readonly challenge: unknown;
  readonly authorization: X402Authorization;
  /** The payer's signature over the EIP-712 typed data for `authorization`. */
  readonly signature: string;
  /** The correlation id carried through proposal → receipt → evidence. */
  readonly paymentIdentifier: string;
  /** How this buyer chose to move the asset, e.g. `"eip3009"`. */
  readonly assetTransferMethod: string;
}

/**
 * The `PAYMENT-SIGNATURE` value: base64 JSON, x402 version 2, answering the challenge it was handed.
 *
 * ⭐ The challenge is a REQUIRED argument and the `accepted` entry is derived from it here, so a caller
 * cannot build a payment without having been served an offer. That is the whole point of the shape.
 *
 * ⚠️ The legal-context carrier is echoed too: `accepts[0].extra.atrHash` rides along inside the copied
 * entry, and the challenge's document-level `extensions` is restated so the payment presents the carrier on
 * the same field the challenge did. A reader may accept any of the placements the protocol allows;
 * presenting the one we were served is the honest answer rather than the minimal one.
 */
export function x402PaymentHeader(input: X402PaymentInput): string {
  const document = ownRecord(input.challenge);
  const extensions = ownRecord(document?.["extensions"]);
  const payment = {
    x402Version: 2,
    accepted: x402AcceptedEntry(input.challenge, {
      assetTransferMethod: input.assetTransferMethod,
    }),
    ...(extensions === null ? {} : { extensions }),
    payload: { authorization: input.authorization, signature: input.signature },
    paymentIdentifier: input.paymentIdentifier,
  };
  return utf8ToBase64(JSON.stringify(payment));
}
