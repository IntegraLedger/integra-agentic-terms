/**
 * The buyer pieces of the card pairings. The build input is the seller's document itself (the shown JSON for TAP, Agent
 * Pay, Visa Intelligent Commerce and the plain checkout, the `checkout_jwt` for Verifiable Intent), kept in `Chosen` as
 * `{doc}`. TAP's and Agent Pay's nonce goes to the agent's RFC 9421 signer, which places it in every message signature of
 * its checkout request and answers `{signatureInput, signature}`, from which `bound` reads the hash the nonce carries.
 * The Visa Intelligent Commerce transaction reference goes to the agent's credential client, which writes it into its
 * credential request and answers `{transactionReferenceId}` as the credential payload Visa signs returns it. The checkout
 * mandate goes to the wallet (L2, answering `{l2}`) or the agent (L3b, answering `{l1, l2, l3b}`). In Immediate mode the
 * agent may create the `checkout_jwt` itself: given the JSON the seller showed and the agent's checkout payload, as the
 * input `checkout`, the agent first signs the payload with the seller's `legalContext` written into it, answering
 * `{checkout_jwt}`, and the wallet then signs the checkout mandate over that `checkout_jwt`.
 */
import { fromBase64, toBase64Url, type AtrHash, type Json, type Refusal } from "@integraledger/lcp/core";
import type {
  TapPresented,
  TapUnsigned,
  VicPresented,
  VicUnsigned,
  ViAutonomous,
  ViCheckoutUnsigned,
  ViImmediate,
  ViUnsigned,
} from "@integraledger/lcp/card";
import type { BuyerPiece, Chosen, Inputs, Next, Presented, Read, Signature, SigningRequest } from "../types.js";
import { isObject, isRefusal, refuse } from "./common.js";
import { confirmOnlyPiece, objectChoice, unnamedBuyer } from "./protocol-groups.js";

const NS = "card";

/** `{doc}` for a named buyer; the document is the one the binding's `read` was given. */
function chooseDoc(_read: Read, account: string, _inputs: Inputs, _now: number, _ref: string, doc?: unknown) {
  const unnamed = unnamedBuyer(account, NS);
  if (unnamed !== undefined) return unnamed;
  return { doc: doc as Json };
}

function docOf(chosen: Chosen): unknown {
  const c = objectChoice(chosen, NS);
  if (isRefusal(c)) return c;
  return Object.hasOwn(c, "doc") ? c["doc"] : refuse("card/choice-malformed");
}

function strings<K extends string>(signature: Signature, keys: readonly K[]): { [k in K]: string } | undefined {
  if (!isObject(signature)) return undefined;
  const out = {} as { [k in K]: string };
  for (const k of keys) {
    const v = signature[k];
    if (typeof v !== "string" || v === "") return undefined;
    out[k] = v;
  }
  return out;
}

function signedPiece(
  pairing: string,
  request: (unsigned: unknown) => SigningRequest,
  complete: (unsigned: unknown, signature: Signature) => Presented | Refusal,
): BuyerPiece {
  return Object.freeze({
    choose(read: Read, account: string, inputs: Inputs, now: number, ref: string, doc?: unknown): Chosen | Refusal {
      const choice = chooseDoc(read, account, inputs, now, ref, doc);
      if (isRefusal(choice)) return choice;
      return { pairing, choice, ref };
    },
    choice: docOf,
    request,
    complete: async (unsigned: unknown, signature: Signature) => complete(unsigned, signature),
  });
}

/** The bytes of a TAP nonce: the hash's 32 bytes, then 32 random bytes. */
const TAP_NONCE_BYTES = 64;

/** Whether `nonce` is the padded base64 of 64 bytes whose first 32 are the hash's. */
function carriesHash(nonce: string, h: AtrHash): boolean {
  const bytes = fromBase64(nonce);
  if (!(bytes instanceof Uint8Array) || bytes.length !== TAP_NONCE_BYTES) return false;
  const want = h.slice(2).toLowerCase();
  let got = "";
  for (const b of bytes.subarray(0, 32)) got += (b < 16 ? "0" : "") + b.toString(16);
  return got === want;
}

/**
 * TAP's nonce exactly as built, for the agent's signer to place in every message signature of its checkout request.
 * The protocol package's build draws the nonce's random half, so the piece keeps the built nonce in `chosen` (`kept`),
 * and a rebuild from that `chosen` gives the nonce the signer was handed, once it is found to carry the hash.
 */
export function tapPiece(
  pairing: string,
  build: (doc: unknown, h: AtrHash) => Promise<TapUnsigned | Refusal>,
): BuyerPiece {
  const base = signedPiece(
    pairing,
    (unsigned) => ({ kind: "tap-field", ...(unsigned as TapUnsigned) }),
    (_unsigned, signature): TapPresented | Refusal => {
      const s = strings(signature, ["signatureInput", "signature"] as const);
      if (s === undefined) return refuse("card/signature-malformed");
      return { signatureInput: s.signatureInput, signature: s.signature };
    },
  );
  return Object.freeze({
    ...base,
    choice(chosen: Chosen): unknown {
      const c = objectChoice(chosen, NS);
      if (isRefusal(c)) return c;
      if (!Object.hasOwn(c, "doc")) return refuse("card/choice-malformed");
      const nonce = c["nonce"];
      if (nonce !== undefined && typeof nonce !== "string") return refuse("card/choice-malformed");
      return nonce === undefined ? { doc: c["doc"] } : { doc: c["doc"], nonce };
    },
    async build(choice: unknown, h: AtrHash): Promise<TapUnsigned | Refusal> {
      const c = choice as { doc: unknown; nonce?: string };
      if (c.nonce === undefined) return build(c.doc, h);
      return carriesHash(c.nonce, h) ? { nonce: c.nonce } : refuse("card/choice-malformed");
    },
    kept(chosen: Chosen, unsigned: unknown): Chosen {
      const c = objectChoice(chosen, NS);
      const nonce = (unsigned as Partial<TapUnsigned>).nonce;
      if (isRefusal(c) || typeof nonce !== "string") return chosen;
      return { ...chosen, choice: { ...(c as Record<string, Json>), nonce } };
    },
  });
}

/** The Visa Intelligent Commerce transaction reference exactly as built, for the agent's credential request. */
export function vicPiece(pairing: string): BuyerPiece {
  return signedPiece(
    pairing,
    (unsigned) => ({ kind: "vic-reference", ...(unsigned as VicUnsigned) }),
    (_unsigned, signature): VicPresented | Refusal => {
      const s = strings(signature, ["transactionReferenceId"] as const);
      return s === undefined ? refuse("card/signature-malformed") : { transactionReferenceId: s.transactionReferenceId };
    },
  );
}

/** The checkout mandate exactly as built, for the agent to sign as its L3b (Autonomous). */
export function viAutonomousPiece(pairing: string): BuyerPiece {
  return signedPiece(
    pairing,
    (unsigned) => ({ kind: "vi-checkout-mandate", ...(unsigned as ViUnsigned) }),
    (_unsigned, signature): ViAutonomous | Refusal => {
      const s = strings(signature, ["l1", "l2", "l3b"] as const);
      return s === undefined ? refuse("card/signature-malformed") : { l1: s.l1, l2: s.l2, l3b: s.l3b };
    },
  );
}

/**
 * Immediate mode. On a `checkout_jwt` the seller wrote, the checkout mandate exactly as built, for the user's wallet to
 * sign as its L2, answering `{l2}`. On the JSON the seller showed, with the agent's checkout payload as the input
 * `checkout`, two signings: the payload with the seller's `legalContext` written into it, exactly as built, for the agent
 * to sign as its `checkout_jwt`, answering `{checkout_jwt}`, whose payload must be that payload as `viJson` writes it;
 * then the checkout mandate over that `checkout_jwt`, for the wallet's L2.
 */
export function viImmediatePiece(
  pairing: string,
  build: (doc: unknown, h: AtrHash) => Promise<ViUnsigned | ViCheckoutUnsigned | Refusal>,
): BuyerPiece {
  const l2Of = (signature: Signature): ViImmediate | Refusal => {
    const s = strings(signature, ["l2"] as const);
    return s === undefined ? refuse("card/signature-malformed") : { l2: s.l2 };
  };
  const mandateRequest = (u: ViUnsigned): SigningRequest => ({ kind: "vi-checkout-mandate", ...u });
  /**
   * The checkout mandate over the agent's `checkout_jwt`, once its payload is found to be the payload handed, whose
   * `legalContext` the build wrote with the hash it was given.
   */
  const mandateOver = async (u: ViCheckoutUnsigned, answer: Signature): Promise<ViUnsigned | Refusal> => {
    const s = strings(answer, ["checkout_jwt"] as const);
    const encoded = viJson(u.checkout);
    const lc = u.checkout["legalContext"];
    const h = isObject(lc) ? lc["value"] : undefined;
    if (s === undefined || encoded === undefined || typeof h !== "string") return refuse("card/signature-malformed");
    const parts = s.checkout_jwt.split(".");
    if (parts.length !== 3 || parts[1] !== toBase64Url(new TextEncoder().encode(encoded))) return refuse("card/signature-malformed");
    const mandate = await build(s.checkout_jwt, h as AtrHash);
    if (isRefusal(mandate)) return mandate;
    return isObject(mandate) && Object.hasOwn(mandate, "checkoutMandate") ? (mandate as ViUnsigned) : refuse("card/vi-malformed");
  };
  return Object.freeze({
    choose(read: Read, account: string, inputs: Inputs, now: number, ref: string, doc?: unknown): Chosen | Refusal {
      const choice = chooseDoc(read, account, inputs, now, ref, doc);
      if (isRefusal(choice)) return choice;
      if (typeof doc === "string") return { pairing, choice, ref };
      const checkout = inputs["checkout"];
      if (!isObject(checkout)) return refuse("card/input-missing");
      return { pairing, choice: { ...choice, checkout }, ref };
    },
    choice(chosen: Chosen): unknown {
      const c = objectChoice(chosen, NS);
      if (isRefusal(c)) return c;
      if (!Object.hasOwn(c, "doc")) return refuse("card/choice-malformed");
      if (!Object.hasOwn(c, "checkout")) return c["doc"];
      return isObject(c["checkout"]) ? { checkout: c["checkout"], shown: c["doc"] } : refuse("card/choice-malformed");
    },
    request(unsigned: unknown): SigningRequest {
      const built = unsigned as ViUnsigned | ViCheckoutUnsigned;
      if (Object.hasOwn(built, "checkoutMandate")) return mandateRequest(built as ViUnsigned);
      return { kind: "vi-checkout", ...(built as ViCheckoutUnsigned) };
    },
    async complete(unsigned: unknown, signature: Signature): Promise<Presented | Next | Refusal> {
      const built = unsigned as ViUnsigned | ViCheckoutUnsigned;
      if (Object.hasOwn(built, "checkoutMandate")) return l2Of(signature);
      if (!Array.isArray(signature)) {
        const mandate = await mandateOver(built as ViCheckoutUnsigned, signature);
        return isRefusal(mandate) ? mandate : { next: mandateRequest(mandate) };
      }
      if (signature.length !== 2) return refuse("card/signature-malformed");
      const mandate = await mandateOver(built as ViCheckoutUnsigned, signature[0]!);
      return isRefusal(mandate) ? mandate : l2Of(signature[1]!);
    },
  });
}

// ── The signer's rule (lcp profile card-mastercard-vi.md, rule 7) ──

/** Python's `float.__repr__` exponent form for a number below 1e-4: `1e-05`, `1.5e-07`. */
function smallNumber(n: number): string {
  const [mantissa, exponent] = n.toExponential().split("e") as [string, string];
  const sign = exponent.startsWith("-") ? "-" : "+";
  const digits = exponent.replace(/^[-+]/, "");
  return `${mantissa}e${sign}${digits.length < 2 ? `0${digits}` : digits}`;
}

/** A string as the signer's rule writes it: every character outside space to `~` escaped. */
function viString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20 || c > 0x7e) out += `\\u${c.toString(16).padStart(4, "0")}`;
    else out += s[i];
  }
  return `${out}"`;
}

/**
 * JSON as a Verifiable Intent signer signs it (lcp profile `card-mastercard-vi.md`, rule 7): compact, with every
 * character outside space to `~` escaped, a non-ASCII one as `\uXXXX` in lowercase hex, one per UTF-16 code unit, and
 * members in the order the object holds them; the text Python's `json.dumps(value, separators=(",", ":"))` writes for
 * the value it parses from it. VI's reference verifier checks each signature over that re-encoding of the JSON it
 * parses, so a header or payload signed as this text is one it accepts. Each number is written so that Python reads and
 * writes it back unchanged: an integer as its digits, and a number below 1e-4 in Python's exponent form. Undefined for a
 * value that is not JSON: a number that is not finite, or anything but null, a boolean, a number, a string, an array
 * or a plain object.
 */
export function viJson(value: unknown): string | undefined {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return undefined;
    return !Number.isInteger(value) && Math.abs(value) < 1e-4 ? smallNumber(value) : JSON.stringify(value);
  }
  if (typeof value === "string") return viString(value);
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (const v of value) {
      const item = viJson(v);
      if (item === undefined) return undefined;
      items.push(item);
    }
    return `[${items.join(",")}]`;
  }
  if (!isObject(value) || Object.getPrototypeOf(value) !== Object.prototype) return undefined;
  const members: string[] = [];
  for (const [k, v] of Object.entries(value)) {
    const item = viJson(v);
    if (item === undefined) return undefined;
    members.push(`${viString(k)}:${item}`);
  }
  return `{${members.join(",")}}`;
}

/** The plain card checkout: the gate confirms only. */
export function sellerReferencePiece(pairing: string): BuyerPiece {
  return confirmOnlyPiece(pairing, chooseDoc);
}
