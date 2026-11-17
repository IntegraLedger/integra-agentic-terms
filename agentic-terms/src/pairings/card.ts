/**
 * The buyer pieces of the card pairings. The build input is the seller's document itself (the shown JSON for TAP and
 * the plain checkout, the `checkout_jwt` for Verifiable Intent), kept in `Chosen` as `{doc}`. TAP's nonce goes to the
 * agent's RFC 9421 signer, which places it in every message signature of its checkout request and answers
 * `{signatureInput, signature}`, from which `bound` reads the hash the nonce carries. The checkout mandate goes to the
 * wallet (L2, answering `{l2}`) or the agent (L3b, answering `{l1, l2, l3b}`).
 */
import { fromBase64, type AtrHash, type Json, type Refusal } from "@integraledger/lcp/core";
import type { TapPresented, TapUnsigned, ViAutonomous, ViImmediate, ViUnsigned } from "@integraledger/lcp/card";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
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

/** The checkout mandate exactly as built, for the wallet (Immediate) or the agent (Autonomous) to sign. */
export function viPiece(pairing: string, mode: "immediate" | "autonomous"): BuyerPiece {
  return signedPiece(
    pairing,
    (unsigned) => ({ kind: "vi-checkout-mandate", ...(unsigned as ViUnsigned) }),
    (_unsigned, signature): ViImmediate | ViAutonomous | Refusal => {
      if (mode === "immediate") {
        const s = strings(signature, ["l2"] as const);
        return s === undefined ? refuse("card/signature-malformed") : { l2: s.l2 };
      }
      const s = strings(signature, ["l1", "l2", "l3b"] as const);
      return s === undefined ? refuse("card/signature-malformed") : { l1: s.l1, l2: s.l2, l3b: s.l3b };
    },
  );
}

/** The plain card checkout: the gate confirms only. */
export function sellerReferencePiece(pairing: string): BuyerPiece {
  return confirmOnlyPiece(pairing, chooseDoc);
}
