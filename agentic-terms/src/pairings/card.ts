/**
 * The buyer pieces of the card pairings. The build input is the seller's document itself (the shown JSON for TAP and
 * the plain checkout, the `checkout_jwt` for Verifiable Intent), kept in `Chosen` as `{doc}`. The TAP field goes to the
 * agent's RFC 9421 signer, which answers `{signatureInput, signature, lcpHash}`, `lcpHash` being every `lcp-hash` field
 * line it sent, in order, which `bound` reads. The checkout mandate goes to the wallet (L2, answering `{l2}`) or the
 * agent (L3b, answering `{l1, l2, l3b}`).
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { TapPresented, TapUnsigned, ViAutonomous, ViImmediate, ViUnsigned } from "@integraledger/lcp/card";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { isObject, isRefusal, refuse } from "./common.js";
import { confirmOnlyPiece, objectChoice, unnamedBuyer } from "./protocol-groups.js";

const NS = "card";

/** `{doc}` for a named buyer; the document is the one the binding's `read` was given. */
function chooseDoc(_read: Read, account: string, _inputs: Inputs, _now: number, _ref: string, doc?: unknown) {
  const unnamed = unnamedBuyer(account, NS);
  if (unnamed !== undefined) return unnamed;
  if (doc === undefined) return refuse("card/document-missing");
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

/** The TAP field exactly as built, for the agent's signer to add and list in its `agent-payer-auth` signature. */
export function tapPiece(pairing: string): BuyerPiece {
  return signedPiece(
    pairing,
    (unsigned) => ({ kind: "tap-field", ...(unsigned as TapUnsigned) }),
    (_unsigned, signature): TapPresented | Refusal => {
      const s = strings(signature, ["signatureInput", "signature"] as const);
      const lines: unknown = isObject(signature) ? signature["lcpHash"] : undefined;
      if (s === undefined || !Array.isArray(lines)) return refuse("card/signature-malformed");
      return { signatureInput: s.signatureInput, signature: s.signature, lcpHash: lines as string[] };
    },
  );
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
