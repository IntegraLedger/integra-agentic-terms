/**
 * The buyer pieces of the UCP pairings. The build input is the offer `read` gives, `{checkout}`. Under the AP2
 * Mandates extension the checkout goes, unchanged, to the buyer's mandate issuer, which answers the checkout mandate
 * as issued, an SD-JWT string. Without it the gate confirms only.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Unsigned } from "@integraledger/lcp/ucp";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { isObject, isRefusal, refuse } from "./common.js";
import { confirmOnlyPiece, objectChoice, unnamedBuyer } from "./protocol-groups.js";

function chooseCheckout(read: Read, account: string, _inputs: Inputs, _now: number, _ref: string) {
  const unnamed = unnamedBuyer(account, "ucp");
  if (unnamed !== undefined) return unnamed;
  if (!isObject(read.offer)) return refuse("ucp/no-payable-option");
  return read.offer as Record<string, Json>;
}

/** The piece of a UCP pairing under the AP2 Mandates extension. */
export function ucpMandatePiece(pairing: string): BuyerPiece {
  return Object.freeze({
    choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
      const choice = chooseCheckout(read, account, inputs, now, ref);
      if (isRefusal(choice)) return choice;
      return { pairing, choice, ref };
    },
    choice: (chosen: Chosen) => objectChoice(chosen, "ucp"),
    request: (unsigned: unknown): SigningRequest => ({
      kind: "ucp-checkout",
      checkout: (unsigned as Unsigned).checkout,
    }),
    async complete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
      if (typeof signature !== "string" || signature === "") return refuse("ucp/signature-malformed");
      return (unsigned as Unsigned).complete(signature);
    },
  });
}

/** The piece of a UCP pairing without the AP2 Mandates extension: the gate confirms only. */
export function ucpUnsignedPiece(pairing: string): BuyerPiece {
  return confirmOnlyPiece(pairing, chooseCheckout);
}
