/**
 * The buyer piece for `ap2/checkout-mandate`: the build input is the offer `read` gives (the merchant's `checkout_jwt`
 * and its payload); the closed Checkout Mandate's claims go to the buyer's mandate signer, which answers the mandate
 * as issued, an SD-JWT string.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Unsigned } from "@integraledger/lcp/ap2";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { isObject, refuse } from "./common.js";
import { objectChoice, unnamedBuyer } from "./protocol-groups.js";

const PAIRING = "ap2/checkout-mandate";

export const ap2CheckoutMandate: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: Inputs, _now: number, ref: string): Chosen | Refusal {
    const unnamed = unnamedBuyer(account, "ap2");
    if (unnamed !== undefined) return unnamed;
    if (!isObject(read.offer)) return refuse("ap2/no-payable-option");
    return { pairing: PAIRING, choice: read.offer as Record<string, Json>, ref };
  },
  choice: (chosen: Chosen) => objectChoice(chosen, "ap2"),
  request: (unsigned: unknown): SigningRequest => ({
    kind: "ap2-checkout-mandate",
    content: (unsigned as Unsigned).content,
  }),
  async complete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
    if (typeof signature !== "string" || signature === "") return refuse("ap2/signature-malformed");
    return (unsigned as Unsigned).complete(signature);
  },
});
