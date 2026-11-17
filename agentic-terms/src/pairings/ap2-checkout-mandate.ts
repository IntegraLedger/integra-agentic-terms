/**
 * The buyer piece for `ap2/checkout-mandate`: the build input is the offer `read` gives (the merchant's `checkout_jwt`
 * and its payload); the closed Checkout Mandate's claims go to the buyer's mandate signer, which answers the mandate
 * as issued, an SD-JWT string, or AP2's chained presentation of the open and closed mandates joined by `~~`. In AP2's
 * push funding, where the payer's side sends the funds itself, the signer answers `{checkout_mandate,
 * payment_receipt}`: the mandate and AP2's Payment Receipt, the confirmation of the funds it sent, which the
 * presentation carries. Such a payment has moved once the signer answers, so a decline after it keeps it.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { Unsigned } from "@integraledger/lcp/ap2";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { isObject, refuse } from "./common.js";
import { objectChoice, unnamedBuyer } from "./protocol-groups.js";

const PAIRING = "ap2/checkout-mandate";

/** The checkout `read` gives, chosen for `pairing` where the account names the buyer. */
export function chooseAp2(pairing: string) {
  return (read: Read, account: string, _inputs: Inputs, _now: number, ref: string): Chosen | Refusal => {
    const unnamed = unnamedBuyer(account, "ap2");
    if (unnamed !== undefined) return unnamed;
    if (!isObject(read.offer)) return refuse("ap2/no-payable-option");
    return { pairing, choice: read.offer as Record<string, Json>, ref };
  };
}

/** The closed Checkout Mandate's claims, for the buyer's mandate signer. */
export const ap2Request = (unsigned: unknown): SigningRequest => ({
  kind: "ap2-checkout-mandate",
  content: (unsigned as Unsigned).content,
});

/** Whether the signer's answer is a push funding's: the mandate with the Payment Receipt of the funds its side sent. */
const pushed = (signature: Signature): signature is { checkout_mandate: string; payment_receipt: Record<string, Json> } =>
  isObject(signature) && isObject(signature["payment_receipt"]);

export const ap2CheckoutMandate: BuyerPiece = Object.freeze({
  choose: chooseAp2(PAIRING),
  choice: (chosen: Chosen) => objectChoice(chosen, "ap2"),
  request: ap2Request,
  async complete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
    if (pushed(signature)) {
      const { checkout_mandate, payment_receipt } = signature;
      if (typeof checkout_mandate !== "string" || checkout_mandate === "" || Object.keys(signature).length !== 2) {
        return refuse("ap2/signature-malformed");
      }
      return { ...(unsigned as Unsigned).complete(checkout_mandate), payment_receipt };
    }
    if (typeof signature !== "string" || signature === "") return refuse("ap2/signature-malformed");
    return (unsigned as Unsigned).complete(signature);
  },
  movedBy: pushed,
});
