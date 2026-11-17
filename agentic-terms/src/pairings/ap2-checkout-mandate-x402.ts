/**
 * The buyer piece for `ap2/checkout-mandate/x402`: AP2's checkout paid with AP2's x402 payment credential. The build is
 * `ap2/checkout-mandate`'s: the closed Checkout Mandate's claims over the merchant's `checkout_jwt` go to the buyer's
 * mandate signer. The x402 payment is the buyer's own credential provider's: AP2's x402 bundle, whose EIP-3009
 * authorization's nonce is keccak-256 of the payment mandate chain, so it carries no hash of the ATR and nothing builds
 * it here. The signer answers `{checkout_mandate, payment}`, the mandate as issued and that bundle as the provider
 * wrote it; the merchant forwards the bundle to its payment processor, which submits the authorization.
 */
import type { Refusal } from "@integraledger/lcp/core";
import type { Unsigned, X402Bundle } from "@integraledger/lcp/ap2";
import type { BuyerPiece, Chosen, Presented, Signature } from "../types.js";
import { isObject, refuse } from "./common.js";
import { objectChoice } from "./protocol-groups.js";
import { ap2Request, chooseAp2 } from "./ap2-checkout-mandate.js";

const PAIRING = "ap2/checkout-mandate/x402";

export const ap2CheckoutMandateX402: BuyerPiece = Object.freeze({
  choose: chooseAp2(PAIRING),
  choice: (chosen: Chosen) => objectChoice(chosen, "ap2"),
  request: ap2Request,
  async complete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
    if (!isObject(signature) || Object.keys(signature).length !== 2) return refuse("ap2/signature-malformed");
    const { checkout_mandate, payment } = signature;
    if (typeof checkout_mandate !== "string" || checkout_mandate === "" || !isObject(payment)) {
      return refuse("ap2/signature-malformed");
    }
    return { ...(unsigned as Unsigned).complete(checkout_mandate), payment: payment as unknown as X402Bundle };
  },
});
