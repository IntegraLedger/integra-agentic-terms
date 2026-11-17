/**
 * The buyer piece for `card/mastercard-vi/immediate`: the checkout mandate for the user's L2, over the seller's
 * `checkout_jwt` or over one the agent creates from its checkout payload.
 */
import { viImmediate } from "@integraledger/lcp/card";
import { viImmediatePiece } from "./card.js";

export const cardMastercardViImmediate = viImmediatePiece("card/mastercard-vi/immediate", (doc, h) => viImmediate.build(doc, h));
