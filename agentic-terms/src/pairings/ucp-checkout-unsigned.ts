/** The buyer piece for `ucp/checkout/unsigned`: UCP defines no buyer signature here, so the gate confirms only. */
import { ucpUnsignedPiece } from "./ucp.js";

export const ucpCheckoutUnsigned = ucpUnsignedPiece("ucp/checkout/unsigned");
