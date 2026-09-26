/** The buyer piece for `mpp/charge/stripe`: nothing the buyer's Stripe token signs carries the hash; the gate confirms only. */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppChargeStripe = mppConfirmOnlyPiece("mpp/charge/stripe");
