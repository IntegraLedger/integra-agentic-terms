/**
 * The buyer piece for `mpp/subscription/stripe`: nothing the buyer's Stripe payment method signs carries the hash; the
 * gate confirms only.
 */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppSubscriptionStripe = mppConfirmOnlyPiece("mpp/subscription/stripe");
