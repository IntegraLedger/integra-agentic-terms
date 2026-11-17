/**
 * The buyer piece for `mpp/subscription/solana`: the first challenge, in document order, that offers the pairing. The
 * buyer's stock `@solana/mpp` client composes and signs the activation, writing the request's `externalId`, H's LCP
 * string, as its Memo instruction; the activation's `transfer_subscription` also takes the challenge's `puller`, the
 * seller's key, as a signer, so the seller's server co-signs and submits it. The protocol package builds nothing for
 * this pairing and nothing is handed to the signer: the gate compares the ATR, and `check` reads H from the activation
 * the buyer's client signed.
 */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppSubscriptionSolana = mppConfirmOnlyPiece("mpp/subscription/solana");
