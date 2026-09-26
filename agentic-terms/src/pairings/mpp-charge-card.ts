/** The buyer piece for `mpp/charge/card`: nothing the buyer's card token signs carries the hash; the gate confirms only. */
import { mppConfirmOnlyPiece } from "./mpp-confirm-only.js";

export const mppChargeCard = mppConfirmOnlyPiece("mpp/charge/card");
