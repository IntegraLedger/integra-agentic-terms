/** The buyer piece for `ucp/booking/unsigned`: UCP defines no buyer signature here, so the gate confirms only. */
import { ucpUnsignedPiece } from "./ucp.js";

export const ucpBookingUnsigned = ucpUnsignedPiece("ucp/booking/unsigned");
