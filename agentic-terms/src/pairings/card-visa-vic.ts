/**
 * The buyer piece for `card/visa-vic`: the transaction reference the agent writes into its Visa Intelligent Commerce
 * credential request. Nothing the payer signs carries it, so the pairing is paid after its agreement.
 */
import { vicPiece } from "./card.js";

export const cardVisaVic = vicPiece("card/visa-vic");
