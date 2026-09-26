/** The buyer piece for `card/visa-tap`: the `lcp-hash` field for the agent's `agent-payer-auth` signature. */
import { tapPiece } from "./card.js";

export const cardVisaTap = tapPiece("card/visa-tap");
