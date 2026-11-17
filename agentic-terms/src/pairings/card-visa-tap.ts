/** The buyer piece for `card/visa-tap`: the nonce the agent's signer places in its message signatures. */
import { visaTap } from "@integraledger/lcp/card";
import { tapPiece } from "./card.js";

export const cardVisaTap = tapPiece("card/visa-tap", (doc, h) => visaTap.build(doc as never, h));
