/** The buyer piece for `card/mastercard-agent-pay`: the nonce the agent's signer places in its Agent Pay message signatures. */
import { agentPay } from "@integraledger/lcp/card";
import { tapPiece } from "./card.js";

export const cardMastercardAgentPay = tapPiece("card/mastercard-agent-pay", (doc, h) => agentPay.build(doc as never, h));
