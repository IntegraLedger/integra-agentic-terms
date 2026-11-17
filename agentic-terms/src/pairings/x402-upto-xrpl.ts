/**
 * The buyer piece for `x402/upto/xrpl`, x402's `upto` scheme on the XRP Ledger, at coverage `none`: the first option,
 * in document order, that the pairing's read offers. The payer's own client opens the payment channel to the option's
 * `payTo` and signs one claim over the channel's id and the maximum, and neither carries the hash, so the protocol
 * package builds nothing and nothing is handed to the signer. The proof of the hash is the agreement payment, on the
 * option's own network, paid before the client opens the channel, from the account that opens it (the protocol
 * package's profile `x402-upto-xrpl.md`, rule 9); the option stays in the choice as `accepted`, so the agreement is
 * paid on its network.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { BuyerPiece, Chosen, Inputs, Read } from "../types.js";
import { choiceOf, isObject, refuse, x402OfferOf } from "./common.js";

const PAIRING = "x402/upto/xrpl";

const nothingToSign = (): Refusal => refuse("x402/nothing-to-sign");

export const x402UptoXrpl: BuyerPiece = Object.freeze({
  choose(read: Read, _account: string, _inputs: Inputs, _now: number, ref: string): Chosen | Refusal {
    const accepted: unknown = x402OfferOf(read)?.options[0];
    if (!isObject(accepted)) return refuse("x402/no-payable-option");
    return { pairing: PAIRING, choice: { accepted: accepted as Json }, ref };
  },
  choice(chosen: Chosen): unknown {
    const c = choiceOf(chosen);
    return c === undefined || !isObject(c["accepted"]) ? refuse("x402/choice-malformed") : c;
  },
  request: () => nothingToSign(),
  complete: async () => nothingToSign(),
});
