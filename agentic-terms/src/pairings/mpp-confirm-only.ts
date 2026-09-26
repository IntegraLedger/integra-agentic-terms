/**
 * The buyer piece for MPP's `card` and `stripe` pairings: the first challenge, in document order, that offers the
 * pairing. Nothing the buyer's card or Stripe token signs carries the hash, and the binding builds nothing for the
 * buyer to sign, so the gate's comparison is the whole of the buyer's step.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Chosen, Inputs, Read } from "../types.js";
import { isObject, refuse } from "./common.js";
import { offers } from "./mpp.js";

const nothingToSign = (): Refusal => refuse("mpp/nothing-to-sign");

export function mppConfirmOnlyPiece(pairing: string): BuyerPiece {
  return Object.freeze({
    choose(read: Read, _account: string, _inputs: Inputs, now: number, ref: string): Chosen | Refusal {
      const offer = read.offer;
      const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
      const challenge = challenges.find((c) => offers(c, pairing));
      if (challenge === undefined) return refuse("mpp/no-payable-option");
      return { pairing, choice: { challenge: challenge as unknown as Json, now }, ref };
    },
    choice(chosen: Chosen): unknown {
      const c = isObject(chosen) && isObject(chosen.choice) ? chosen.choice : undefined;
      return c === undefined || !isObject(c["challenge"]) ? refuse("mpp/choice-malformed") : c;
    },
    request: () => nothingToSign(),
    complete: async () => nothingToSign(),
  });
}
