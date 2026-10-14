/**
 * The buyer piece for `mpp/charge/nearintents`: the first challenge offering the pairing whose `originNetwork` is the
 * account's network. Nothing the buyer deposits carries the hash, and the binding builds nothing for the buyer to sign:
 * the proof of the hash is the agreement payment the offer's agreement URL asks for, whose signed payload carries it.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { BuyerPiece, Chosen } from "../types.js";
import { refuse } from "./common.js";
import { railChoose } from "./mpp-rails.js";

const PAIRING = "mpp/charge/nearintents";

const nothingToSign = (): Refusal => refuse("mpp/nothing-to-sign");

export const mppChargeNearIntents: BuyerPiece = Object.freeze({
  choose: railChoose({
    pairing: PAIRING,
    namespace: null,
    address: /^.+$/,
    payer: null,
    now: false,
    inputs: (): Record<string, Json> => ({}),
    revive: (c: Record<string, unknown>) => c,
    complete: async () => nothingToSign(),
  }),
  choice: (_chosen: Chosen) => nothingToSign(),
  request: () => nothingToSign(),
  complete: async () => nothingToSign(),
});
