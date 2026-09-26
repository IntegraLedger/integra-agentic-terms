/**
 * The buyer piece for `x402/exact/starknet`: the request is SNIP-9's outside execution as SNIP-12 typed data for the
 * payer's account, whose nonce the build takes from the ATR hash; the account answers its signature as a list of felts.
 */
import type { Refusal } from "@integraledger/lcp";
import type { Felt, StarknetUnsigned } from "@integraledger/lcp/starknet";
import type { BuyerPiece, Chosen, Presented, Read, Signature } from "../types.js";
import { choiceOf, isRefusal, refuse, x402Chosen } from "./common.js";
import { identified, railOption } from "./x402-account-rails.js";

const PAIRING = "x402/exact/starknet";
const FELT = /^0x[0-9a-fA-F]{1,64}$/;

export const x402ExactStarknet: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: unknown, now: number, ref: string): Chosen | Refusal {
    const o = railOption(read, account, ["starknet"], PAIRING, (a) => FELT.test(a));
    if (isRefusal(o)) return o;
    return x402Chosen(PAIRING, { required: o.required, accepted: o.accepted, from: o.address, now }, ref);
  },
  choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
  request: (unsigned: unknown) => (unsigned as StarknetUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    if (!Array.isArray(signature) || !signature.every((s) => typeof s === "string")) {
      return refuse("x402/signature-malformed");
    }
    return identified((unsigned as StarknetUnsigned).complete(signature as Felt[]), chosen);
  },
});
