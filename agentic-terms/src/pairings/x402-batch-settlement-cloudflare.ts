/**
 * The buyer piece for `x402/batch-settlement/cloudflare`: the first option on `cloudflare:402` for the account's agent.
 * The build is itself the payment, echoing the challenge's extensions; the agent's HTTP message signature stack signs
 * the request that carries it, so the gate calls no signer.
 */
import type { Refusal } from "@integraledger/lcp";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature } from "../types.js";
import { choiceOf, isObject, refuse, withPaymentIdentifier, x402Chosen, x402OfferOf } from "./common.js";

const PAIRING = "x402/batch-settlement/cloudflare";
const NETWORK = "cloudflare:402";
/** `cloudflare:402:` and a CAIP-10 account reference naming the agent. */
const ACCOUNT = /^cloudflare:402:[-.%a-zA-Z0-9]{1,128}$/;

export const x402BatchSettlementCloudflare: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: Inputs, _now: number, ref: string): Chosen | Refusal {
    const offer = x402OfferOf(read);
    if (typeof account !== "string" || !ACCOUNT.test(account) || offer === undefined) return refuse("x402/no-payable-option");
    const accepted = offer.options.find((o) => isObject(o) && o.network === NETWORK);
    if (accepted === undefined) return refuse("x402/no-payable-option");
    return x402Chosen(PAIRING, { required: offer.required, accepted }, ref);
  },
  choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
  request: () => null,
  async complete(unsigned: unknown, _signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    return withPaymentIdentifier(unsigned as Presented, choiceOf(chosen)?.["required"], chosen.ref);
  },
});
