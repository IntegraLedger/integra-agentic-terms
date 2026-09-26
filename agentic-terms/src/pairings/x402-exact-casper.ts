/**
 * The buyer piece for `x402/exact/casper`: the CEP-3009 typed data with the hash as its nonce, signed by the account's
 * key; the answer is `{publicKey, signature}`, each hex with its one-byte algorithm tag.
 */
import type { Refusal } from "@integraledger/lcp";
import type { CasperUnsigned } from "@integraledger/lcp/casper";
import type { BuyerPiece, Chosen, Presented, Read, Signature } from "../types.js";
import { choiceOf, firstOption, isObject, refuse, withPaymentIdentifier, x402Chosen } from "./common.js";

const ID = "x402/exact/casper";

export const x402ExactCasper: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: unknown, now: number, ref: string): Chosen | Refusal {
    const o = firstOption(read, account, "casper", ID);
    if ("refused" in o) return refuse("x402/no-payable-option");
    return x402Chosen(ID, { required: o.required, accepted: o.accepted, from: o.address, now }, ref);
  },
  choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
  request: (unsigned: unknown) => (unsigned as CasperUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    if (!isObject(signature) || typeof signature["publicKey"] !== "string" || typeof signature["signature"] !== "string") {
      return refuse("x402/signature-malformed");
    }
    const signed = (unsigned as CasperUnsigned).complete(signature["publicKey"], signature["signature"]);
    if ("refused" in signed) return signed;
    return withPaymentIdentifier(signed as Presented, choiceOf(chosen)?.["required"], chosen.ref);
  },
});
