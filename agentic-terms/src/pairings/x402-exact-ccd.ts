/**
 * The buyer piece for `x402/exact/ccd`: the transfer the wallet assembles, with the hash in its memo; the answer is the
 * sender-signed V1 sponsored transaction in x402's wire form, the JSON-serialized transaction: with
 * `@concordium/web-sdk`, `JSON.parse(Transaction.toJSONString(tx))`. Any other value is `ccd/transaction-malformed`.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { CcdUnsigned } from "@integraledger/lcp/ccd";
import type { BuyerPiece, Chosen, Presented, Read, Signature } from "../types.js";
import { choiceOf, firstOption, isObject, isRefusal, refuse, withPaymentIdentifier, x402Chosen } from "./common.js";

const ID = "x402/exact/ccd";

export const x402ExactCcd: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: unknown, now: number, ref: string): Chosen | Refusal {
    const o = firstOption(read, account, "ccd", ID);
    if (isRefusal(o)) return refuse("x402/no-payable-option");
    return x402Chosen(ID, { required: o.required, accepted: o.accepted, now }, ref);
  },
  choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
  request: (unsigned: unknown) => (unsigned as CcdUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    if (!isObject(signature)) return refuse("x402/signature-malformed");
    const signed = (unsigned as CcdUnsigned).complete(signature as Json);
    if (isRefusal(signed)) return signed;
    return withPaymentIdentifier(signed as unknown as Presented, choiceOf(chosen)?.["required"], chosen.ref);
  },
});
