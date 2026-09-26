/**
 * The buyer piece for `x402/exact/near`: the request is the NEP-461 hash of the delegate action whose one
 * `ft_transfer` carries the ATR hash in its memo. The buyer supplies its key and the key's nonce and the final block
 * height from its RPC; the key answers `{keyType, bytes}`, with the 64- or 65-byte signature as `0x` hex.
 */
import type { Refusal } from "@integraledger/lcp";
import type { NearUnsigned } from "@integraledger/lcp/near";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature } from "../types.js";
import { bigintOf, bytesOf, choiceOf, inputsOf, isObject, isRefusal, refuse, x402Chosen } from "./common.js";
import { identified, railOption } from "./x402-account-rails.js";

const PAIRING = "x402/exact/near";
const NEAR_ACCOUNT = /^[a-z0-9._-]{2,64}$/;

export const x402ExactNear: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, _now: number, ref: string): Chosen | Refusal {
    const o = railOption(read, account, ["near"], PAIRING, (a) => NEAR_ACCOUNT.test(a));
    if (isRefusal(o)) return o;
    const given = inputsOf(inputs, PAIRING, { publicKey: "string", accessKeyNonce: "decimal", finalHeight: "decimal" });
    if (isRefusal(given)) return given;
    return x402Chosen(PAIRING, { required: o.required, accepted: o.accepted, payer: o.address, ...given }, ref);
  },
  choice(chosen: Chosen): unknown {
    const c = choiceOf(chosen);
    const accessKeyNonce = bigintOf(c?.["accessKeyNonce"]);
    const finalHeight = bigintOf(c?.["finalHeight"]);
    if (c === undefined || accessKeyNonce === undefined || finalHeight === undefined) {
      return refuse("x402/choice-malformed");
    }
    return { ...c, accessKeyNonce, finalHeight };
  },
  request: (unsigned: unknown) => (unsigned as NearUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    if (!isObject(signature)) return refuse("x402/signature-malformed");
    const { keyType } = signature;
    const bytes = bytesOf(signature["bytes"]);
    if ((keyType !== 0 && keyType !== 1) || bytes === undefined) return refuse("x402/signature-malformed");
    return identified((unsigned as NearUnsigned).complete({ keyType, bytes }), chosen);
  },
});
