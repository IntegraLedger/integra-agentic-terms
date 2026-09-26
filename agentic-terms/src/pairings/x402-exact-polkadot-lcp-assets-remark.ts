/**
 * The buyer piece for `x402/exact/polkadot/lcp-assets-remark`: the request is the profile's call, which the wallet
 * signs as a v4 extrinsic with its own extensions and answers as the extrinsic's bytes in `0x` hex.
 */
import type { Refusal } from "@integraledger/lcp";
import { ss58Decode, type PolkadotUnsigned } from "@integraledger/lcp/polkadot";
import type { BuyerPiece, Chosen, Presented, Read, Signature } from "../types.js";
import { bytesOf, choiceOf, isRefusal, refuse, x402Chosen } from "./common.js";
import { identified, railOption } from "./x402-account-rails.js";

const PAIRING = "x402/exact/polkadot/lcp-assets-remark";

export const x402ExactPolkadotLcpAssetsRemark: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: unknown, _now: number, ref: string): Chosen | Refusal {
    const o = railOption(read, account, ["polkadot"], PAIRING, (a) => !isRefusal(ss58Decode(a)));
    if (isRefusal(o)) return o;
    return x402Chosen(PAIRING, { required: o.required, accepted: o.accepted }, ref);
  },
  choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
  request: (unsigned: unknown) => (unsigned as PolkadotUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    const extrinsic = bytesOf(signature);
    if (extrinsic === undefined || extrinsic.length === 0) return refuse("x402/signature-malformed");
    return identified((unsigned as PolkadotUnsigned).complete(extrinsic), chosen);
  },
});
