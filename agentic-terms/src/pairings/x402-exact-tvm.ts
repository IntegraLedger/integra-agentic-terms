/**
 * The buyer piece for `x402/exact/tvm`: the request is the representation hash of the W5 request whose one Jetton
 * transfer carries the ATR hash's text comment as its forward payload. The payer's wallet is the account's raw
 * address. The buyer supplies `walletId`, `seqno`, `jettonWallet` and `attachNanotons` from its RPC, and, for a wallet
 * not yet deployed, its `stateInit` as a base64 BoC; the wallet key answers its 64-byte Ed25519 signature as `0x` hex.
 */
import type { Refusal } from "@integraledger/lcp";
import type { TvmUnsigned } from "@integraledger/lcp/tvm";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature } from "../types.js";
import { bigintOf, bytesOf, choiceOf, inputsOf, isRefusal, refuse, x402Chosen } from "./common.js";
import { identified, railOption } from "./x402-account-rails.js";

const PAIRING = "x402/exact/tvm";
const RAW_ADDRESS = /^-?[0-9]{1,10}:[0-9a-fA-F]{64}$/;

export const x402ExactTvm: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const o = railOption(read, account, ["tvm"], PAIRING, (a) => RAW_ADDRESS.test(a));
    if (isRefusal(o)) return o;
    const given = inputsOf(inputs, PAIRING, {
      walletId: "uint",
      seqno: "uint",
      jettonWallet: "string",
      attachNanotons: "decimal",
      stateInit: "optional-string",
    });
    if (isRefusal(given)) return given;
    return x402Chosen(PAIRING, { required: o.required, accepted: o.accepted, wallet: o.address, now, ...given }, ref);
  },
  choice(chosen: Chosen): unknown {
    const c = choiceOf(chosen);
    const attachNanotons = bigintOf(c?.["attachNanotons"]);
    if (c === undefined || attachNanotons === undefined) return refuse("x402/choice-malformed");
    return { ...c, attachNanotons };
  },
  request: (unsigned: unknown) => (unsigned as TvmUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    const bytes = bytesOf(signature, 64);
    if (bytes === undefined) return refuse("x402/signature-malformed");
    return identified((unsigned as TvmUnsigned).complete(bytes), chosen);
  },
});
