/**
 * The buyer piece for `x402/exact/tron/lcp-trc20-memo`: the request is the id of the TRC-20 transfer whose memo is the
 * ATR hash. The buyer supplies a recent block (`refBlock`, `{number, id}`) and the transaction's `feeLimit` from its
 * FullNode; the transaction's `timestamp` is the gate's clock in milliseconds. The payer's key answers its 65-byte
 * secp256k1 signature `r ‖ s ‖ v` over the id as `0x` hex.
 */
import type { Refusal } from "@integraledger/lcp";
import type { TronUnsigned } from "@integraledger/lcp/tron";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature } from "../types.js";
import { bigintOf, bytesOf, choiceOf, inputsOf, isObject, isRefusal, refuse, x402Chosen } from "./common.js";
import { identified, railOption } from "./x402-account-rails.js";

const PAIRING = "x402/exact/tron/lcp-trc20-memo";
const TRON_ADDRESS = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;

/** A block reference `{number, id}`: the number as a decimal string and the 32-byte id as `0x` hex. */
function refBlockOf(v: unknown): { number: bigint; id: `0x${string}` } | undefined {
  if (!isObject(v)) return undefined;
  const number = bigintOf(v["number"]);
  const id = v["id"];
  if (number === undefined || bytesOf(id, 32) === undefined) return undefined;
  return { number, id: id as `0x${string}` };
}

export const x402ExactTronLcpTrc20Memo: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const o = railOption(read, account, ["tron"], PAIRING, (a) => TRON_ADDRESS.test(a));
    if (isRefusal(o)) return o;
    const given = inputsOf(inputs, PAIRING, { refBlock: "object", feeLimit: "decimal" });
    if (isRefusal(given)) return given;
    if (refBlockOf(given["refBlock"]) === undefined) return refuse("x402/input-missing");
    const nowMs = (BigInt(now) * 1000n).toString();
    return x402Chosen(PAIRING, { required: o.required, accepted: o.accepted, payer: o.address, now: nowMs, ...given }, ref);
  },
  choice(chosen: Chosen): unknown {
    const c = choiceOf(chosen);
    const refBlock = refBlockOf(c?.["refBlock"]);
    const now = bigintOf(c?.["now"]);
    const feeLimit = bigintOf(c?.["feeLimit"]);
    if (c === undefined || refBlock === undefined || now === undefined || feeLimit === undefined) {
      return refuse("x402/choice-malformed");
    }
    return { ...c, refBlock, now, feeLimit };
  },
  request: (unsigned: unknown) => (unsigned as TronUnsigned).request,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    const bytes = bytesOf(signature, 65);
    if (bytes === undefined) return refuse("x402/signature-malformed");
    return identified((unsigned as TronUnsigned).complete(bytes), chosen);
  },
});
