/**
 * The summary of a `ton-w5` request, the buyer's signing of `x402/exact/tvm` (profile `buyer-gate.md`, rule 13): the
 * wallet key signs `hash`, the representation hash of `signedBoc`, the W5 request less its signature. The protocol
 * package's `tvmRequest` reads that request at the network's configuration as its own decoder reads a settlement's, one
 * action sending one bounceable message that carries a TEP-74 Jetton `transfer`, or none, and gives the hash of its
 * root; the summary holds that hash equal to the request's, so what it shows is what the key signs.
 */
import { MAX_TVM_ATTACHED_ABOVE_FORWARD, tvmRequest, type TvmNetwork } from "@integraledger/lcp/tvm";
import type { Shown } from "../summary.js";
import { isRefusal } from "../pairings/common.js";
import type { SigningRequest } from "../types.js";
import { hex, networkIn } from "./encode.js";

/**
 * `ton-w5`: the amount and the one payee's part are the transfer's `amount`, the payee its destination, the asset the
 * message's destination, the payer's Jetton wallet, each address raw (the request names no Jetton master), the network
 * the signer's account's (the request names none), and the validity none to `valid_until`, in seconds. The message
 * attaches at most `MAX_TVM_ATTACHED_ABOVE_FORWARD` nanotons, the stock settler's cap, which pays the transfer's fees;
 * a forward TON amount above zero, a second asset paid to the payee, an extra currency, a state init or a custom
 * payload gives no summary.
 */
export function tonW5(request: SigningRequest, network?: string): Shown | undefined {
  const q = request as { kind?: unknown; hash?: unknown; signedBoc?: unknown };
  if (q.kind !== "ton-w5" || !(q.hash instanceof Uint8Array) || typeof q.signedBoc !== "string") return undefined;
  const net = networkIn("tvm", network);
  if (net === undefined) return undefined;
  const r = tvmRequest(q.signedBoc, net as TvmNetwork);
  if (isRefusal(r) || hex(r.hash) !== hex(q.hash)) return undefined;
  if (r.forwardTonAmount !== "0" || r.attachNanotons > MAX_TVM_ATTACHED_ABOVE_FORWARD) return undefined;
  if (r.extraCurrencies.length !== 0 || r.stateInit !== undefined || r.customPayload !== undefined) return undefined;
  return {
    amount: r.amount,
    payees: [{ account: r.payTo, amount: r.amount }],
    asset: r.jettonWallet,
    network: net,
    validity: { notBefore: null, notAfter: String(r.validUntil), unit: "seconds" },
  };
}
