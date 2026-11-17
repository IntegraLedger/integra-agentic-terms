/**
 * The summary of a `near-delegate` request, the buyer's signing of `x402/exact/near` (profile `buyer-gate.md`, rule
 * 13): the key signs `hash`, the SHA-256 of the NEP-461 prefix and `delegateAction`, the borsh of a NEP-366
 * `DelegateAction`. The protocol package's `nearRequest` reads those bytes as its own decoder reads a signed delegate
 * action, one action, a NEP-141 `ft_transfer`, or none, and gives the hash they are signed under; the summary holds that
 * hash equal to the request's, so what it shows is what the key signs.
 */
import { nearRequest } from "@integraledger/lcp/near";
import type { Shown } from "../summary.js";
import { bigintOf, isRefusal } from "../pairings/common.js";
import type { Inputs, SigningRequest } from "../types.js";
import { hex, networkIn } from "./encode.js";

/**
 * `near-delegate`: the amount and the one payee's part are the `ft_transfer` arguments' `amount`, the payee their
 * `receiver_id`, the asset the delegate action's receiver, the token contract, the network the signer's account's (the
 * request names none), and the validity none to `maxBlockHeight`, in blocks. The function call attaches 1 yoctoNEAR, as
 * NEP-141's `ft_transfer` requires; a call attaching another deposit, which would move NEAR to the contract, has no
 * summary.
 */
export async function nearDelegate(request: SigningRequest, network?: string): Promise<Shown | undefined> {
  const q = request as { kind?: unknown; hash?: unknown; delegateAction?: unknown };
  if (q.kind !== "near-delegate" || !(q.hash instanceof Uint8Array) || !(q.delegateAction instanceof Uint8Array)) return undefined;
  const net = networkIn("near", network);
  if (net === undefined) return undefined;
  const r = await nearRequest(q.delegateAction);
  if (isRefusal(r) || hex(r.hash) !== hex(q.hash) || r.deposit !== 1n) return undefined;
  return {
    amount: r.amount,
    payees: [{ account: r.payTo, amount: r.amount }],
    asset: r.asset,
    network: net,
    validity: { notBefore: null, notAfter: r.maxBlockHeight.toString(), unit: "block" },
  };
}

/**
 * The height the caller gave the build, `finalHeight`, a decimal string as the pairing's piece reads it, from which
 * `maxBlockHeight` was counted.
 */
export function nearStart(inputs: Inputs): bigint | undefined {
  return bigintOf(inputs["finalHeight"]);
}
