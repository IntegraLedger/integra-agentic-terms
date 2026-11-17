/**
 * The summary of a `tron-txid` request, the buyer's signing of `x402/exact/tron/lcp-trc20-memo` (profile
 * `buyer-gate.md`, rule 13): the key signs `txid`, the SHA-256 of `rawBytes`, the transaction's `raw_data`. The protocol
 * package's `tronRequest` reads those bytes as its own decoder reads a signed transaction's, one `TriggerSmartContract`
 * with no call value calling `transfer(address,uint256)`, or none, and gives the id they hash to; the summary holds that
 * id equal to the request's, so what it shows is what the key signs.
 */
import { tronRequest } from "@integraledger/lcp/tron";
import type { Shown } from "../summary.js";
import { isRefusal } from "../pairings/common.js";
import type { SigningRequest } from "../types.js";
import { hex, networkIn } from "./encode.js";

/**
 * `tron-txid`: the amount and the one payee's part are the transfer's value, the payee its recipient and the asset the
 * contract, each address in base58check, the network the signer's account's (the request names none), and the
 * validity none to `expiration`, in seconds, its milliseconds rounded up.
 */
export async function tronTxid(request: SigningRequest, network?: string): Promise<Shown | undefined> {
  const q = request as { kind?: unknown; txid?: unknown; rawBytes?: unknown };
  if (q.kind !== "tron-txid" || !(q.txid instanceof Uint8Array) || !(q.rawBytes instanceof Uint8Array)) return undefined;
  const net = networkIn("tron", network);
  if (net === undefined) return undefined;
  const r = await tronRequest(q.rawBytes);
  if (isRefusal(r) || hex(r.txid) !== hex(q.txid)) return undefined;
  return {
    amount: r.amount,
    payees: [{ account: r.payTo, amount: r.amount }],
    asset: r.asset,
    network: net,
    validity: { notBefore: null, notAfter: ((r.raw.expiration + 999n) / 1000n).toString(), unit: "seconds" },
  };
}
