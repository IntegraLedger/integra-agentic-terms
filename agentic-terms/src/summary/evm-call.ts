/**
 * `evm-call` requests (profile `buyer-gate.md`, rule 13): a transaction the buyer's wallet makes on the request's chain
 * calling `call.to` with `call.data`. The summary is read from the call only where its data is an ERC-20
 * `transfer(address,uint256)` and nothing else, the call lcp's build writes; any other call has no summary.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject } from "./evm-fields.js";

/** `transfer(address,uint256)`'s selector, then the recipient's word, 12 zero bytes and 20, then the amount's word. */
const TRANSFER = /^0xa9059cbb0{24}([0-9a-fA-F]{40})([0-9a-fA-F]{64})$/;

/**
 * `mpp/charge/evm/hash` and `mpp/charge/evm/transaction`: the amount and the one payee's part are the transfer's
 * amount, the payee its recipient, as the call data writes it, the asset `call.to`, the network `eip155:` and
 * `chainId`; a transaction signs no end, so the validity is none to none.
 */
export function erc20Transfer(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; chainId?: unknown; call?: unknown };
  // A call of any other member, a value among them, moves what this summary does not read.
  if (r.kind !== "evm-call" || !isObject(r.call) || Object.keys(r.call).sort().join() !== "data,to") return undefined;
  const chain = decimal(r.chainId);
  const asset = address(r.call["to"]);
  const data = r.call["data"];
  const words = typeof data === "string" ? TRANSFER.exec(data) : null;
  if (chain === undefined || asset === undefined || words === null) return undefined;
  const amount = BigInt(`0x${words[2]!}`).toString();
  const to = `0x${words[1]!}`;
  return {
    amount,
    payees: [{ account: to, amount }],
    asset,
    network: `eip155:${chain}`,
    validity: { notBefore: null, notAfter: null, unit: "seconds" },
  };
}
