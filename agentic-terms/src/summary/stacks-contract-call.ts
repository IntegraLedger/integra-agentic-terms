/**
 * The summary of a Stacks contract call handed to the signer's wallet, `stacks-contract-call`: the SIP-010 `transfer`
 * the wallet builds and signs, as the request names it. A Stacks transaction signs no expiry, so its validity is none to
 * none, and the gate holds it to the profile's rule for a form that signs no end.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { isRecord } from "./encode.js";

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;

/**
 * `transfer(amount, sender, recipient, memo)` on the token contract `contract`, with one `SentEq` post-condition in
 * mode `deny`, so the call moves exactly `amount` of the token from the sender and nothing else: the amount and the one
 * payee's part are `args.amount`, the payee `args.recipient`, the asset `contract`, the network `stacks:` and
 * `chainId`.
 */
export function stacksTransfer(request: SigningRequest): Shown | undefined {
  const r = request as Record<string, unknown>;
  if (r["kind"] !== "stacks-contract-call" || r["functionName"] !== "transfer") return undefined;
  if (r["postCondition"] !== "SentEq" || r["postConditionMode"] !== "deny") return undefined;
  const args = r["args"];
  const chainId = r["chainId"];
  const contract = r["contract"];
  if (!isRecord(args) || !Number.isSafeInteger(chainId) || (chainId as number) < 0 || typeof contract !== "string") return undefined;
  const { amount, recipient } = args;
  if (typeof amount !== "string" || !DECIMAL.test(amount) || typeof recipient !== "string") return undefined;
  return {
    amount,
    payees: [{ account: recipient, amount }],
    asset: contract,
    network: `stacks:${chainId}`,
    validity: { notBefore: null, notAfter: null, unit: "seconds" },
  };
}
