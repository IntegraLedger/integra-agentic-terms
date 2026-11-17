/**
 * The summary of a `gateway-burn-intent` request, the buyer's signing of `mpp/charge/usdc/gateway` (profile
 * `buyer-gate.md`, rules 13 and 14; lcp profile `mpp-charge.md`, rule 8). The buyer's Gateway client signs a Circle
 * Gateway burn intent whose TransferSpec salt commits to the request's `preimage`, whose `requestHash` is the keccak-256
 * of the challenge's `request` as issued. The request carries that `request` as `challengeRequest`, so the summary
 * recomputes the hash with the protocol package's `usdcRequestHash` and shows the challenge's terms only where it is
 * `preimage.requestHash`: the amount the recipient is paid, the currency, the network the recipient is paid on and the
 * cap on Gateway's fee, which the payer pays beside the amount from the same balance (draft-usdc-charge-00, *Gateway
 * Transfer Profile*: "Clients SHOULD present `amount + maxFee` as the payer's worst-case spend"). The burn intent's
 * `maxBlockHeight` is counted in the blocks of the network it spends from, the signer's account's.
 */
import { usdcRequestHash } from "@integraledger/lcp/mpp";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { isRefusal } from "../pairings/common.js";
import { decodeObject } from "../pairings/mpp.js";
import { CAIP2, isRecord, networkIn } from "./encode.js";

const DECIMAL = /^[0-9]{1,78}$/;

const isDecimal = (v: unknown): v is string => typeof v === "string" && DECIMAL.test(v);

/**
 * `gateway-burn-intent`: where `usdcRequestHash(challengeRequest)` is `preimage.requestHash`, the challenge's request
 * `r` shows the amount and the one payee's part, `r.amount`, the payee `r.recipient`, which must be the preimage's, the
 * asset `r.currency`, and, as the grant, `r.methodDetails.gateway`'s `destinationNetwork` and `maxFee`; the network is
 * the signer's account's, the EVM network the burn intent spends from, which the request does not name; and the validity
 * is none to `maxBlockHeight`, in that network's blocks. Any other request has no summary.
 */
export async function gatewayBurnIntent(request: SigningRequest, network?: string): Promise<Shown | undefined> {
  const q = request as { kind?: unknown; preimage?: unknown; maxBlockHeight?: unknown; challengeRequest?: unknown };
  if (q.kind !== "gateway-burn-intent" || !isRecord(q.preimage) || typeof q.challengeRequest !== "string") return undefined;
  const source = networkIn("eip155", network);
  const until = q.maxBlockHeight;
  if (source === undefined || !isDecimal(until)) return undefined;
  const hash = await usdcRequestHash(q.challengeRequest);
  if (isRefusal(hash) || hash !== q.preimage["requestHash"]) return undefined;
  const r = decodeObject(q.challengeRequest);
  const details = r?.["methodDetails"];
  const gateway = isRecord(details) ? details["gateway"] : undefined;
  if (r === undefined || !isRecord(gateway)) return undefined;
  const { amount, currency, recipient } = r;
  const { destinationNetwork, maxFee } = gateway;
  if (!isDecimal(amount) || typeof currency !== "string" || typeof recipient !== "string" || recipient !== q.preimage["recipient"]) {
    return undefined;
  }
  if (typeof destinationNetwork !== "string" || !CAIP2.test(destinationNetwork) || !isDecimal(maxFee)) return undefined;
  return {
    amount,
    payees: [{ account: recipient, amount }],
    asset: currency,
    network: source,
    validity: { notBefore: null, notAfter: until, unit: "block" },
    grant: { destinationNetwork, maxFee },
  };
}
