/**
 * `substrate-call` requests (profile `buyer-gate.md`, rule 13): the call the payer's signer wraps in a signed extrinsic.
 * The summary reads the call only where lcp's `decodeProfileCall` reads it as the profile's call, exactly:
 * `batch_all([transfer_keep_alive(assetId, Id(dest), amount), remark_with_event(remark)])`; any other call has no
 * summary. The era and the nonce are the extrinsic's, which the signer writes: the gate hands it the longest mortal era
 * it may sign, `maxEraPeriod`, which the summary shows as the validity, counted in blocks from the era's birth.
 */
import { decodeProfileCall } from "@integraledger/lcp/polkadot";
import { hexOf, isRefusal } from "../pairings/common.js";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";

const NETWORK = /^polkadot:[0-9a-f]{32}$/;

/**
 * `x402/exact/polkadot/lcp-assets-remark`: the amount and the one payee's part are the transfer's `amount`, the payee its
 * `dest`, the 32-byte account as `0x` and lowercase hex, the asset its `assetId` in decimal, the network `network`, and
 * the validity `0` to `maxEraPeriod`, in blocks from the era's birth (the block whose hash the extrinsic signs, at or
 * before the block it is signed at); none to none where the request carries no `maxEraPeriod`.
 */
export function substrateTransfer(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; network?: unknown; call?: unknown; maxEraPeriod?: unknown };
  if (r.kind !== "substrate-call" || typeof r.network !== "string" || !NETWORK.test(r.network)) return undefined;
  if (!(r.call instanceof Uint8Array)) return undefined;
  const era = r.maxEraPeriod;
  if (era !== undefined && (typeof era !== "string" || !/^[0-9]{1,78}$/.test(era))) return undefined;
  const c = decodeProfileCall(r.call);
  if (isRefusal(c)) return undefined;
  const amount = c.amount.toString();
  return {
    amount,
    payees: [{ account: hexOf(c.dest), amount }],
    asset: String(c.assetId),
    network: r.network,
    validity: era === undefined ? { notBefore: null, notAfter: null, unit: "block" } : { notBefore: "0", notAfter: era, unit: "block" },
  };
}
