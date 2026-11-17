/**
 * `substrate-call` requests (profile `buyer-gate.md`, rule 13): the call the payer's signer wraps in a signed extrinsic.
 * The summary reads the call only where lcp's `decodeProfileCall` reads it as the profile's call, exactly:
 * `batch_all([transfer_keep_alive(assetId, Id(dest), amount), remark_with_event(remark)])`; any other call has no
 * summary. The era and the nonce are the extrinsic's, which the signer writes, so the call signs no end.
 */
import { decodeProfileCall } from "@integraledger/lcp/polkadot";
import { hexOf, isRefusal } from "../pairings/common.js";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";

const NETWORK = /^polkadot:[0-9a-f]{32}$/;

/**
 * `x402/exact/polkadot/lcp-assets-remark`: the amount and the one payee's part are the transfer's `amount`, the payee its
 * `dest`, the 32-byte account as `0x` and lowercase hex, the asset its `assetId` in decimal, the network `network`, and
 * the validity none to none, in blocks: the call signs no era.
 */
export function substrateTransfer(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; network?: unknown; call?: unknown };
  if (r.kind !== "substrate-call" || typeof r.network !== "string" || !NETWORK.test(r.network)) return undefined;
  if (!(r.call instanceof Uint8Array)) return undefined;
  const c = decodeProfileCall(r.call);
  if (isRefusal(c)) return undefined;
  const amount = c.amount.toString();
  return {
    amount,
    payees: [{ account: hexOf(c.dest), amount }],
    asset: String(c.assetId),
    network: r.network,
    validity: { notBefore: null, notAfter: null, unit: "block" },
  };
}
