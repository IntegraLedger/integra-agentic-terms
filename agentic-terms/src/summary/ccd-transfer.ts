/**
 * `ccd-transfer` requests (profile `buyer-gate.md`, rule 13): the one transfer the payer's wallet assembles and signs
 * as a sponsored Concordium transaction, whose members the request names: the receiver, the asset, the amount, the
 * memo and the expiry. The sponsor pays the transaction's energy and moves nothing, so it is not shown.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { decimal } from "./evm-fields.js";

const NETWORK = /^ccd:[0-9a-f]{32}$/;
/** An account address in Concordium's base58check form, as the request writes it. */
const ACCOUNT = /^[1-9A-HJ-NP-Za-km-z]{1,64}$/;
/** `CCD`, in any case, or a protocol-level token's id. */
const TOKEN = /^[\x21-\x7e]{1,128}$/;

/**
 * `x402/exact/ccd`: the amount and the one payee's part are `amount`, the payee `toAddress`, the asset `asset`, the
 * network `network`, and the validity none to `expiresBy`, in seconds.
 */
export function ccdTransfer(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; network?: unknown; toAddress?: unknown; asset?: unknown; amount?: unknown; expiresBy?: unknown };
  if (r.kind !== "ccd-transfer") return undefined;
  const { network, toAddress, asset } = r;
  const amount = decimal(r.amount);
  const until = typeof r.expiresBy === "number" ? decimal(r.expiresBy) : undefined;
  if (typeof network !== "string" || !NETWORK.test(network) || typeof toAddress !== "string" || !ACCOUNT.test(toAddress)) {
    return undefined;
  }
  if (typeof asset !== "string" || !TOKEN.test(asset) || amount === undefined || until === undefined) return undefined;
  return {
    amount,
    payees: [{ account: toAddress, amount }],
    asset,
    network,
    validity: { notBefore: null, notAfter: until, unit: "seconds" },
  };
}
