/**
 * `bolt11-pay`, the BOLT 11 invoice the buyer's node pays (`x402/exact/lnbtc/payment-hash`, `mpp/charge/lightning`,
 * `mpp/session/lightning`), read with the protocol package's strict decoder (`decodeBolt11`, asynchronous): the amount
 * and the one payee's part are the invoice's amount, in millisatoshis; the payee is the key that signed the invoice,
 * its `n` field's where it has one and otherwise the key the signature recovers, as 66 lowercase hex digits; the asset
 * is `BTC`; the network is the signer's account's `lnbtc` network, where the invoice's currency is that network's
 * (BOLT 11's prefix: `bc` mainnet, `tb` testnet3 and testnet4, `tbs` signet, `bcrt` regtest); and the validity is the
 * invoice's creation time to that time plus its expiry, in seconds. An invoice the decoder refuses, one that names no
 * amount, which the node would pay at an amount the request does not state, and one whose currency is not the
 * account's network's give no summary. A session's deposit invoice is also its `deposit`.
 */
import { decodeBolt11 } from "@integraledger/lcp/lightning";
import { isRefusal } from "../pairings/common.js";
import { LN_CURRENCY } from "../pairings/lightning.js";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";

/** The invoice's summary, or undefined. */
async function invoiceShown(request: SigningRequest, network: string | undefined): Promise<Shown | undefined> {
  const r = request as { kind?: unknown; invoice?: unknown };
  if (r.kind !== "bolt11-pay" || typeof r.invoice !== "string" || network === undefined) return undefined;
  const b = await decodeBolt11(r.invoice);
  if (isRefusal(b) || b.amountMsat === null || !Object.hasOwn(LN_CURRENCY, network) || LN_CURRENCY[network] !== b.currency) {
    return undefined;
  }
  const amount = b.amountMsat.toString();
  return {
    amount,
    payees: [{ account: b.signer, amount }],
    asset: "BTC",
    network,
    validity: { notBefore: String(b.timestamp), notAfter: String(b.timestamp + b.expiry), unit: "seconds" },
  };
}

/** The invoice a charge's node pays. */
export const bolt11Pay = (request: SigningRequest, network?: string): Promise<Shown | undefined> => invoiceShown(request, network);

/** A Lightning session's deposit invoice: as a charge's, its amount also the session's `deposit`. */
export async function bolt11Deposit(request: SigningRequest, network?: string): Promise<Shown | undefined> {
  const shown = await invoiceShown(request, network);
  return shown === undefined ? undefined : { ...shown, deposit: shown.amount! };
}
