/**
 * The requests whose transaction the payer's wallet builds itself from the option the request carries, as x402's
 * scheme for the chain has the client do (profile `buyer-gate.md`, rule 13): `aptos-transaction`,
 * `cardano-transaction` and `sui-transaction`. The request hands the wallet `accepted`, the exact option to pay, beside
 * what carries H; the summary reads `accepted` as the request holds it. The transaction's expiry is the wallet's to set
 * and the request names none, so the request signs no end.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { decimal, isObject } from "./evm-fields.js";

/** The longest account or asset text read: Sui's coin type bound, the longest of the three chains'. */
const MAX_TEXT = 4096;

const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;

/**
 * An `exact` option as a request of `kind` carries it in `accepted`, on a network `network` matches: the amount and the
 * one payee's part are `accepted.amount`, the payee `accepted.payTo`, the asset `accepted.asset`, the network
 * `accepted.network`, and the validity none to none in `unit`.
 */
function walletBuilt(request: SigningRequest, kind: string, network: RegExp, unit: string): Shown | undefined {
  const r = request as { kind?: unknown; accepted?: unknown };
  if (r.kind !== kind || !isObject(r.accepted)) return undefined;
  const a = r.accepted;
  const amount = decimal(a["amount"]);
  const { network: n, payTo, asset } = a;
  if (a["scheme"] !== "exact" || amount === undefined || typeof n !== "string" || !network.test(n)) return undefined;
  if (!text(payTo) || !text(asset)) return undefined;
  return {
    amount,
    payees: [{ account: payTo, amount }],
    asset,
    network: n,
    validity: { notBefore: null, notAfter: null, unit },
  };
}

/** `x402/exact/aptos`: `accepted`'s members; the validity none to none, in seconds. */
export const aptosTransaction = (request: SigningRequest): Shown | undefined =>
  walletBuilt(request, "aptos-transaction", /^aptos:[1-9][0-9]{0,2}$/, "seconds");

/** `x402/exact/cardano`: `accepted`'s members; the validity none to none, in slots. */
export const cardanoTransaction = (request: SigningRequest): Shown | undefined =>
  walletBuilt(request, "cardano-transaction", /^cardano:(?:mainnet|preprod|preview)$/, "slot");

/**
 * `x402/exact/sui`: `accepted`'s members, where the request asks a transaction bounded by epoch; the validity none to
 * none, in epochs: the request names no epoch.
 */
export function suiTransaction(request: SigningRequest): Shown | undefined {
  if ((request as { expiration?: unknown }).expiration !== "epoch-bounded") return undefined;
  return walletBuilt(request, "sui-transaction", /^sui:(?:mainnet|testnet|devnet)$/, "epoch");
}
