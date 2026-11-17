/**
 * The requests whose transaction the payer's wallet builds itself from the option the request carries, as x402's
 * scheme for the chain has the client do (profile `buyer-gate.md`, rule 13): `aptos-transaction`,
 * `cardano-transaction` and `sui-transaction`. The request hands the wallet `accepted`, the exact option to pay, beside
 * what carries H; the summary reads `accepted` as the request holds it. The transaction's expiry is the wallet's to set:
 * the gate hands it the latest it may sign (`maxExpirationTimestampSecs`, `maxTtl`, `maxEpoch`), which the summary shows
 * as the validity's end, and a request without one signs no end.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { decimal, isObject } from "./evm-fields.js";

/** The longest account or asset text read: Sui's coin type bound, the longest of the three chains'. */
const MAX_TEXT = 4096;

const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;

/** The latest deadline a request carries in `member`: a decimal string, null where it carries none, else undefined. */
function latestIn(request: Record<string, unknown>, member: string): string | null | undefined {
  if (!Object.hasOwn(request, member)) return null;
  const v = request[member];
  return typeof v === "string" && /^[0-9]{1,78}$/.test(v) ? v : undefined;
}

/**
 * An `exact` option as a request of `kind` carries it in `accepted`, on a network `network` matches: the amount and the
 * one payee's part are `accepted.amount`, the payee `accepted.payTo`, the asset `accepted.asset`, the network
 * `accepted.network`, and the validity none to the latest deadline the request carries in `member`, in `unit`, or none
 * to none where it carries none.
 */
function walletBuilt(request: SigningRequest, kind: string, network: RegExp, unit: string, member: string): Shown | undefined {
  const r = request as { kind?: unknown; accepted?: unknown };
  if (r.kind !== kind || !isObject(r.accepted)) return undefined;
  const notAfter = latestIn(r as Record<string, unknown>, member);
  if (notAfter === undefined) return undefined;
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
    validity: { notBefore: null, notAfter, unit },
  };
}

/** `x402/exact/aptos`: `accepted`'s members; the validity none to `maxExpirationTimestampSecs`, in seconds. */
export const aptosTransaction = (request: SigningRequest): Shown | undefined =>
  walletBuilt(request, "aptos-transaction", /^aptos:[1-9][0-9]{0,2}$/, "seconds", "maxExpirationTimestampSecs");

/**
 * `x402/exact/cardano`: `accepted`'s members, on a network named in the `cardano` namespace or by its CIP-34 alias, as
 * the protocol package reads it; the validity none to `maxTtl`, in slots.
 */
export const cardanoTransaction = (request: SigningRequest): Shown | undefined =>
  walletBuilt(
    request,
    "cardano-transaction",
    /^(?:cardano:(?:mainnet|preprod|preview)|cip34:(?:1-764824073|0-1|0-2))$/,
    "slot",
    "maxTtl",
  );

/**
 * `x402/exact/cardano/lock`, a script lock (`accepted.extra.assetTransferMethod` `"script"`): the address method's
 * members, its payee `payTo`, the contract the seller defines, as the protocol package's reference names it. A Masumi
 * lock, whose `payTo` is the escrow every seller of a deployment shares, has no summary here.
 */
export function cardanoLock(request: SigningRequest): Shown | undefined {
  const accepted = (request as { accepted?: unknown }).accepted;
  const extra = isObject(accepted) ? accepted["extra"] : undefined;
  return isObject(extra) && extra["assetTransferMethod"] === "script" ? cardanoTransaction(request) : undefined;
}

/**
 * `x402/exact/sui`: `accepted`'s members, where the request asks a transaction bounded by epoch; the validity none to
 * `maxEpoch`, in epochs.
 */
export function suiTransaction(request: SigningRequest): Shown | undefined {
  if ((request as { expiration?: unknown }).expiration !== "epoch-bounded") return undefined;
  return walletBuilt(request, "sui-transaction", /^sui:(?:mainnet|testnet|devnet)$/, "epoch", "maxEpoch");
}
