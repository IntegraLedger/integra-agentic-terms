/**
 * The requests whose transaction the payer's wallet builds itself from the option the request carries, as x402's
 * scheme for the chain has the client do (profile `buyer-gate.md`, rule 13): `aptos-transaction`,
 * `cardano-transaction` and `sui-transaction`. The request hands the wallet `accepted`, the exact option to pay, beside
 * what carries H; the summary reads `accepted` as the request holds it. The transaction's expiry is the wallet's to set:
 * the gate hands it the latest it may sign (`maxExpirationTimestampSecs`, `maxTtl`, `maxEpoch`), which the summary shows
 * as the validity's end, and a request without one signs no end.
 */
import type { Json } from "@integraledger/lcp/core";
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
 * The admins of the canonical Masumi V2 deployment, where the option names no `extra.deployment` (x402's
 * `scheme_exact_cardano.md`, *Deployment and escrow address*): two of these three key hashes settle a disputed escrow.
 * Preview has no canonical deployment.
 */
const MASUMI_ADMINS = {
  requiredAdmins: "2",
  adminVkeys: [
    "fc16a1fcf309aed03ec18bb2176f5ea29acea70bb79145ebaffa8e75",
    "7f78161369549d8e2b138fee724c9fa606d6107a66720bdb4c48ada6",
    "89eef9ea84e0ee7fe4921fa93eb2873ff6e34473f751d5d52cb75aa6",
  ],
} as const;
const PREVIEW = new Set(["cardano:preview", "cip34:0-2"]);
/** A positive canonical decimal, as the scheme writes a time in POSIX milliseconds and `requiredAdmins`. */
const POSITIVE = /^[1-9][0-9]{0,19}$/;
const KEY_HASH = /^[0-9a-f]{56}$/;

/** A POSIX-millisecond time as Unix seconds, rounded down, as a decimal string; else undefined. */
const secondsOf = (v: unknown): string | undefined => (typeof v === "string" && POSITIVE.test(v) ? (BigInt(v) / 1000n).toString() : undefined);

/**
 * The admins who may settle a disputed Masumi escrow: the option's `extra.deployment`, or the canonical deployment's
 * where it names none and the network has one. Each distinct key hash with its weight, the times it appears, as the
 * contract counts it, and the weight required, as decimal strings; undefined for a deployment of another form.
 */
function masumiAdmins(extra: Record<string, unknown>, network: string): Json | undefined {
  const declared = extra["deployment"];
  if (declared === undefined && PREVIEW.has(network)) return undefined;
  const d = declared === undefined ? MASUMI_ADMINS : declared;
  if (!isObject(d)) return undefined;
  const keys: unknown = d["adminVkeys"];
  const required = typeof d["requiredAdmins"] === "string" && POSITIVE.test(d["requiredAdmins"]) ? d["requiredAdmins"] : undefined;
  if (!Array.isArray(keys) || keys.length === 0 || !keys.every((k) => typeof k === "string" && KEY_HASH.test(k))) return undefined;
  if (required === undefined || BigInt(required) > BigInt(keys.length)) return undefined;
  const weights = new Map<string, number>();
  for (const k of keys as string[]) weights.set(k, (weights.get(k) ?? 0) + 1);
  return { required, weights: [...weights].map(([key, weight]) => ({ key, weight: String(weight) })) };
}

/**
 * `x402/exact/cardano/lock`, as the protocol package's reference names the payee: on a script lock
 * (`accepted.extra.assetTransferMethod` `"script"`) the address method's members, its payee `payTo`, the contract the
 * seller defines; on a Masumi lock (`"masumi"`) the same members but the payee, the seller `accepted.extra.terms`
 * names in `sellerAddress`, with the amount, and the grant: every party that can move the locked funds, and when, as
 * the `vested_pay` escrow gates each (`masumi-payment-service` `d74b2c31`, the blueprint x402's
 * `scheme_exact_cardano.md` names, `vested_pay.ak`): `escrow`, `payTo`, which holds the deposit; `seller`, its
 * `account` and, where the terms name one, its `returnAddress`, which may withdraw `after` `unlockTime` (`Withdraw`);
 * `buyer`, whose refund may be withdrawn `refundAfter` `submitResultTime` (`WithdrawRefund`); and `admins`, who may
 * settle a disputed escrow `after` `externalDisputeUnlockTime` (`WithdrawDisputed`), with their weights and the weight
 * `required`. Each time is in Unix seconds, rounded down.
 */
export function cardanoLock(request: SigningRequest): Shown | undefined {
  const accepted = (request as { accepted?: unknown }).accepted;
  const extra = isObject(accepted) ? accepted["extra"] : undefined;
  if (!isObject(extra)) return undefined;
  if (extra["assetTransferMethod"] === "script") return cardanoTransaction(request);
  if (extra["assetTransferMethod"] !== "masumi") return undefined;
  const terms = extra["terms"];
  const shown = cardanoTransaction(request);
  if (shown === undefined || !isObject(terms)) return undefined;
  const seller = terms["sellerAddress"];
  const returnAddress = terms["sellerReturnAddress"];
  const [unlock, refund, dispute] = [terms["unlockTime"], terms["submitResultTime"], terms["externalDisputeUnlockTime"]].map(secondsOf);
  const admins = masumiAdmins(extra, shown.network!);
  if (!text(seller) || (returnAddress !== undefined && !text(returnAddress))) return undefined;
  if (unlock === undefined || refund === undefined || dispute === undefined || admins === undefined) return undefined;
  const grant: Json = {
    escrow: shown.payees[0]!.account,
    seller: { account: seller, ...(returnAddress === undefined ? {} : { returnAddress }), after: unlock },
    buyer: { refundAfter: refund },
    admins: { ...(admins as Record<string, Json>), after: dispute },
  };
  return { ...shown, payees: [{ account: seller, amount: shown.payees[0]!.amount }], grant };
}

/**
 * `x402/exact/sui`: `accepted`'s members, where the request asks a transaction bounded by epoch; the validity none to
 * `maxEpoch`, in epochs.
 */
export function suiTransaction(request: SigningRequest): Shown | undefined {
  if ((request as { expiration?: unknown }).expiration !== "epoch-bounded") return undefined;
  return walletBuilt(request, "sui-transaction", /^sui:(?:mainnet|testnet|devnet)$/, "epoch", "maxEpoch");
}
