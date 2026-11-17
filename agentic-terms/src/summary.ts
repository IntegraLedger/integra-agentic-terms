/**
 * The approval summary (profile `buyer-gate.md`, rule 13): for each pairing whose row the profile's table fills, the
 * function that reads every authority the signature grants from the request handed to the signer, never from the
 * option or the build's inputs. A pairing with no entry here, or whose entry cannot read the request it is given, has no
 * summary, and the gate declines its request `summary-missing`: nothing is signed unshown.
 */
import type { Json } from "@integraledger/lcp/core";
import type { Inputs, Signature, SigningRequest, Summary } from "./types.js";
import { exactPermit2, mppPermit2, uptoPermit2 } from "./summary/eip712.js";
import { erc20Transfer } from "./summary/evm-call.js";
import { keyAuthorization } from "./summary/tempo-key-authorization.js";
import { algorandTransfer } from "./summary/algorand-txn.js";
import { hederaExecutor, hederaTransfer } from "./summary/hedera-body.js";
import { solanaSessionOpen, solanaTransfer, solanaUptoOpen } from "./summary/solana-message.js";
import { stacksTransfer } from "./summary/stacks-contract-call.js";
import { xrplPayment, xrplSessionOpen } from "./summary/xrpl-tx.js";
import { casperTransferWithAuthorization } from "./summary/casper-eip712.js";
import { ccdTransfer } from "./summary/ccd-transfer.js";
import { starknetTransfer } from "./summary/starknet-snip12.js";
import { substrateTransfer } from "./summary/substrate-call.js";
import { aptosTransaction, cardanoLock, cardanoTransaction, suiTransaction } from "./summary/x402-wallet.js";
import { tapField, vicReference, viCheckout, viCheckoutMandate } from "./summary/card.js";
import { stellarPrecondition, stellarStart } from "./summary/stellar-precondition.js";
import { acpAllowance, ap2CheckoutMandate, ucpCheckout, ucpLegalContext } from "./summary/checkout.js";
import { nearDelegate, nearStart } from "./summary/near-delegate.js";
import { tronTxid } from "./summary/tron-txid.js";
import { tonW5 } from "./summary/ton-w5.js";
import { spendPermission } from "./summary/spend-permission.js";

/** A summary without the ATR's bytes, which the gate adds. */
export type Shown = Omit<Summary, "atr">;

/**
 * The step that opened a payment signed in steps, such as a session's or a channel's opening before its voucher: the
 * request the signer was handed, its summary, whose payees, asset and network are the channel's, and the signer's
 * answer to it.
 */
export interface Opened {
  readonly request: SigningRequest;
  readonly summary: Shown;
  readonly signature: Signature;
}

/**
 * One pairing's summary. `show` reads the request handed to the signer, and answers undefined for a request it cannot
 * read; `network`, where the gate knows it, is the signing account's CAIP-2 network, which the summary names where the
 * request names none, a request that names a network showing that one. `opened`, for a later step of a payment signed
 * in steps, which names only the channel, is the step that opened that channel: the later step is shown with its
 * payees, asset and network, and one whose channel is not the one it opened has no summary. `start`, for a deadline
 * signed as a height where the request signs no start, reads the height the caller gave the build from its inputs.
 * `show` may answer a promise, for a request read with an asynchronous decoder; the gate awaits it.
 */
export interface SummaryEntry {
  readonly show: (request: SigningRequest, network?: string, opened?: Opened) => Shown | undefined | Promise<Shown | undefined>;
  readonly start?: (inputs: Inputs) => bigint | undefined;
}

const DECIMAL = /^[0-9]{1,78}$/;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A non-negative integer as a decimal string: a bigint, a safe integer, or a decimal string; else undefined. */
function decimal(v: unknown): string | undefined {
  if (typeof v === "bigint") return v >= 0n ? v.toString() : undefined;
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? String(v) : undefined;
  return typeof v === "string" && DECIMAL.test(v) ? v : undefined;
}

/**
 * `eip712`, `TransferWithAuthorization` (EIP-3009): the amount and the one payee's part are `m.value`, the payee
 * `m.to`, the asset `d.verifyingContract`, the network `eip155:` and `d.chainId`, and the validity `m.validAfter` to
 * `m.validBefore`, in seconds.
 */
function transferWithAuthorization(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData) || r.typedData["primaryType"] !== "TransferWithAuthorization") return undefined;
  const { message: m, domain: d } = r.typedData;
  if (!isObject(m) || !isObject(d)) return undefined;
  const value = decimal(m["value"]);
  const after = decimal(m["validAfter"]);
  const before = decimal(m["validBefore"]);
  const chain = decimal(d["chainId"]);
  const to = m["to"];
  const asset = d["verifyingContract"];
  if (value === undefined || after === undefined || before === undefined || chain === undefined) return undefined;
  if (typeof to !== "string" || typeof asset !== "string") return undefined;
  return {
    amount: value,
    payees: [{ account: to, amount: value }],
    asset,
    network: `eip155:${chain}`,
    validity: { notBefore: after, notAfter: before, unit: "seconds" },
  };
}

/**
 * `erc7710`: the amount and the one payee's part are `amount`, the payee `payTo`, the asset `token`, the network
 * `eip155:` and `chainId`; a delegation signs no end, and its grant is `{token, payTo, amount}`.
 */
function erc7710(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; chainId?: unknown; token?: unknown; payTo?: unknown; amount?: unknown };
  if (r.kind !== "erc7710") return undefined;
  const amount = decimal(r.amount);
  const chain = decimal(r.chainId);
  const { token, payTo } = r;
  if (amount === undefined || chain === undefined || typeof token !== "string" || typeof payTo !== "string") return undefined;
  const grant: Json = { token, payTo, amount };
  return {
    amount,
    payees: [{ account: payTo, amount }],
    asset: token,
    network: `eip155:${chain}`,
    validity: { notBefore: null, notAfter: null, unit: "seconds" },
    grant,
  };
}

/** Each pairing's summary, by pairing id, as the profile's table fills its row. */
export const SUMMARIES: ReadonlyMap<string, SummaryEntry> = new Map<string, SummaryEntry>([
  ["x402/exact/eip155/eip3009", { show: transferWithAuthorization }],
  ["x402/exact/eip155/erc7710", { show: erc7710 }],
  ["x402/exact/eip155/erc7710-salt", { show: erc7710 }],
  ["x402/exact/eip155/permit2", { show: exactPermit2 }],
  ["x402/upto/eip155/permit2", { show: uptoPermit2 }],
  ["mpp/charge/evm/authorization", { show: transferWithAuthorization }],
  ["mpp/charge/usdc/evm", { show: transferWithAuthorization }],
  ["mpp/charge/evm/hash", { show: erc20Transfer }],
  ["mpp/charge/evm/transaction", { show: erc20Transfer }],
  ["mpp/charge/evm/permit2", { show: mppPermit2 }],
  ["mpp/subscription/tempo", { show: keyAuthorization }],
  ["x402/exact/solana", { show: solanaTransfer }],
  ["mpp/charge/solana", { show: solanaTransfer }],
  ["mpp/charge/solana/unsponsored", { show: solanaTransfer }],
  ["mpp/charge/usdc/solana", { show: solanaTransfer }],
  ["x402/upto/solana", { show: solanaUptoOpen }],
  ["mpp/session/solana/memo", { show: solanaSessionOpen }],
  ["x402/exact/xrpl", { show: xrplPayment }],
  ["mpp/charge/xrpl", { show: xrplPayment }],
  ["mpp/session/xrpl", { show: xrplSessionOpen }],
  ["x402/exact/algorand", { show: algorandTransfer }],
  ["mpp/charge/usdc/stacks", { show: stacksTransfer }],
  ["x402/exact/hedera", { show: hederaTransfer }],
  ["mpp/charge/lcp/hedera", { show: hederaTransfer }],
  ["x402/exact/hedera/transfer-executor", { show: hederaExecutor }],
  ["x402/exact/casper", { show: casperTransferWithAuthorization }],
  ["x402/exact/starknet", { show: starknetTransfer }],
  ["x402/exact/ccd", { show: ccdTransfer }],
  ["x402/exact/polkadot/lcp-assets-remark", { show: substrateTransfer }],
  ["x402/exact/aptos", { show: aptosTransaction }],
  ["x402/exact/cardano", { show: cardanoTransaction }],
  ["x402/exact/cardano/lock", { show: cardanoLock }],
  ["x402/exact/sui", { show: suiTransaction }],
  ["x402/exact/stellar/precondition", { show: stellarPrecondition, start: stellarStart }],
  ["ap2/checkout-mandate", { show: ap2CheckoutMandate }],
  ["ap2/checkout-mandate/x402", { show: ap2CheckoutMandate }],
  ["ucp/checkout/ap2-mandate", { show: ucpCheckout }],
  ["ucp/booking/ap2-mandate", { show: ucpCheckout }],
  ["ucp/checkout/agent-signed", { show: ucpLegalContext }],
  ["acp/checkout/delegated", { show: acpAllowance }],
  ["card/visa-tap", { show: tapField }],
  ["card/mastercard-agent-pay", { show: tapField }],
  ["card/visa-vic", { show: vicReference }],
  ["card/mastercard-vi/immediate", { show: (r) => viCheckout(r) ?? viCheckoutMandate(r) }],
  ["card/mastercard-vi/autonomous", { show: viCheckoutMandate }],
  ["x402/exact/near", { show: nearDelegate, start: nearStart }],
  ["x402/exact/tron/lcp-trc20-memo", { show: tronTxid }],
  ["x402/exact/tvm", { show: tonW5 }],
  ["spend-permissions/eip155", { show: spendPermission }],
]);

/**
 * The summary of `request`, a request of `pairing` handed to the signer, with `atr`, a copy of the ATR's bytes; or
 * undefined where the pairing has no summary or its entry cannot read the request. An entry that throws, or whose
 * promise rejects, gives none.
 * `network` is the signing account's CAIP-2 network where the gate knows it, and `opened`, for a later step, the step
 * that opened its channel, each given to the entry as it is given here.
 */
export async function summaryOf(
  pairing: string,
  request: SigningRequest,
  atr: Uint8Array,
  network?: string,
  opened?: Opened,
): Promise<Summary | undefined> {
  const entry = SUMMARIES.get(pairing);
  if (entry === undefined) return undefined;
  let shown: Shown | undefined;
  try {
    shown = await entry.show(request, network, opened);
  } catch {
    return undefined;
  }
  return shown === undefined ? undefined : { ...shown, atr: atr.slice() };
}

/** The height the caller gave the build of `pairing`'s request, where its entry reads one. */
export function startOf(pairing: string, inputs: Inputs): bigint | undefined {
  try {
    return SUMMARIES.get(pairing)?.start?.(inputs);
  } catch {
    return undefined;
  }
}
