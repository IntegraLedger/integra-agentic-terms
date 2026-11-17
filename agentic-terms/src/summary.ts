/**
 * The approval summary (profile `buyer-gate.md`, rule 13): for each pairing whose row the profile's table fills, the
 * function that reads every authority the signature grants from the request handed to the signer, never from the
 * option or the build's inputs. A pairing with no entry here, or whose entry cannot read the request it is given, has no
 * summary, and the gate declines its request `summary-missing`: nothing is signed unshown.
 */
import type { Json } from "@integraledger/lcp/core";
import type { Inputs, SigningRequest, Summary } from "./types.js";
import { exactPermit2, uptoPermit2 } from "./summary/eip712.js";
import { erc20Transfer } from "./summary/evm-call.js";
import { keyAuthorization } from "./summary/tempo-key-authorization.js";

/** A summary without the ATR's bytes, which the gate adds. */
export type Shown = Omit<Summary, "atr">;

/**
 * One pairing's summary. `show` reads the request handed to the signer, and answers undefined for a request it cannot
 * read. `start`, for a deadline signed as a height where the request signs no start, reads the height the caller gave
 * the build from its inputs.
 */
export interface SummaryEntry {
  readonly show: (request: SigningRequest) => Shown | undefined;
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
  ["mpp/subscription/tempo", { show: keyAuthorization }],
]);

/**
 * The summary of `request`, a request of `pairing` handed to the signer, with `atr`, a copy of the ATR's bytes; or
 * undefined where the pairing has no summary or its entry cannot read the request. An entry that throws gives none.
 */
export function summaryOf(pairing: string, request: SigningRequest, atr: Uint8Array): Summary | undefined {
  const entry = SUMMARIES.get(pairing);
  if (entry === undefined) return undefined;
  let shown: Shown | undefined;
  try {
    shown = entry.show(request);
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
