/**
 * The `batch` request of x402's `batch-settlement` opening on EVM (profile `buyer-gate.md`, rule 13): the deposit's
 * token authorization, then the first voucher, each signing the channel only by its id, the EIP-712 digest of the
 * channel's configuration. The receiver, the authorizers and the token are behind that id, so the summary shows them
 * from the `config` the request carries only once `batchChannelId` over it, under the requests' chain id, is the
 * voucher's `channelId` and the channel the deposit commits to: its Permit2 witness's `channelId`, or, for an
 * ERC-3009 deposit, whose nonce is `keccak256(abi.encode(channelId, authSalt))`, the nonce recomputed with the
 * request's `authSalt`. A request without them, or whose ids they do not give, has no summary.
 */
import {
  BATCH_SETTLEMENT,
  ERC3009_DEPOSIT_COLLECTOR,
  PERMIT2_DEPOSIT_COLLECTOR,
  batchChannelId,
  erc3009DepositNonce,
  type ChannelConfig,
} from "@integraledger/lcp/x402-batch-settlement";
import type { Hex } from "@integraledger/lcp/evm";
import type { Shown } from "../summary.js";
import type { SigningRequest, Validity } from "../types.js";
import { permitWitness } from "./eip712.js";
import { address, decimal, isObject, sameAddress, typeIs } from "./evm-fields.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const HASH32 = /^0x[0-9a-fA-F]{64}$/;
const VOUCHER = [
  ["channelId", "bytes32"],
  ["maxClaimableAmount", "uint128"],
] as const;
const RECEIVE_WITH_AUTHORIZATION = [
  ["from", "address"],
  ["to", "address"],
  ["value", "uint256"],
  ["validAfter", "uint256"],
  ["validBefore", "uint256"],
  ["nonce", "bytes32"],
] as const;
const DEPOSIT_WITNESS = [["channelId", "bytes32"]] as const;

const hash32 = (v: unknown): string | undefined => (typeof v === "string" && HASH32.test(v) ? v : undefined);
const sameHash = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/** The request's `config`, its seven members as `batchChannelId` reads them; else undefined. */
function configOf(v: unknown): ChannelConfig | undefined {
  if (!isObject(v)) return undefined;
  const [payer, payerAuthorizer, receiver, receiverAuthorizer, token] = [
    v["payer"],
    v["payerAuthorizer"],
    v["receiver"],
    v["receiverAuthorizer"],
    v["token"],
  ].map(address);
  const delay = decimal(v["withdrawDelay"]);
  const salt = hash32(v["salt"]);
  if (!payer || !payerAuthorizer || !receiver || !receiverAuthorizer || !token || delay === undefined || !salt) return undefined;
  const withdrawDelay = Number(delay);
  if (!Number.isSafeInteger(withdrawDelay)) return undefined;
  return {
    payer: payer as Hex,
    payerAuthorizer: payerAuthorizer as Hex,
    receiver: receiver as Hex,
    receiverAuthorizer: receiverAuthorizer as Hex,
    token: token as Hex,
    withdrawDelay,
    salt: salt as Hex,
  };
}

/** The voucher, `Voucher(bytes32 channelId, uint128 maxClaimableAmount)` under the channel contract's domain. */
function voucherOf(request: unknown): { chain: string; channelId: string; max: string } | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData) || r.typedData["primaryType"] !== "Voucher") return undefined;
  const { types, message: m, domain: d } = r.typedData;
  if (!isObject(types) || !isObject(m) || !isObject(d) || !typeIs(types["Voucher"], VOUCHER)) return undefined;
  const contract = address(d["verifyingContract"]);
  if (d["name"] !== "x402 Batch Settlement" || d["version"] !== "1" || !contract || !sameAddress(contract, BATCH_SETTLEMENT)) return undefined;
  const chain = decimal(d["chainId"]);
  const channelId = hash32(m["channelId"]);
  const max = decimal(m["maxClaimableAmount"]);
  return chain === undefined || channelId === undefined || max === undefined ? undefined : { chain, channelId, max };
}

/**
 * The deposit into channel `id` of `c` on `chain`: an ERC-3009 `ReceiveWithAuthorization` from the payer to x402's
 * ERC-3009 deposit collector, in the token's domain, whose nonce is `erc3009DepositNonce(id, authSalt)`; or a Permit2
 * permit of the token to x402's Permit2 deposit collector whose `DepositWitness` names `id`. Its amount and validity.
 */
function depositOf(
  request: unknown,
  c: ChannelConfig,
  id: string,
  chain: string,
  authSalt: unknown,
): { value: string; validity: Validity } | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData)) return undefined;
  if (r.typedData["primaryType"] === "ReceiveWithAuthorization") {
    const { types, message: m, domain: d } = r.typedData;
    if (!isObject(types) || !isObject(m) || !isObject(d) || !typeIs(types["ReceiveWithAuthorization"], RECEIVE_WITH_AUTHORIZATION)) {
      return undefined;
    }
    const [from, to, token] = [address(m["from"]), address(m["to"]), address(d["verifyingContract"])];
    const salt = hash32(authSalt);
    const nonce = salt === undefined ? undefined : erc3009DepositNonce(id as Hex, salt as Hex);
    const [value, after, before] = [decimal(m["value"]), decimal(m["validAfter"]), decimal(m["validBefore"])];
    if (!from || !to || !token || typeof nonce !== "string" || typeof m["nonce"] !== "string") return undefined;
    if (!sameAddress(from, c.payer) || !sameAddress(to, ERC3009_DEPOSIT_COLLECTOR) || !sameAddress(token, c.token)) return undefined;
    if (decimal(d["chainId"]) !== chain || !sameHash(m["nonce"], nonce)) return undefined;
    if (value === undefined || after === undefined || before === undefined) return undefined;
    return { value, validity: { notBefore: after, notAfter: before, unit: "seconds" } };
  }
  const s = permitWitness(request as SigningRequest, "DepositWitness", DEPOSIT_WITNESS);
  const witnessed = s === undefined ? undefined : hash32(s.w["channelId"]);
  if (s === undefined || witnessed === undefined || !sameHash(witnessed, id) || s.chain !== chain) return undefined;
  if (!sameAddress(s.spender, PERMIT2_DEPOSIT_COLLECTOR) || !sameAddress(s.token, c.token)) return undefined;
  return { value: s.amount, validity: { notBefore: null, notAfter: s.deadline, unit: "seconds" } };
}

/**
 * `x402/batch-settlement/eip155`, the opening: the amount and the one payee's part are the voucher's
 * `maxClaimableAmount`, the payee `config.receiver`; the deposit the deposit authorization's amount; who may close
 * `config.receiver` and `config.receiverAuthorizer`, by a refund at any time, and `config.payer` and, where it is not
 * the zero address, `config.payerAuthorizer`, by a withdrawal once `config.withdrawDelay` has passed; the asset
 * `config.token`; the network `eip155:` and the requests' chain id; and the validity the deposit authorization's.
 */
export function batchEvmOpening(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; requests?: unknown; config?: unknown; authSalt?: unknown };
  if (r.kind !== "batch" || !Array.isArray(r.requests) || r.requests.length !== 2) return undefined;
  const c = configOf(r.config);
  const v = voucherOf(r.requests[1]);
  if (c === undefined || v === undefined) return undefined;
  const id = batchChannelId(Number(v.chain), c);
  if (typeof id !== "string" || !sameHash(id, v.channelId)) return undefined;
  const deposit = depositOf(r.requests[0], c, id, v.chain, r.authSalt);
  if (deposit === undefined) return undefined;
  const closers = [c.receiver, c.receiverAuthorizer, c.payer, c.payerAuthorizer].filter((a) => !sameAddress(a, ZERO_ADDRESS));
  return {
    amount: v.max,
    payees: [{ account: c.receiver, amount: v.max }],
    deposit: deposit.value,
    closableBy: closers,
    asset: c.token,
    network: `eip155:${v.chain}`,
    validity: deposit.validity,
  };
}
