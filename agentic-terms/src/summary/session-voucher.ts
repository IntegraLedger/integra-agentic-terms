/**
 * MPP's payment channels on EVM networks and on Tempo (profile `buyer-gate.md`, rule 13): an EVM session's opening
 * funded by a Permit2 transfer or an EIP-3009 authorization to the escrow, and the voucher that follows a session's
 * opening. The voucher signs only
 * the channel id and a cumulative amount; the channel id is a hash over the payer, the payee, the token, the salt, the
 * authorized signer, the escrow and the chain (on the TIP-20 channel reserve also the operator and the opening
 * transaction's expiring nonce hash). So the voucher is shown with the payees, asset and network of the opening the
 * gate hands its summary, and only once the channel id recomputed from that opening, with the signer's account as the
 * payer, is the one the voucher signs; a voucher of another channel, or one shown without the opening or the account,
 * has no summary.
 */
import type { Json } from "@integraledger/lcp/core";
import type { Hex } from "@integraledger/lcp/evm";
import { evmChannelId, evmSessionAuthorizationNonce } from "@integraledger/lcp/mpp";
import { expiringNonceHash, tempoChannelId } from "@integraledger/lcp/tempo";
import type { Opened, Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { permitWitness } from "./eip712.js";
import { address, decimal, isObject, sameAddress, typeIs } from "./evm-fields.js";
import { openOf } from "./tempo-call.js";

/** The escrow's witness, `ChannelOpenWitness(address payee,bytes32 salt,address authorizedSigner)`. */
const CHANNEL_OPEN_WITNESS = [
  ["payee", "address"],
  ["salt", "bytes32"],
  ["authorizedSigner", "address"],
] as const;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;
/** A signed Tempo transaction as `0x` hex, at most the protocol package's 64 KiB. */
const SIGNED_TX = /^0x(?:[0-9a-fA-F]{2}){1,65536}$/;
const ZERO = "0x0000000000000000000000000000000000000000";

/** EIP-3009's `ReceiveWithAuthorization` members, in order. */
const RECEIVE_WITH_AUTHORIZATION = [
  ["from", "address"],
  ["to", "address"],
  ["value", "uint256"],
  ["validAfter", "uint256"],
  ["validBefore", "uint256"],
  ["nonce", "bytes32"],
] as const;

/** An EVM session's opening: the channel's payee, token, salt and authorized signer, the escrow, the deposit and its window. */
interface EvmOpening {
  readonly payee: string;
  readonly token: string;
  readonly salt: string;
  readonly authorizedSigner: string;
  readonly escrow: string;
  readonly deposit: string;
  readonly chain: string;
  readonly notBefore: string | null;
  readonly notAfter: string;
}

/**
 * An EVM session's opening, as the escrow opens the channel from it: a Permit2 `PermitWitnessTransferFrom` of the
 * deposit whose spender is the escrow and whose witness `ChannelOpenWitness` names the payee, the salt and the
 * authorized signer (`openWithPermit2`); or an EIP-3009 `ReceiveWithAuthorization` of the deposit to the escrow, `m.to`,
 * in the token's domain, whose nonce is `evmSessionAuthorizationNonce` over `m.from`, the payee, the token, the salt and
 * the authorized signer the request's `opening` names, recomputed and held equal to `m.nonce` (`openWithAuthorization`
 * recomputes it so); else undefined.
 */
function evmOpening(request: SigningRequest): EvmOpening | undefined {
  const s = permitWitness(request, "ChannelOpenWitness", CHANNEL_OPEN_WITNESS);
  if (s !== undefined) {
    const payee = address(s.w["payee"]);
    const signer = address(s.w["authorizedSigner"]);
    const salt = s.w["salt"];
    if (payee === undefined || signer === undefined || typeof salt !== "string" || !HASH32.test(salt)) return undefined;
    const { token, amount: deposit, spender: escrow, chain, deadline } = s;
    return { payee, token, salt, authorizedSigner: signer, escrow, deposit, chain, notBefore: null, notAfter: deadline };
  }
  const r = request as { kind?: unknown; typedData?: unknown; opening?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData) || !isObject(r.opening)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "ReceiveWithAuthorization" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["ReceiveWithAuthorization"], RECEIVE_WITH_AUTHORIZATION)) return undefined;
  const [from, escrow, token] = [address(m["from"]), address(m["to"]), address(d["verifyingContract"])];
  const [payee, signer, salt] = [address(r.opening["payee"]), address(r.opening["authorizedSigner"]), r.opening["salt"]];
  const [deposit, after, before, chain] = [decimal(m["value"]), decimal(m["validAfter"]), decimal(m["validBefore"]), decimal(d["chainId"])];
  if (from === undefined || escrow === undefined || token === undefined || payee === undefined || signer === undefined) return undefined;
  if (typeof salt !== "string" || !HASH32.test(salt) || deposit === undefined || after === undefined || before === undefined) return undefined;
  const nonce = evmSessionAuthorizationNonce({ from: from as Hex, payee: payee as Hex, token: token as Hex, salt: salt as Hex, authorizedSigner: signer as Hex });
  const signed = m["nonce"];
  if (typeof nonce !== "string" || typeof signed !== "string" || nonce.toLowerCase() !== signed.toLowerCase() || chain === undefined) return undefined;
  return { payee, token, salt, authorizedSigner: signer, escrow, deposit, chain, notBefore: after, notAfter: before };
}

/**
 * An EVM session's opening (`evmOpening`): the deposit moves from the payer to the escrow, and the channel's payee may
 * draw on it with vouchers, which are signed apart, so the summary names no amount. The one payee is the channel's
 * payee, with the deposit; the asset the token; the network `eip155:` and `d.chainId`; the validity the funding's, none
 * or `m.validAfter` to `m.deadline` or `m.validBefore`, in seconds. `deposit` is the deposit, and `grant`
 * `{escrow, authorizedSigner}`: the contract that holds the deposit, and the key the opening names to sign the
 * channel's vouchers.
 */
export function evmSessionOpen(request: SigningRequest): Shown | undefined {
  const o = evmOpening(request);
  if (o === undefined) return undefined;
  const grant: Json = { escrow: o.escrow, authorizedSigner: o.authorizedSigner };
  return {
    payees: [{ account: o.payee, amount: o.deposit }],
    asset: o.token,
    network: `eip155:${o.chain}`,
    validity: { notBefore: o.notBefore, notAfter: o.notAfter, unit: "seconds" },
    deposit: o.deposit,
    grant,
  };
}

/** The channel an opening opens for `payer`: its voucher domain's name and amount type, the escrow, the chain and the id. */
interface Channel {
  readonly name: "EVM Payment Channel" | "Tempo Stream Channel" | "TIP20 Channel Reserve";
  readonly width: "uint128" | "uint96";
  readonly escrow: string;
  readonly chainId: number;
  readonly id: string;
}

/** `0x` hex as bytes. */
function bytesOf(h: string): Uint8Array {
  const out = new Uint8Array((h.length - 2) / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

/**
 * The channel the opening `opened` opens for `payer`, recomputed with the protocol package's channel ids: a Tempo
 * `open` on the earlier escrow, or an EVM session's opening of either funding, by `evmChannelId`; a Tempo `open` on the
 * TIP-20 channel reserve by `tempoChannelId`, over the expiring nonce hash of the signed transaction the signer
 * answered, under `payer`. Undefined for any other opening.
 */
function channelOf(opened: Opened, payer: Hex): Channel | undefined {
  const r = opened.request as { kind?: unknown; chainId?: unknown; call?: unknown };
  if (r.kind === "tempo-call") {
    const chain = decimal(r.chainId);
    const call = isObject(r.call) ? r.call : undefined;
    const escrow = address(call?.["to"]);
    const data = call?.["data"];
    const open = typeof data === "string" ? openOf(data) : undefined;
    if (chain === undefined || !Number.isSafeInteger(Number(chain)) || escrow === undefined || open === undefined) return undefined;
    const chainId = Number(chain);
    const common = { payer, payee: open.payee as Hex, token: open.token as Hex, salt: open.salt as Hex, authorizedSigner: open.authorizedSigner as Hex };
    if (open.version === "v1") {
      const id = evmChannelId({ ...common, escrow: escrow as Hex, chainId });
      return typeof id === "string" ? { name: "Tempo Stream Channel", width: "uint128", escrow, chainId, id } : undefined;
    }
    const signed = opened.signature;
    if (typeof signed !== "string" || !SIGNED_TX.test(signed)) return undefined;
    const nonceHash = expiringNonceHash(bytesOf(signed), payer);
    if (typeof nonceHash !== "string") return undefined;
    const descriptor = { ...common, operator: (open.operator ?? ZERO) as Hex, expiringNonceHash: nonceHash };
    const id = tempoChannelId({ ...descriptor, escrow: escrow as Hex, chainId });
    return typeof id === "string" ? { name: "TIP20 Channel Reserve", width: "uint96", escrow, chainId, id } : undefined;
  }
  const o = evmOpening(opened.request);
  if (o === undefined || !Number.isSafeInteger(Number(o.chain))) return undefined;
  const chainId = Number(o.chain);
  const c = { payer, payee: o.payee as Hex, token: o.token as Hex, salt: o.salt as Hex, authorizedSigner: o.authorizedSigner as Hex };
  const id = evmChannelId({ ...c, escrow: o.escrow as Hex, chainId });
  return typeof id === "string" ? { name: "EVM Payment Channel", width: "uint128", escrow: o.escrow, chainId, id } : undefined;
}

/** The address of an `eip155` CAIP-10 account; else undefined. */
function payerOf(account: string | undefined): Hex | undefined {
  const parts = account?.split(":");
  return parts?.length === 3 && parts[0] === "eip155" && address(parts[2]) !== undefined ? (parts[2] as Hex) : undefined;
}

/**
 * The voucher after a session's opening: `Voucher(bytes32 channelId, uint128 cumulativeAmount)` (`uint96` on the TIP-20
 * channel reserve) under the domain `{name, version "1", chainId, verifyingContract}` of the opened channel's escrow,
 * whose `m.channelId` is the channel `opened` opens for the signer's account. The amount and the one payee's part are
 * `m.cumulativeAmount`, what the payee may claim from the channel in all; the payee, the asset, the network and the
 * validity are the opening's, as its summary shows them: the voucher signs none of them, and pays only from the deposit
 * that opening moves; the operator is the opening's, where it shows one.
 */
export function sessionVoucher(request: SigningRequest, _network?: string, opened?: Opened, account?: string): Shown | undefined {
  const payer = payerOf(account);
  const r = request as { kind?: unknown; typedData?: unknown };
  if (opened === undefined || payer === undefined || r.kind !== "eip712" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "Voucher" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  const c = channelOf(opened, payer);
  if (c === undefined || !typeIs(types["Voucher"], [["channelId", "bytes32"], ["cumulativeAmount", c.width]])) return undefined;
  const contract = address(d["verifyingContract"]);
  if (d["name"] !== c.name || d["version"] !== "1" || decimal(d["chainId"]) !== String(c.chainId)) return undefined;
  if (contract === undefined || !sameAddress(contract, c.escrow)) return undefined;
  const id = m["channelId"];
  const amount = decimal(m["cumulativeAmount"]);
  if (typeof id !== "string" || !HASH32.test(id) || id.toLowerCase() !== c.id.toLowerCase()) return undefined;
  if (amount === undefined || BigInt(amount) >= 1n << (c.width === "uint96" ? 96n : 128n)) return undefined;
  const facts = opened.summary;
  const payee = facts.payees.length === 1 ? facts.payees[0]!.account : undefined;
  if (payee === undefined) return undefined;
  return {
    amount,
    payees: [{ account: payee, amount }],
    asset: facts.asset,
    network: facts.network,
    validity: { ...facts.validity },
    ...(facts.operator === undefined ? {} : { operator: facts.operator }),
  };
}
