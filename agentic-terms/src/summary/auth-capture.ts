/**
 * `eip712` requests of x402's `auth-capture` scheme on the commerce-payments escrow (profile `buyer-gate.md`, rule 13):
 * the token authorization the payer signs, an EIP-3009 `ReceiveWithAuthorization` to the escrow's EIP-3009 collector or
 * a Permit2 `PermitTransferFrom` to its Permit2 collector, whose nonce is the escrow's payment hash of a `PaymentInfo`
 * with the payer the zero address. The operator, the receiver and both expiries are behind that hash, so the summary
 * shows them from the `paymentInfo` and `escrow` the request carries only once `paymentHash` over them, under the typed
 * data's chain id, is the signed nonce; a request without them, or whose nonce they do not hash to, has no summary.
 */
import { ESCROW, PERMIT2, paymentHash, type Hex, type PaymentInfo } from "@integraledger/lcp/evm";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject, sameAddress, typeIs } from "./evm-fields.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const RECEIVE_WITH_AUTHORIZATION = [
  ["from", "address"],
  ["to", "address"],
  ["value", "uint256"],
  ["validAfter", "uint256"],
  ["validBefore", "uint256"],
  ["nonce", "bytes32"],
] as const;
const PERMIT_TRANSFER_FROM = [
  ["permitted", "TokenPermissions"],
  ["spender", "address"],
  ["nonce", "uint256"],
  ["deadline", "uint256"],
] as const;
const TOKEN_PERMISSIONS = [
  ["token", "address"],
  ["amount", "uint256"],
] as const;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;

type Deployment = (typeof ESCROW)[keyof typeof ESCROW];

/** A fee in basis points, a `uint16`, as a number; else undefined. */
function bps(v: unknown): number | undefined {
  const d = decimal(v);
  return d !== undefined && BigInt(d) < 65536n ? Number(d) : undefined;
}

/**
 * The request's `paymentInfo`, as `paymentHash` takes it, with the escrow deployment `escrow` names, where the payer is
 * the zero address, as the collectors hash it; else undefined.
 */
function escrowed(request: SigningRequest): { info: PaymentInfo; deployment: Deployment } | undefined {
  const r = request as { paymentInfo?: unknown; escrow?: unknown };
  const p = r.paymentInfo;
  const escrow = address(r.escrow);
  if (!isObject(p) || escrow === undefined) return undefined;
  const deployment = Object.values(ESCROW).find((d) => sameAddress(d.escrow, escrow));
  const addresses = [p["operator"], p["payer"], p["receiver"], p["token"], p["feeReceiver"]].map(address);
  const uints = [p["maxAmount"], p["preApprovalExpiry"], p["authorizationExpiry"], p["refundExpiry"]].map(decimal);
  const [minFeeBps, maxFeeBps] = [bps(p["minFeeBps"]), bps(p["maxFeeBps"])];
  const salt = p["salt"];
  if (deployment === undefined || addresses.includes(undefined) || uints.includes(undefined)) return undefined;
  if (minFeeBps === undefined || maxFeeBps === undefined || typeof salt !== "string" || !HASH32.test(salt)) return undefined;
  const [operator, payer, receiver, token, feeReceiver] = addresses as Hex[];
  const [maxAmount, preApprovalExpiry, authorizationExpiry, refundExpiry] = (uints as string[]).map(BigInt);
  if (!sameAddress(payer!, ZERO_ADDRESS)) return undefined;
  const info: PaymentInfo = {
    operator: operator!,
    payer: payer!,
    receiver: receiver!,
    token: token!,
    maxAmount: maxAmount!,
    preApprovalExpiry: preApprovalExpiry!,
    authorizationExpiry: authorizationExpiry!,
    refundExpiry: refundExpiry!,
    minFeeBps,
    maxFeeBps,
    feeReceiver: feeReceiver!,
    salt: salt as Hex,
  };
  return { info, deployment };
}

/** Whether `nonce`, a `bytes32` as hex or a `uint256`, is `paymentHash(chain, escrow, info)`. */
function noncesTo(nonce: unknown, chain: string, deployment: Deployment, info: PaymentInfo): boolean {
  const hash = paymentHash(Number(chain), deployment.escrow, info);
  if (typeof hash !== "string") return false;
  if (typeof nonce === "string" && HASH32.test(nonce)) return BigInt(nonce) === BigInt(hash);
  const n = decimal(nonce);
  return n !== undefined && BigInt(n) === BigInt(hash);
}

/** The summary of an authorization of `value` of `info.token` on `chain`, from `notBefore` to `notAfter`. */
function shown(info: PaymentInfo, value: string, chain: string, notBefore: string | null, notAfter: string): Shown {
  return {
    maximum: value,
    payees: [{ account: info.receiver, amount: value }],
    operator: info.operator,
    authorizationExpiry: info.authorizationExpiry.toString(),
    refundExpiry: info.refundExpiry.toString(),
    asset: info.token,
    network: `eip155:${chain}`,
    validity: { notBefore, notAfter, unit: "seconds" },
  };
}

/**
 * `x402/auth-capture/eip155/eip3009`: a `ReceiveWithAuthorization` of `m.value` to the EIP-3009 collector of the
 * deployment whose escrow is `escrow`, in the domain of `paymentInfo.token`, whose `m.nonce` is
 * `paymentHash(d.chainId, escrow, paymentInfo)`. The maximum and the one payee's part are `m.value`, which the operator
 * captures for the payee up to; the payee `paymentInfo.receiver`; the operator `paymentInfo.operator`; the
 * authorization's and the refund's expiries `paymentInfo.authorizationExpiry` and `paymentInfo.refundExpiry`; the asset
 * `d.verifyingContract`; the network `eip155:` and `d.chainId`; and the validity `m.validAfter` to `m.validBefore`.
 */
export function authCaptureEip3009(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData) || r.typedData["primaryType"] !== "ReceiveWithAuthorization") return undefined;
  const { types, message: m, domain: d } = r.typedData;
  if (!isObject(types) || !isObject(m) || !isObject(d) || !typeIs(types["ReceiveWithAuthorization"], RECEIVE_WITH_AUTHORIZATION)) {
    return undefined;
  }
  const e = escrowed(request);
  const value = decimal(m["value"]);
  const after = decimal(m["validAfter"]);
  const before = decimal(m["validBefore"]);
  const chain = decimal(d["chainId"]);
  const to = address(m["to"]);
  const token = address(d["verifyingContract"]);
  if (e === undefined || value === undefined || after === undefined || before === undefined || chain === undefined) return undefined;
  if (to === undefined || !sameAddress(to, e.deployment.eip3009Collector)) return undefined;
  if (token === undefined || !sameAddress(token, e.info.token) || !noncesTo(m["nonce"], chain, e.deployment, e.info)) return undefined;
  return shown(e.info, value, chain, after, before);
}

/**
 * `x402/auth-capture/eip155/permit2`: a Permit2 `PermitTransferFrom` of `m.permitted.amount` of `paymentInfo.token`
 * whose spender is the Permit2 collector of the deployment whose escrow is `escrow`, and whose `m.nonce` is
 * `paymentHash(d.chainId, escrow, paymentInfo)`. Its members are those of the EIP-3009 form, the maximum being
 * `m.permitted.amount`, the asset `m.permitted.token`, and the validity none to `m.deadline`.
 */
export function authCapturePermit2(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData) || r.typedData["primaryType"] !== "PermitTransferFrom") return undefined;
  const { types, message: m, domain: d } = r.typedData;
  if (!isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["PermitTransferFrom"], PERMIT_TRANSFER_FROM) || !typeIs(types["TokenPermissions"], TOKEN_PERMISSIONS)) return undefined;
  const e = escrowed(request);
  const contract = address(d["verifyingContract"]);
  const spender = address(m["spender"]);
  const p = m["permitted"];
  if (e === undefined || contract === undefined || !sameAddress(contract, PERMIT2) || !isObject(p)) return undefined;
  if (spender === undefined || !sameAddress(spender, e.deployment.permit2Collector)) return undefined;
  const token = address(p["token"]);
  const amount = decimal(p["amount"]);
  const deadline = decimal(m["deadline"]);
  const chain = decimal(d["chainId"]);
  if (token === undefined || amount === undefined || deadline === undefined || chain === undefined) return undefined;
  if (!sameAddress(token, e.info.token) || !noncesTo(m["nonce"], chain, e.deployment, e.info)) return undefined;
  return shown(e.info, amount, chain, null, deadline);
}
