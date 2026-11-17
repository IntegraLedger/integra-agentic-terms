/**
 * `eip712` requests signing Permit2's `PermitWitnessTransferFrom`, through x402's Permit2 proxies and MPP's charge
 * (profile `buyer-gate.md`, rule 13). The summary reads only what the typed data signs: the message's members under the
 * types the request names, so a member the types do not sign is never shown.
 */
import { EXACT_PERMIT2_PROXY, PERMIT2, UPTO_PERMIT2_PROXY } from "@integraledger/lcp/evm";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject, sameAddress, typeIs } from "./evm-fields.js";

const PERMIT_WITNESS_TRANSFER_FROM = [
  ["permitted", "TokenPermissions"],
  ["spender", "address"],
  ["nonce", "uint256"],
  ["deadline", "uint256"],
] as const;
const TOKEN_PERMISSIONS = [
  ["token", "address"],
  ["amount", "uint256"],
] as const;
/** x402's exact proxy's witness, `Witness(address to,uint256 validAfter)`. */
const EXACT_WITNESS = [
  ["to", "address"],
  ["validAfter", "uint256"],
] as const;
/** x402's upto proxy's witness, `Witness(address to,address facilitator,uint256 validAfter)`. */
const UPTO_WITNESS = [
  ["to", "address"],
  ["facilitator", "address"],
  ["validAfter", "uint256"],
] as const;
/** MPP's charge witness, `PaymentWitness(bytes32 challengeHash,string externalId)`. */
const PAYMENT_WITNESS = [
  ["challengeHash", "bytes32"],
  ["externalId", "string"],
] as const;

/**
 * A `PermitWitnessTransferFrom` to Permit2 under the witness type `witnessType` of members `witness`: the permitted
 * token and amount, the spender, the witness, the deadline and the chain, or undefined where the request is of another
 * form.
 */
function permitWitness(
  request: SigningRequest,
  witnessType: string,
  witness: readonly (readonly [string, string])[],
): { token: string; amount: string; spender: string; w: Record<string, unknown>; deadline: string; chain: string } | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "PermitWitnessTransferFrom" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["PermitWitnessTransferFrom"], [...PERMIT_WITNESS_TRANSFER_FROM, ["witness", witnessType] as const])) return undefined;
  if (!typeIs(types["TokenPermissions"], TOKEN_PERMISSIONS) || !typeIs(types[witnessType], witness)) return undefined;
  const contract = address(d["verifyingContract"]);
  const spender = address(m["spender"]);
  if (contract === undefined || !sameAddress(contract, PERMIT2) || spender === undefined) return undefined;
  const { permitted: p, witness: w } = m;
  if (!isObject(p) || !isObject(w)) return undefined;
  const token = address(p["token"]);
  const amount = decimal(p["amount"]);
  const deadline = decimal(m["deadline"]);
  const chain = decimal(d["chainId"]);
  if (token === undefined || amount === undefined || deadline === undefined || chain === undefined) return undefined;
  return { token, amount, spender, w, deadline, chain };
}

/**
 * `x402/exact/eip155/permit2`: the amount and the one payee's part are `m.permitted.amount`, the payee `m.witness.to`,
 * the asset `m.permitted.token`, the network `eip155:` and `d.chainId`, and the validity `m.witness.validAfter` to
 * `m.deadline`, in seconds.
 */
export function exactPermit2(request: SigningRequest): Shown | undefined {
  const s = permitWitness(request, "Witness", EXACT_WITNESS);
  if (s === undefined) return undefined;
  const to = address(s.w["to"]);
  const after = decimal(s.w["validAfter"]);
  // The proxy pays only the witness's `to`, so the spender must be that proxy for `to` to be the payee.
  if (!sameAddress(s.spender, EXACT_PERMIT2_PROXY) || to === undefined || after === undefined) return undefined;
  return {
    amount: s.amount,
    payees: [{ account: to, amount: s.amount }],
    asset: s.token,
    network: `eip155:${s.chain}`,
    validity: { notBefore: after, notAfter: s.deadline, unit: "seconds" },
  };
}

/**
 * `x402/upto/eip155/permit2`: the maximum and the one payee's part are `m.permitted.amount`, the payee `m.witness.to`,
 * the operator `m.witness.facilitator`, who settles the charge, the asset `m.permitted.token`, the network `eip155:` and
 * `d.chainId`, and the validity `m.witness.validAfter` to `m.deadline`, in seconds.
 */
export function uptoPermit2(request: SigningRequest): Shown | undefined {
  const s = permitWitness(request, "Witness", UPTO_WITNESS);
  if (s === undefined) return undefined;
  const to = address(s.w["to"]);
  const facilitator = address(s.w["facilitator"]);
  const after = decimal(s.w["validAfter"]);
  // The proxy pays only the witness's `to`, so the spender must be that proxy for `to` to be the payee.
  if (!sameAddress(s.spender, UPTO_PERMIT2_PROXY) || to === undefined || facilitator === undefined || after === undefined) return undefined;
  return {
    maximum: s.amount,
    payees: [{ account: to, amount: s.amount }],
    operator: facilitator,
    asset: s.token,
    network: `eip155:${s.chain}`,
    validity: { notBefore: after, notAfter: s.deadline, unit: "seconds" },
  };
}

/**
 * `mpp/charge/evm/permit2`: the permit signs no recipient, so the payee is `m.spender`, the one account the signature
 * lets move the amount, to any account; the amount and its part are `m.permitted.amount`, the asset
 * `m.permitted.token`, the network `eip155:` and `d.chainId`, and the validity none to `m.deadline`, in seconds.
 */
export function mppPermit2(request: SigningRequest): Shown | undefined {
  const s = permitWitness(request, "PaymentWitness", PAYMENT_WITNESS);
  if (s === undefined) return undefined;
  return {
    amount: s.amount,
    payees: [{ account: s.spender, amount: s.amount }],
    asset: s.token,
    network: `eip155:${s.chain}`,
    validity: { notBefore: null, notAfter: s.deadline, unit: "seconds" },
  };
}
