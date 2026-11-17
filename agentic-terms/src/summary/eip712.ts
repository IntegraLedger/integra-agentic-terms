/**
 * `eip712` requests signing Permit2's `PermitWitnessTransferFrom` through x402's Permit2 proxies (profile
 * `buyer-gate.md`, rule 13). The summary reads only what the typed data signs: the message's members under the types the
 * request names, so a member the types do not sign is never shown.
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
  ["witness", "Witness"],
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

/**
 * A `PermitWitnessTransferFrom` to `proxy` under `witness`: the permitted token and amount, the witness's `to` and
 * `validAfter`, the deadline and the chain, or undefined where the request is of another form. The proxy pays only the
 * witness's `to`, so the spender must be that proxy for `to` to be the payee.
 */
function permitWitness(
  request: SigningRequest,
  proxy: string,
  witness: readonly (readonly [string, string])[],
): { token: string; amount: string; to: string; after: string; deadline: string; chain: string } | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "PermitWitnessTransferFrom" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["PermitWitnessTransferFrom"], PERMIT_WITNESS_TRANSFER_FROM)) return undefined;
  if (!typeIs(types["TokenPermissions"], TOKEN_PERMISSIONS) || !typeIs(types["Witness"], witness)) return undefined;
  const contract = address(d["verifyingContract"]);
  const spender = address(m["spender"]);
  if (contract === undefined || !sameAddress(contract, PERMIT2) || spender === undefined || !sameAddress(spender, proxy)) return undefined;
  const { permitted: p, witness: w } = m;
  if (!isObject(p) || !isObject(w)) return undefined;
  const token = address(p["token"]);
  const amount = decimal(p["amount"]);
  const to = address(w["to"]);
  const after = decimal(w["validAfter"]);
  const deadline = decimal(m["deadline"]);
  const chain = decimal(d["chainId"]);
  if (token === undefined || amount === undefined || to === undefined || after === undefined) return undefined;
  if (deadline === undefined || chain === undefined) return undefined;
  return { token, amount, to, after, deadline, chain };
}

/**
 * `x402/exact/eip155/permit2`: the amount and the one payee's part are `m.permitted.amount`, the payee `m.witness.to`,
 * the asset `m.permitted.token`, the network `eip155:` and `d.chainId`, and the validity `m.witness.validAfter` to
 * `m.deadline`, in seconds.
 */
export function exactPermit2(request: SigningRequest): Shown | undefined {
  const s = permitWitness(request, EXACT_PERMIT2_PROXY, EXACT_WITNESS);
  if (s === undefined) return undefined;
  return {
    amount: s.amount,
    payees: [{ account: s.to, amount: s.amount }],
    asset: s.token,
    network: `eip155:${s.chain}`,
    validity: { notBefore: s.after, notAfter: s.deadline, unit: "seconds" },
  };
}

/**
 * `x402/upto/eip155/permit2`: the maximum and the one payee's part are `m.permitted.amount`, the payee `m.witness.to`,
 * the asset `m.permitted.token`, the network `eip155:` and `d.chainId`, and the validity `m.witness.validAfter` to
 * `m.deadline`, in seconds.
 */
export function uptoPermit2(request: SigningRequest): Shown | undefined {
  const s = permitWitness(request, UPTO_PERMIT2_PROXY, UPTO_WITNESS);
  if (s === undefined) return undefined;
  return {
    maximum: s.amount,
    payees: [{ account: s.to, amount: s.amount }],
    asset: s.token,
    network: `eip155:${s.chain}`,
    validity: { notBefore: s.after, notAfter: s.deadline, unit: "seconds" },
  };
}
