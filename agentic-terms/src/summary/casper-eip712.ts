/**
 * `casper-eip712` requests (profile `buyer-gate.md`, rule 13): CEP-3009's `TransferWithAuthorization`, which the payer's
 * key signs as typed data. The summary reads only what the typed data signs, and only under CEP-3009's own types, so a
 * member the types do not sign is never shown.
 */
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { decimal, isObject, typeIs } from "./evm-fields.js";

/** CEP-3009's domain: the token's name and version, the chain's name, and the token's contract package hash. */
const DOMAIN = [
  ["name", "string"],
  ["version", "string"],
  ["chain_name", "string"],
  ["contract_package_hash", "bytes32"],
] as const;
const TRANSFER_WITH_AUTHORIZATION = [
  ["from", "address"],
  ["to", "address"],
  ["value", "uint256"],
  ["validAfter", "uint256"],
  ["validBefore", "uint256"],
  ["nonce", "bytes32"],
] as const;
/** The chain's name as the domain signs it: the network's CAIP-2 id. */
const NETWORK = /^casper:[a-z0-9-]{1,64}$/;
const PACKAGE = /^[0-9a-fA-F]{64}$/;
/** A Casper key as CEP-3009 signs an address: a tag byte, `00` an account hash or `01` a package hash, and 32 bytes. */
const ADDRESS = /^0[01][0-9a-fA-F]{64}$/;

/**
 * `x402/exact/casper`: the amount and the one payee's part are `m.value`, the payee `m.to`, the asset
 * `d.contract_package_hash`, the network `d.chain_name`, and the validity `m.validAfter` to `m.validBefore`, in seconds.
 */
export function casperTransferWithAuthorization(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "casper-eip712" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "TransferWithAuthorization" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["EIP712Domain"], DOMAIN) || !typeIs(types["TransferWithAuthorization"], TRANSFER_WITH_AUTHORIZATION)) {
    return undefined;
  }
  const network = d["chain_name"];
  const asset = d["contract_package_hash"];
  const to = m["to"];
  const value = decimal(m["value"]);
  const after = decimal(m["validAfter"]);
  const before = decimal(m["validBefore"]);
  if (typeof network !== "string" || !NETWORK.test(network) || typeof asset !== "string" || !PACKAGE.test(asset)) return undefined;
  if (typeof to !== "string" || !ADDRESS.test(to) || value === undefined || after === undefined || before === undefined) {
    return undefined;
  }
  return {
    amount: value,
    payees: [{ account: to, amount: value }],
    asset,
    network,
    validity: { notBefore: after, notAfter: before, unit: "seconds" },
  };
}
