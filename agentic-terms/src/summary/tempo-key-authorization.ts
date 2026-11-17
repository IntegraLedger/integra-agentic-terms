/**
 * `tempo-key-authorization` requests (profile `buyer-gate.md`, rule 13): the account's root key signs `digest`, the
 * keccak-256 of the RLP of `authorization`, which lets the key `keyId` spend under its limits and call only its allowed
 * calls until its expiry. The summary is read from `authorization` only where `digest` is that hash, recomputed with the
 * protocol package's `keyAuthorizationDigest`, and the key may spend one token and may call only that token's
 * `transferWithMemo` to named recipients, the authorization lcp's build writes; any other has no summary.
 */
import { keyAuthorizationDigest, TRANSFER_WITH_MEMO_SELECTOR, type TempoKeyAuthorization } from "@integraledger/lcp/tempo";
import type { Json } from "@integraledger/lcp/core";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject, sameAddress } from "./evm-fields.js";

/**
 * `mpp/subscription/tempo`: the one limit's `limit` is the limit per period and each payee's part, its `period` the
 * period, the payees every recipient of the allowed calls' selector rules, the asset the limit's `token`, the network
 * `eip155:` and `chainId`, and the end and the validity's end `expiry`, an expiry of 0 signing none; the grant is the
 * key and what it may do, `{keyId, limits, allowedCalls}`.
 */
export function keyAuthorization(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; authorization?: unknown; digest?: unknown };
  if (r.kind !== "tempo-key-authorization" || !isObject(r.authorization) || typeof r.digest !== "string") return undefined;
  const a = r.authorization;
  const digest = keyAuthorizationDigest(a as unknown as TempoKeyAuthorization);
  if (typeof digest !== "string" || digest.toLowerCase() !== r.digest.toLowerCase()) return undefined;
  const chain = decimal(a["chainId"]);
  const keyId = address(a["keyId"]);
  const expiry = decimal(a["expiry"]);
  const { limits, allowedCalls } = a;
  if (chain === undefined || keyId === undefined || expiry === undefined) return undefined;
  if (!Array.isArray(limits) || limits.length !== 1 || !isObject(limits[0])) return undefined;
  const token = address(limits[0]["token"]);
  const limit = decimal(limits[0]["limit"]);
  const period = decimal(limits[0]["period"]);
  if (token === undefined || limit === undefined || period === undefined) return undefined;
  if (!Array.isArray(allowedCalls) || allowedCalls.length === 0) return undefined;
  const recipients: string[] = [];
  const calls: Json[] = [];
  for (const call of allowedCalls as unknown[]) {
    if (!isObject(call) || address(call["target"]) === undefined || !sameAddress(call["target"] as string, token)) return undefined;
    const rules = call["selectorRules"];
    if (!Array.isArray(rules) || rules.length === 0) return undefined;
    const shown: Json[] = [];
    for (const rule of rules as unknown[]) {
      if (!isObject(rule) || typeof rule["selector"] !== "string") return undefined;
      if (rule["selector"].toLowerCase() !== TRANSFER_WITH_MEMO_SELECTOR) return undefined;
      const named = rule["recipients"];
      if (!Array.isArray(named) || named.length === 0) return undefined;
      const accounts = (named as unknown[]).map(address);
      if (accounts.some((x) => x === undefined)) return undefined;
      for (const x of accounts as string[]) if (!recipients.some((y) => sameAddress(x, y))) recipients.push(x);
      shown.push({ selector: rule["selector"], recipients: accounts as string[] });
    }
    calls.push({ target: call["target"] as string, selectorRules: shown });
  }
  const grant: Json = { keyId, limits: [{ token, limit, period }], allowedCalls: calls };
  const end = BigInt(expiry) === 0n ? undefined : expiry;
  return {
    payees: recipients.map((account) => ({ account, amount: limit })),
    period,
    limitPerPeriod: limit,
    ...(end === undefined ? {} : { end }),
    grant,
    asset: token,
    network: `eip155:${chain}`,
    validity: { notBefore: null, notAfter: end ?? null, unit: "seconds" },
  };
}
