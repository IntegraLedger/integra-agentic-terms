/**
 * `spend-permissions/eip155` requests (profile `buyer-gate.md`, rule 13): the account approves a Spend Permission, which
 * lets its `spender` draw `token` from the account, up to `allowance` in each `period`, from `start` until `end` (lcp
 * profile `spend-permissions-eip155.md`). On the route `"signature"` the account signs the permission as EIP-712 typed
 * data in the SpendPermissionManager's domain (`eip712`); on the route `"transaction"` it calls the manager's
 * `approve(SpendPermission)` with it (`evm-call`). The summary is read from the permission either request carries, in
 * the form the protocol package's build writes; any other request has no summary.
 */
import { APPROVE_SELECTOR, SPEND_PERMISSION_DOMAIN } from "@integraledger/lcp/spend-permissions";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { address, decimal, isObject, typeIs } from "./evm-fields.js";

/** The manager's `SpendPermission` type, its members in the contract's order. */
const SPEND_PERMISSION = [
  ["account", "address"],
  ["spender", "address"],
  ["token", "address"],
  ["allowance", "uint160"],
  ["period", "uint48"],
  ["start", "uint48"],
  ["end", "uint48"],
  ["salt", "uint256"],
  ["extraData", "bytes"],
] as const;

/** What the summary shows of a permission, each integer a decimal string, and the chain it is approved on. */
interface Granted {
  readonly spender: string;
  readonly token: string;
  readonly allowance: string;
  readonly period: string;
  readonly start: string;
  readonly end: string;
  readonly chain: string;
}

/** The typed data's permission, under exactly the manager's type and domain; undefined for any other request. */
function signed(request: SigningRequest): Granted | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "eip712" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "SpendPermission" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["SpendPermission"], SPEND_PERMISSION)) return undefined;
  if (d["name"] !== SPEND_PERMISSION_DOMAIN.name || d["version"] !== SPEND_PERMISSION_DOMAIN.version) return undefined;
  if (address(d["verifyingContract"]) === undefined) return undefined;
  const spender = address(m["spender"]);
  const token = address(m["token"]);
  const [allowance, period, start, end, chain] = [m["allowance"], m["period"], m["start"], m["end"], d["chainId"]].map(decimal);
  if (spender === undefined || token === undefined || allowance === undefined || period === undefined) return undefined;
  if (start === undefined || end === undefined || chain === undefined) return undefined;
  return { spender, token, allowance, period, start, end, chain };
}

/** The `i`th 32-byte word of hex digits, and whether the first `zeros` bytes of hex digits are zero. */
const word = (data: string, i: number): string => data.slice(64 * i, 64 * i + 64);
const fits = (w: string, zeros: number): boolean => /^0*$/.test(w.slice(0, 2 * zeros));

/**
 * The permission an `approve(SpendPermission)` call carries, in the ABI's one form the protocol package writes: the
 * selector, the tuple's offset (32), its nine head words, each within its type's width, `extraData`'s offset from the
 * tuple (288), its length and its bytes padded with zeros to a word, and nothing after; undefined for any other call.
 */
function approved(request: SigningRequest): Granted | undefined {
  const r = request as { kind?: unknown; chainId?: unknown; call?: unknown };
  if (r.kind !== "evm-call" || !isObject(r.call) || Object.keys(r.call).sort().join() !== "data,to") return undefined;
  const chain = decimal(r.chainId);
  const data = r.call["data"];
  if (chain === undefined || address(r.call["to"]) === undefined || typeof data !== "string") return undefined;
  if (!data.toLowerCase().startsWith(APPROVE_SELECTOR) || !/^[0-9a-fA-F]*$/.test(data.slice(10))) return undefined;
  const body = data.slice(10);
  if (body.length % 64 !== 0 || body.length < 64 * 11) return undefined;
  const w = (i: number): string => word(body, i);
  const n = BigInt(`0x${w(10)}`);
  if (BigInt(`0x${w(0)}`) !== 32n || BigInt(`0x${w(9)}`) !== 288n || n > BigInt(body.length / 2)) return undefined;
  const padded = Math.ceil(Number(n) / 32) * 32;
  if (body.length !== 64 * 11 + 2 * padded || !fits(body.slice(64 * 11 + 2 * Number(n)), padded - Number(n))) return undefined;
  if (![1, 2, 3].every((i) => fits(w(i), 12)) || !fits(w(4), 12) || ![5, 6, 7].every((i) => fits(w(i), 26))) return undefined;
  const int = (i: number): string => BigInt(`0x${w(i)}`).toString();
  const addr = (i: number): string => `0x${w(i).slice(24)}`;
  return { spender: addr(2), token: addr(3), allowance: int(4), period: int(5), start: int(6), end: int(7), chain };
}

/**
 * `spend-permissions/eip155`: the one payee is the `spender`, with the allowance as its part; the period is `period`,
 * the limit per period `allowance` and the end `end`; the asset is `token`, the network `eip155:` and the chain id; and
 * the validity `start` to `end`, in seconds, while the spender may draw. The approval itself moves nothing, so the
 * summary shows no amount.
 */
export function spendPermission(request: SigningRequest): Shown | undefined {
  const p = signed(request) ?? approved(request);
  if (p === undefined) return undefined;
  return {
    payees: [{ account: p.spender, amount: p.allowance }],
    period: p.period,
    limitPerPeriod: p.allowance,
    end: p.end,
    asset: p.token,
    network: `eip155:${p.chain}`,
    validity: { notBefore: p.start, notAfter: p.end, unit: "seconds" },
  };
}
