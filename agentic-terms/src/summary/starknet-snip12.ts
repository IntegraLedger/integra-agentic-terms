/**
 * `starknet-snip12` requests (profile `buyer-gate.md`, rule 13): SNIP-9's `OutsideExecution` under SNIP-12's revision 1,
 * which the payer's account key signs. The summary reads only what the typed data signs, under SNIP-9's own types, and
 * only where its calls are one ERC-20 `transfer(recipient, amount)` and nothing else, the call lcp's build writes; any
 * other call, or a second one, has no summary.
 */
import { FELT_P, SELECTOR_TRANSFER } from "@integraledger/lcp/starknet";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { isObject, typeIs } from "./evm-fields.js";

const DOMAIN = [
  ["name", "shortstring"],
  ["version", "shortstring"],
  ["chainId", "shortstring"],
  ["revision", "shortstring"],
] as const;
const OUTSIDE_EXECUTION = [
  ["Caller", "ContractAddress"],
  ["Nonce", "felt"],
  ["Execute After", "u128"],
  ["Execute Before", "u128"],
  ["Calls", "Call*"],
] as const;
const CALL = [
  ["To", "ContractAddress"],
  ["Selector", "selector"],
  ["Calldata", "felt*"],
] as const;
const FELT = /^0x[0-9a-fA-F]{1,64}$/;
const DECIMAL = /^[0-9]{1,78}$/;
const U128 = 2n ** 128n;

/** A felt written as `0x` hex, below the field's prime; else undefined. */
function felt(v: unknown): bigint | undefined {
  if (typeof v !== "string" || !FELT.test(v)) return undefined;
  const n = BigInt(v);
  return n < FELT_P ? n : undefined;
}

/** A `u128` as SNIP-12 takes it, a decimal or a felt, as a decimal string; else undefined. */
function u128(v: unknown): string | undefined {
  const n = typeof v === "string" && DECIMAL.test(v) ? BigInt(v) : felt(v);
  return n !== undefined && n < U128 ? n.toString() : undefined;
}

/** A short string's felt as its ASCII text, each character printable; else undefined. */
function shortString(v: unknown): string | undefined {
  const n = felt(v);
  if (n === undefined || n === 0n) return undefined;
  let s = "";
  for (let x = n; x > 0n; x >>= 8n) {
    const c = Number(x & 0xffn);
    if (c < 0x21 || c > 0x7e) return undefined;
    s = String.fromCharCode(c) + s;
  }
  return s;
}

/**
 * `x402/exact/starknet`: the one call's `transfer`, `c` being `m.Calls[0]`: the amount and the one payee's part are its
 * `u256` amount, `c.Calldata[1]` and `[2]` as its low and high halves; the payee `c.Calldata[0]`, the asset `c.To`, the
 * network `starknet:` and `d.chainId`'s short string, and the validity `m["Execute After"]` to `m["Execute Before"]`, in
 * seconds.
 */
export function starknetTransfer(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; typedData?: unknown };
  if (r.kind !== "starknet-snip12" || !isObject(r.typedData)) return undefined;
  const { primaryType, types, message: m, domain: d } = r.typedData;
  if (primaryType !== "OutsideExecution" || !isObject(types) || !isObject(m) || !isObject(d)) return undefined;
  if (!typeIs(types["StarknetDomain"], DOMAIN) || !typeIs(types["OutsideExecution"], OUTSIDE_EXECUTION)) return undefined;
  if (!typeIs(types["Call"], CALL)) return undefined;
  const calls = m["Calls"];
  if (!Array.isArray(calls) || calls.length !== 1 || !isObject(calls[0])) return undefined;
  const c = calls[0];
  const data = c["Calldata"];
  if (felt(c["Selector"]) !== BigInt(SELECTOR_TRANSFER) || !Array.isArray(data) || data.length !== 3) return undefined;
  const [to, low, high] = data as unknown[];
  const lo = felt(low);
  const hi = felt(high);
  const asset = c["To"];
  const chain = shortString(d["chainId"]);
  const after = u128(m["Execute After"]);
  const before = u128(m["Execute Before"]);
  if (felt(to) === undefined || felt(asset) === undefined || lo === undefined || hi === undefined || lo >= U128 || hi >= U128) {
    return undefined;
  }
  if (chain === undefined || after === undefined || before === undefined) return undefined;
  const amount = (lo + (hi << 128n)).toString();
  return {
    amount,
    payees: [{ account: to as string, amount }],
    asset: asset as string,
    network: `starknet:${chain}`,
    validity: { notBefore: after, notAfter: before, unit: "seconds" },
  };
}
