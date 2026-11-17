/**
 * What the summaries of the Solana, XRP Ledger, Algorand, Stacks, Stellar and Hedera requests share: the text forms
 * their chains write an account in, and the reading of an unsigned integer.
 */

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Bytes in base58, the Bitcoin alphabet, each leading zero byte a leading `1`: a Solana address's text. */
export function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58[Number(n % 58n)]! + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

/** Bytes in base32 (RFC 4648, section 6) without padding: an Algorand address's text, of the key and its checksum. */
export function base32(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(acc >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  return bits > 0 ? out + BASE32[(acc << (5 - bits)) & 31]! : out;
}

/** Bytes as lowercase hex, without `0x`. */
export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** An unsigned little-endian integer of `length` bytes at `at`. */
export function uintLe(b: Uint8Array, at: number, length: number): bigint {
  let v = 0n;
  for (let i = length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[at + i]!);
  return v;
}

/** A plain object, not an array. */
export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A CAIP-2 network id, as the summary's `network` names one. */
export const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

/** `network` where it is a CAIP-2 id in `namespace`, else undefined. */
export function networkIn(namespace: string, network: unknown): string | undefined {
  return typeof network === "string" && CAIP2.test(network) && network.startsWith(`${namespace}:`) ? network : undefined;
}
