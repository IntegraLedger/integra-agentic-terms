/**
 * The summary of an Algorand transaction handed to the signer, `algorand-txn`: the bytes it signs, `TX` and the
 * transaction's msgpack map (the Algorand transaction format). Only an asset transfer is summarised, and only one whose
 * every member the summary reads or that grants nothing: a member that hands over the account (`rekey`), closes out
 * its holding (`aclose`) or claws back another's (`asnd`), or one the reader does not know, gives no summary.
 */
import { stacksTxid } from "@integraledger/lcp/stacks";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { base32 } from "./encode.js";

/** A value of the transfer's flat map: an unsigned integer, a string or a byte string. */
type Value = bigint | string | Uint8Array;

/** The members of an asset transfer the summary reads, or that grant nothing beyond it. */
const MEMBERS = new Set(["aamt", "arcv", "fee", "fv", "gen", "gh", "grp", "lv", "lx", "note", "snd", "type", "xaid"]);

/**
 * One flat msgpack map of string keys to unsigned integers, strings and byte strings (the formats the msgpack
 * specification names: fixmap, map 16; fixstr, str 8, str 16; positive fixint, uint 8 to 64; bin 8, bin 16), the whole
 * input; undefined for anything else.
 */
function flatMap(b: Uint8Array): Map<string, Value> | undefined {
  let at = 0;
  const byte = () => {
    if (at >= b.length) throw RangeError();
    return b[at++]!;
  };
  const take = (n: number) => {
    if (at + n > b.length) throw RangeError();
    const out = b.subarray(at, at + n);
    at += n;
    return out;
  };
  const uint = (n: number) => {
    let v = 0n;
    for (const x of take(n)) v = (v << 8n) | BigInt(x);
    return v;
  };
  const value = (): Value => {
    const t = byte();
    if (t <= 0x7f) return BigInt(t);
    if (t >= 0xa0 && t <= 0xbf) return new TextDecoder("utf-8", { fatal: true }).decode(take(t & 0x1f));
    if (t === 0xd9 || t === 0xda) return new TextDecoder("utf-8", { fatal: true }).decode(take(Number(uint(t === 0xd9 ? 1 : 2))));
    if (t === 0xcc || t === 0xcd || t === 0xce || t === 0xcf) return uint(1 << (t - 0xcc));
    if (t === 0xc4 || t === 0xc5) return take(Number(uint(t === 0xc4 ? 1 : 2))).slice();
    throw RangeError();
  };
  try {
    const t = byte();
    const count = t >= 0x80 && t <= 0x8f ? t & 0x0f : t === 0xde ? Number(uint(2)) : -1;
    if (count < 0) return undefined;
    const out = new Map<string, Value>();
    for (let i = 0; i < count; i++) {
      const k = value();
      if (typeof k !== "string" || out.has(k)) return undefined;
      out.set(k, value());
    }
    return at === b.length ? out : undefined;
  } catch {
    return undefined;
  }
}

/** An Algorand address's text: base32 of the 32-byte key and the last 4 bytes of its SHA-512/256. */
function address(key: Value | undefined): string | undefined {
  if (!(key instanceof Uint8Array) || key.length !== 32) return undefined;
  const sum = stacksTxid(key).slice(-8);
  const check = Uint8Array.from(sum.match(/../g)!, (h) => parseInt(h, 16));
  const both = new Uint8Array(36);
  both.set(key, 0);
  both.set(check, 32);
  return base32(both);
}

/** Base64 (RFC 4648, section 4) of bytes. */
function base64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/**
 * `algorand-txn`, an asset transfer (`type` `axfer`): the amount and the one payee's part are `aamt` (absent, 0), the
 * payee `arcv`, the asset `xaid` as its decimal id, the network `algorand:` and the first 32 characters of `gh` in
 * URL-safe base64, as the protocol package names an Algorand network, and the validity `fv` to `lv`, in rounds.
 */
export function algorandTransfer(request: SigningRequest): Shown | undefined {
  const r = request as { kind?: unknown; bytes?: unknown };
  if (r.kind !== "algorand-txn" || !(r.bytes instanceof Uint8Array) || r.bytes[0] !== 0x54 || r.bytes[1] !== 0x58) return undefined;
  const m = flatMap(r.bytes.subarray(2));
  if (m === undefined || ![...m.keys()].every((k) => MEMBERS.has(k)) || m.get("type") !== "axfer") return undefined;
  const amount = m.get("aamt") ?? 0n;
  const asset = m.get("xaid");
  const fv = m.get("fv") ?? 0n;
  const lv = m.get("lv");
  const gh = m.get("gh");
  const payee = address(m.get("arcv"));
  if (typeof amount !== "bigint" || typeof asset !== "bigint" || typeof fv !== "bigint" || typeof lv !== "bigint") return undefined;
  if (!(gh instanceof Uint8Array) || gh.length !== 32 || payee === undefined) return undefined;
  const network = `algorand:${base64(gh).replace(/\+/g, "-").replace(/\//g, "_").slice(0, 32)}`;
  return {
    amount: amount.toString(),
    payees: [{ account: payee, amount: amount.toString() }],
    asset: asset.toString(),
    network,
    validity: { notBefore: fv.toString(), notAfter: lv.toString(), unit: "round" },
  };
}
