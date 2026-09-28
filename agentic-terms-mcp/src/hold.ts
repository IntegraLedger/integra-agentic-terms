/**
 * The seal on a channel hold the server hands out. A hold's `mac` member is an HMAC-SHA-256 over its other members,
 * keyed with a key this process generates on first use, cannot export, and never logs or returns. A hold passed back is
 * used only when its `mac` verifies, so a hold with any member changed, added or removed, or a hold another process
 * sealed, is not used.
 */
import type { Json } from "@integraledger/lcp";

/** A hold as JSON: its members by name. */
export type HoldJson = { [member: string]: Json };

/** A `mac` as the tools write it: the 32-byte HMAC-SHA-256 tag as `0x` and lowercase hex. */
const MAC = /^0x[0-9a-f]{64}$/;

let key: Promise<CryptoKey> | undefined;

/** This process's key, generated once and not extractable. */
function processKey(): Promise<CryptoKey> {
  key ??= crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]) as Promise<CryptoKey>;
  return key;
}

/** The members as UTF-8 JSON with every object's keys sorted, so the order the members arrive in does not change it. */
function canonical(members: HoldJson): Uint8Array<ArrayBuffer> {
  const text = JSON.stringify(members, (_k, v: unknown) =>
    typeof v === "object" && v !== null && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
  return new TextEncoder().encode(text);
}

function hex(bytes: Uint8Array): string {
  let s = "0x";
  for (const b of bytes) s += (b < 16 ? "0" : "") + b.toString(16);
  return s;
}

function fromHex(s: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer((s.length - 2) / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

/** The hold with its `mac`: this process's HMAC-SHA-256 of every other member. */
export async function seal(hold: HoldJson): Promise<HoldJson> {
  const { mac: _, ...members } = hold;
  const tag = await crypto.subtle.sign("HMAC", await processKey(), canonical(members));
  return { ...members, mac: hex(new Uint8Array(tag)) };
}

/** The hold's members without `mac` when `mac` is this process's HMAC-SHA-256 of them, else undefined. */
export async function unseal(hold: HoldJson): Promise<HoldJson | undefined> {
  const { mac, ...members } = hold;
  if (typeof mac !== "string" || !MAC.test(mac)) return undefined;
  try {
    return (await crypto.subtle.verify("HMAC", await processKey(), fromHex(mac), canonical(members))) ? members : undefined;
  } catch {
    return undefined;
  }
}
