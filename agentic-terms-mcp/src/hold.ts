/**
 * The seals on what the channel tools take back. A channel hold's `mac` member, and the `mac` returned beside a channel
 * pairing's signed opening, are each an HMAC-SHA-256 keyed with a key this process generates on first use, cannot
 * export, and never logs or returns. Each is over a label naming what is sealed and the sealed members. A hold or an
 * opening passed back is used only when its `mac` verifies, so one with any member changed, added or removed, or one
 * another process sealed, is not used.
 */
import type { Json } from "@integraledger/lcp";

/** A JSON object: its members by name. */
export type HoldJson = { [member: string]: Json };

/** What a `mac` seals: a channel hold, or a signed opening with its pairing. */
type Sealed = "hold" | "opening";

/** A `mac` as the tools write it: the 32-byte HMAC-SHA-256 tag as `0x` and lowercase hex. */
const MAC = /^0x[0-9a-f]{64}$/;

let key: Promise<CryptoKey> | undefined;

/** This process's key, generated once and not extractable. */
function processKey(): Promise<CryptoKey> {
  key ??= crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]) as Promise<CryptoKey>;
  return key;
}

/**
 * The label, a line feed, and the members as JSON with every object's keys sorted, as UTF-8: the order the members
 * arrive in does not change it.
 */
function message(label: Sealed, members: HoldJson): Uint8Array<ArrayBuffer> {
  const text = JSON.stringify(members, (_k, v: unknown) =>
    typeof v === "object" && v !== null && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
  return new TextEncoder().encode(`${label}\n${text}`);
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

/** This process's HMAC-SHA-256 of the label and the members, as `0x` hex. */
export async function macOf(label: Sealed, members: HoldJson): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.sign("HMAC", await processKey(), message(label, members))));
}

/** Whether `mac` is this process's HMAC-SHA-256 of the label and the members. */
export async function verifies(label: Sealed, members: HoldJson, mac: unknown): Promise<boolean> {
  if (typeof mac !== "string" || !MAC.test(mac)) return false;
  try {
    return await crypto.subtle.verify("HMAC", await processKey(), fromHex(mac), message(label, members));
  } catch {
    return false;
  }
}

/** The hold with its `mac`: this process's HMAC-SHA-256 of every other member. */
export async function seal(hold: HoldJson): Promise<HoldJson> {
  const { mac: _, ...members } = hold;
  return { ...members, mac: await macOf("hold", members) };
}

/** The hold's members without `mac` when `mac` is this process's HMAC-SHA-256 of them, else undefined. */
export async function unseal(hold: HoldJson): Promise<HoldJson | undefined> {
  const { mac, ...members } = hold;
  return (await verifies("hold", members, mac)) ? members : undefined;
}
