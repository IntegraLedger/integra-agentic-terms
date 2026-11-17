/**
 * The deadline of a payment whose wallet builds the transaction and picks its expiry itself (terms' profile
 * `buyer-gate.md`, rule 8): `aptos-transaction`, `cardano-transaction`, `sui-transaction` and `substrate-call`. Before
 * anything is signed, the gate hands the wallet the pairing's ceiling as the latest deadline it may sign, in the form's
 * own unit; after the wallet signs, and before the payment is returned, the gate reads the deadline the transaction
 * signs with the protocol package's own read of the payment and holds it to that latest deadline. A payment signed past
 * it, or with no deadline, is declined and discarded: the decline carries no part of it.
 */
import { isRefusal } from "./pairings/common.js";
import { ceilingOf, givenStart, paceOf, startInput } from "./checks.js";
import type { Binding, Ceilings, Chosen, Declined, Inputs, Presented, SigningRequest } from "./types.js";

/** Each wallet-built kind: the request member that carries the latest deadline, and the unit it is counted in. */
const MEMBERS: { readonly [kind: string]: { readonly member: string; readonly unit: string } } = {
  "aptos-transaction": { member: "maxExpirationTimestampSecs", unit: "seconds" },
  "cardano-transaction": { member: "maxTtl", unit: "slot" },
  "sui-transaction": { member: "maxEpoch", unit: "epoch" },
  "substrate-call": { member: "maxEraPeriod", unit: "block" },
};

/** A mortal era's period on a Substrate chain: a power of two from 4 to 65,536 blocks. */
const MIN_ERA = 4n;
const MAX_ERA = 65_536n;
const DECIMAL = /^[0-9]{1,78}$/;

function declined(code: Declined["decline"]["code"], detail: string): Declined {
  return { decline: { code, detail } };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The request's kind where it is one whose wallet picks the expiry; else undefined. */
function walletKind(request: SigningRequest | null): string | undefined {
  const kind = isObject(request) ? request["kind"] : undefined;
  return typeof kind === "string" && Object.hasOwn(MEMBERS, kind) ? kind : undefined;
}

/** The network the request names: `accepted.network` for an x402 option the wallet builds from, else `network`. */
function networkOf(request: Record<string, unknown>): string | undefined {
  const accepted = request["accepted"];
  const n = isObject(accepted) ? accepted["network"] : request["network"];
  return typeof n === "string" ? n : undefined;
}

/** The largest power of two at most `n`, or 0n for none. */
function floorPowerOfTwo(n: bigint): bigint {
  let p = 1n;
  while (p * 2n <= n) p *= 2n;
  return n >= 1n ? p : 0n;
}

/**
 * The latest deadline the wallet may sign, in the form's unit, for a ceiling of `ceiling` seconds at the gate's clock
 * `now`: Aptos's `expiration_timestamp_secs` at `now` plus the ceiling; Cardano's TTL slot and Sui's epoch counted from
 * the slot or epoch the caller gives, at the chain's pace, an epoch admitting the whole of itself; the longest mortal era
 * a Substrate signer may write, a power of two. A form whose finest deadline is longer than the ceiling (a Sui epoch
 * against less than a day) is `past-ceiling`; a start the caller does not give is `no-payable-option`.
 */
function latest(kind: string, network: string, ceiling: number, inputs: Inputs, now: number, pairing: string): string | Declined {
  const c = BigInt(Math.floor(ceiling));
  if (kind === "aptos-transaction") return (BigInt(now) + c).toString();
  const pace = paceOf(network);
  if (pace === undefined) return declined("past-ceiling", `The gate holds no pace for ${network}.`);
  const units = BigInt(Math.floor(ceiling / pace));
  if (kind === "substrate-call") {
    const era = floorPowerOfTwo(units > MAX_ERA ? MAX_ERA : units);
    if (era < MIN_ERA) return declined("past-ceiling", `The shortest era a payment through ${pairing} signs is past its ceiling of ${ceiling} s.`);
    return era.toString();
  }
  const name = startInput(network);
  const start = givenStart(network, inputs);
  if (name === undefined || start === undefined) {
    return declined("no-payable-option", `${network.split(":")[0]!}/input-missing`);
  }
  if (kind === "sui-transaction") {
    if (units < 1n) return declined("past-ceiling", `An epoch, the shortest deadline a payment through ${pairing} signs, is past its ceiling of ${ceiling} s.`);
    return (start + units - 1n).toString();
  }
  return (start + units).toString();
}

/**
 * The request handed to the wallet with the latest deadline it may sign, and `chosen` keeping it, where the request is
 * of a kind whose wallet picks the expiry: the deadline `chosen` already keeps, else the pairing's ceiling in the form's
 * unit. Where `ceilings` lifts the pairing's ceiling (`"no-end"`) the request is handed as built. Any other request is
 * returned as it is.
 */
export function withDeadline(
  binding: Binding,
  request: SigningRequest | null,
  chosen: Chosen,
  inputs: Inputs,
  ceilings: Ceilings | undefined,
  now: number,
): { request: SigningRequest | null; chosen: Chosen } | Declined {
  const kind = walletKind(request);
  if (kind === undefined) return { request, chosen };
  const r = request as unknown as Record<string, unknown>;
  const { member } = MEMBERS[kind]!;
  let deadline = chosen.deadline;
  if (deadline === undefined) {
    const pairing = String(binding.id);
    const ceiling = ceilingOf(pairing, inputs, ceilings);
    if (ceiling === "no-end") return { request, chosen };
    if (typeof ceiling !== "number") return ceiling;
    const network = networkOf(r);
    if (network === undefined) return declined("offer-unreadable", `${pairing.split("/")[0]!}/option-malformed`);
    const found = latest(kind, network, ceiling, inputs, now, pairing);
    if (typeof found !== "string") return found;
    deadline = found;
  }
  return { request: { ...r, [member]: deadline } as unknown as SigningRequest, chosen: { ...chosen, deadline } };
}

/** The `accepted` option of the payment chosen, which the protocol package's `reference` holds the payment to. */
function acceptedOf(chosen: Chosen): unknown {
  return isObject(chosen.choice) ? chosen.choice["accepted"] : undefined;
}

/**
 * The deadline the signed payment signs, in the form's unit, read with the protocol package's `reference` for the
 * pairing: Aptos's `expiresAt`, Cardano's `ttlSlot`, Sui's `untilEpoch` and a Substrate era's `period`; `"none"` where it
 * signs none (no TTL, no expiration epoch, an immortal era); undefined where it cannot be read.
 */
async function signedDeadline(binding: Binding, kind: string, signed: Presented, chosen: Chosen): Promise<bigint | "none" | undefined> {
  const reference = (binding as unknown as { reference?: (p: unknown, o: unknown) => unknown }).reference;
  if (typeof reference !== "function") return undefined;
  let ref: unknown;
  try {
    ref = await reference(signed, acceptedOf(chosen));
  } catch {
    return undefined;
  }
  if (isRefusal(ref)) return kind === "cardano-transaction" && ref.code === "cardano/ttl-missing" ? "none" : undefined;
  if (!isObject(ref)) return undefined;
  const at = (v: unknown): bigint | undefined => (typeof v === "string" && DECIMAL.test(v) ? BigInt(v) : undefined);
  switch (kind) {
    case "aptos-transaction":
      return at(ref["expiresAt"]);
    case "cardano-transaction":
      return ref["ttlSlot"] === undefined ? "none" : at(ref["ttlSlot"]);
    case "sui-transaction":
      return ref["untilEpoch"] === null ? "none" : at(ref["untilEpoch"]);
    default: {
      const era = ref["era"];
      if (era === "immortal") return "none";
      const period = isObject(era) ? era["period"] : undefined;
      return typeof period === "number" && Number.isSafeInteger(period) && period > 0 ? BigInt(period) : undefined;
    }
  }
}

/**
 * After the wallet signs and before the payment is returned: where `chosen` keeps the latest deadline the request
 * carried, the deadline the signed payment signs, read with the protocol package's `reference`, is held to it: a
 * payment that signs none is `no-end`, one past it, or one whose deadline cannot be read, `past-ceiling`. The decline
 * names no part of the payment, which the gate discards.
 */
export async function heldToDeadline(
  binding: Binding,
  request: SigningRequest | null,
  signed: Presented,
  chosen: Chosen,
): Promise<Declined | undefined> {
  const kind = walletKind(request);
  const kept: unknown = chosen.deadline;
  if (kind === undefined || kept === undefined) return undefined;
  const pairing = String(binding.id);
  if (typeof kept !== "string" || !DECIMAL.test(kept)) return declined("past-ceiling", `The latest deadline kept for ${pairing} is not a decimal.`);
  const signedAt = await signedDeadline(binding, kind, signed, chosen);
  if (signedAt === "none") return declined("no-end", `The payment through ${pairing} the wallet signed signs no end; it was discarded.`);
  if (signedAt === undefined) {
    return declined("past-ceiling", `The gate cannot read the deadline the payment through ${pairing} signs; it was discarded.`);
  }
  const { unit } = MEMBERS[kind]!;
  return signedAt > BigInt(kept)
    ? declined("past-ceiling", `The payment through ${pairing} the wallet signed ends past the latest ${unit} it may sign, ${kept}; it was discarded.`)
    : undefined;
}
