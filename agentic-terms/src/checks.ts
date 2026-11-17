/**
 * The checks of terms' profile `buyer-gate.md` that the gate makes on what it fetched and built: the parse of the ATR's
 * bytes (rule 5), the option chosen against the binding slot (rule 6), the buyer's request against the slot's request
 * commitment (rule 7), the ceiling and the served floor (rules 8 and 9), and the approval of each signing (rule 11).
 */
import { MAX_JSON_DEPTH } from "@integraledger/lcp";
import { canonicalJson } from "@integraledger/lcp/core";
import { issuedDigest as mppIssuedDigest, type MppChallenge } from "@integraledger/lcp/mpp";
import { requestCommitment, toolCallCommitment, type HttpRequest, type ToolCall } from "@integraledger/lcp/x402";
import { isRefusal } from "./pairings/common.js";
import { startOf, summaryOf, type Opened } from "./summary.js";
import type {
  Approver,
  Binding,
  Ceilings,
  Chosen,
  DeclineCode,
  Declined,
  Inputs,
  ResourceRequest,
  SigningRequest,
  SigningStep,
  Summary,
  ToSign,
  Validity,
} from "./types.js";

function declined(code: DeclineCode, detail: string): Declined {
  return { decline: { code, detail } };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ── The parse (rule 5).

const TRUE = [0x74, 0x72, 0x75, 0x65] as const;
const FALSE = [0x66, 0x61, 0x6c, 0x73, 0x65] as const;
const NULL = [0x6e, 0x75, 0x6c, 0x6c] as const;

function isHexByte(c: number | undefined): boolean {
  return c !== undefined && ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66));
}

/** For each UTF-8 lead byte: the continuation bytes it needs, and the range its second byte must fall in. */
const UTF8_LEAD: { readonly [lead: number]: readonly [need: number, lo: number, hi: number] } = (() => {
  const t: { [lead: number]: readonly [number, number, number] } = {};
  for (let c = 0xc2; c <= 0xdf; c++) t[c] = [1, 0x80, 0xbf];
  t[0xe0] = [2, 0xa0, 0xbf];
  for (let c = 0xe1; c <= 0xec; c++) t[c] = [2, 0x80, 0xbf];
  t[0xed] = [2, 0x80, 0x9f];
  t[0xee] = [2, 0x80, 0xbf];
  t[0xef] = [2, 0x80, 0xbf];
  t[0xf0] = [3, 0x90, 0xbf];
  for (let c = 0xf1; c <= 0xf3; c++) t[c] = [3, 0x80, 0xbf];
  t[0xf4] = [3, 0x80, 0x8f];
  return t;
})();

/** Whether `b` is well-formed UTF-8 (Unicode's Table 3-7): no overlong form, no surrogate, nothing above U+10FFFF. */
function isUtf8(b: Uint8Array): boolean {
  let i = 0;
  while (i < b.length) {
    const c = b[i]!;
    if (c < 0x80) {
      i++;
      continue;
    }
    const form = UTF8_LEAD[c];
    if (form === undefined) return false;
    const [need, lo, hi] = form;
    const second = b[i + 1];
    if (second === undefined || second < lo || second > hi) return false;
    for (let k = 2; k <= need; k++) {
      const t = b[i + k];
      if (t === undefined || t < 0x80 || t > 0xbf) return false;
    }
    i += need + 1;
  }
  return true;
}

/**
 * Whether `b` is what the protocol package's `assemble` takes as a party's bytes (its check 8): well-formed UTF-8 with no
 * leading byte-order mark, holding exactly one RFC 8259 JSON value with optional surrounding whitespace, nested at most
 * `MAX_JSON_DEPTH` levels, in which no object repeats a member name (names compared after their escapes are decoded), no
 * number overflows a double, and no integer (a number with neither fraction nor exponent) lies beyond 2^53 - 1 either
 * way. The text is scanned on its bytes, never built.
 */
export function isOneJsonText(b: Uint8Array): boolean {
  const n = b.length;
  if (n >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return false;
  if (!isUtf8(b)) return false;

  const stack: number[] = [];
  const names: Set<string>[] = [];
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let i = 0;

  const ws = (): void => {
    while (i < n) {
      const c = b[i]!;
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const string = (): boolean => {
    if (b[i] !== 0x22) return false;
    i++;
    while (i < n) {
      const c = b[i]!;
      if (c === 0x22) {
        i++;
        return true;
      }
      if (c < 0x20) return false;
      if (c === 0x5c) {
        const e = b[i + 1];
        if (e === 0x75) {
          for (let k = 2; k < 6; k++) if (!isHexByte(b[i + k])) return false;
          i += 6;
        } else if (e === 0x22 || e === 0x5c || e === 0x2f || e === 0x62 || e === 0x66 || e === 0x6e || e === 0x72 || e === 0x74) {
          i += 2;
        } else {
          return false;
        }
      } else {
        i++;
      }
    }
    return false;
  };
  const digits = (): boolean => {
    const start = i;
    while (i < n && b[i]! >= 0x30 && b[i]! <= 0x39) i++;
    return i > start;
  };
  const number = (): boolean => {
    const start = i;
    let integer = true;
    if (b[i] === 0x2d) i++;
    if (b[i] === 0x30) i++;
    else if (b[i] !== undefined && b[i]! >= 0x31 && b[i]! <= 0x39) digits();
    else return false;
    if (b[i] === 0x2e) {
      i++;
      integer = false;
      if (!digits()) return false;
    }
    if (b[i] === 0x65 || b[i] === 0x45) {
      i++;
      integer = false;
      if (b[i] === 0x2b || b[i] === 0x2d) i++;
      if (!digits()) return false;
    }
    const value = Number(utf8.decode(b.subarray(start, i)));
    return integer ? Number.isSafeInteger(value) : Number.isFinite(value);
  };
  const literal = (word: readonly number[]): boolean => {
    for (let k = 0; k < word.length; k++) if (b[i + k] !== word[k]) return false;
    i += word.length;
    return true;
  };
  const member = (): boolean => {
    const start = i;
    if (!string()) return false;
    const name = JSON.parse(utf8.decode(b.subarray(start, i))) as string;
    const seen = names[names.length - 1]!;
    if (seen.has(name)) return false;
    seen.add(name);
    ws();
    if (b[i] !== 0x3a) return false;
    i++;
    ws();
    return true;
  };

  ws();
  for (;;) {
    // A value starts at i.
    const c = b[i];
    if (c === 0x7b || c === 0x5b) {
      if (stack.length >= MAX_JSON_DEPTH) return false;
      stack.push(c);
      if (c === 0x7b) names.push(new Set());
      i++;
      ws();
      const close = c === 0x7b ? 0x7d : 0x5d;
      if (b[i] === close) {
        i++;
        if (stack.pop() === 0x7b) names.pop();
      } else {
        if (c === 0x7b && !member()) return false;
        continue;
      }
    } else if (c === 0x22) {
      if (!string()) return false;
    } else if (c === 0x2d || (c !== undefined && c >= 0x30 && c <= 0x39)) {
      if (!number()) return false;
    } else if (c === 0x74) {
      if (!literal(TRUE)) return false;
    } else if (c === 0x66) {
      if (!literal(FALSE)) return false;
    } else if (c === 0x6e) {
      if (!literal(NULL)) return false;
    } else {
      return false;
    }

    // A value ended before i: close containers until another value is due.
    for (;;) {
      ws();
      const top = stack[stack.length - 1];
      if (top === undefined) return i === n;
      const d = b[i];
      if (d === 0x2c) {
        i++;
        ws();
        if (top === 0x7b && !member()) return false;
        break;
      }
      if ((top === 0x5b && d === 0x5d) || (top === 0x7b && d === 0x7d)) {
        i++;
        if (stack.pop() === 0x7b) names.pop();
        continue;
      }
      return false;
    }
  }
}

/**
 * The ATR's bytes parsed as they were fetched: the value they hold, or `atr-malformed` where they are not one JSON text
 * as `isOneJsonText` takes it.
 */
export function parseAtr(bytes: Uint8Array): { value: unknown } | Declined {
  if (!isOneJsonText(bytes)) return declined("atr-malformed", "The ATR's bytes are not one JSON text both languages read alike.");
  return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)) as unknown };
}

// ── The option chosen and the binding slot (rule 6).

/** The member of each protocol's binding slot that lists the options offered. */
const LISTING: { readonly [protocol: string]: string } = {
  x402: "accepts",
  mpp: "challenges",
  acp: "options",
  ap2: "options",
  card: "options",
  ucp: "options",
  ack: "paymentOptions",
};

/** RFC 8785's form of `v`, or undefined where it has none. */
function canonical(v: unknown): string | undefined {
  const text = canonicalJson(v);
  return typeof text === "string" ? text : undefined;
}

/** An MPP challenge's bound members as the protocol package's `issuedDigest` reads them, or undefined. */
async function issuedOf(challenge: unknown): Promise<string | undefined> {
  try {
    const d = await mppIssuedDigest(challenge as MppChallenge);
    return isRefusal(d) ? undefined : d;
  } catch {
    return undefined;
  }
}

/**
 * Where the ATR's binding slot lists the options offered, `option-not-in-atr` for an option chosen that equals none of
 * them: an x402 option as the pairing's `unplaced` gives it against each member as the slot holds it, by RFC 8785 form;
 * an MPP challenge and each member by their bound members (`issuedDigest`, without `id` and the protocol package's
 * `opaque` members). The option chosen is the choice's `accepted` (x402) or `challenge` (MPP); a pairing whose choice
 * holds neither is not compared.
 */
export async function slotHolds(binding: Binding, chosen: Chosen, atr: unknown): Promise<Declined | undefined> {
  const protocol = String(binding.id).split("/")[0]!;
  const listing = LISTING[protocol];
  if (listing === undefined || !isObject(atr)) return undefined;
  const slot = atr[protocol];
  if (!isObject(slot) || !Object.hasOwn(slot, listing)) return undefined;
  const listed: unknown = slot[listing];
  const members: readonly unknown[] = Array.isArray(listed) ? listed : [];
  const choice: unknown = isObject(chosen) ? chosen.choice : undefined;
  const notHeld = declined("option-not-in-atr", `The ATR's ${protocol} slot does not hold the option chosen.`);

  if (protocol === "mpp") {
    const challenge = isObject(choice) ? choice["challenge"] : undefined;
    if (challenge === undefined) return undefined;
    const want = await issuedOf(challenge);
    if (want === undefined) return notHeld;
    for (const m of members) if ((await issuedOf(m)) === want) return undefined;
    return notHeld;
  }
  if (protocol !== "x402") return undefined;
  const accepted = isObject(choice) ? choice["accepted"] : undefined;
  if (accepted === undefined) return undefined;
  const unplace = (binding as unknown as { unplaced?: (o: unknown) => unknown }).unplaced;
  let option: unknown = accepted;
  try {
    if (typeof unplace === "function") option = unplace(accepted);
  } catch {
    return notHeld;
  }
  const want = isRefusal(option) ? undefined : canonical(option);
  if (want === undefined) return notHeld;
  return members.some((m) => canonical(m) === want) ? undefined : notHeld;
}

// ── The buyer's request and the binding slot (rule 7).

const HTTP_MEMBERS: readonly string[] = ["bodyDigest", "method", "path", "query"];
const HTTP_HEADERS_MEMBERS: readonly string[] = ["bodyDigest", "headers", "method", "path", "query"];
const MCP_MEMBERS: readonly string[] = ["argumentsDigest", "tool"];

/** Whether the sorted member names `keys` are exactly `names`, compared one by one. */
const exactly = (keys: readonly string[], names: readonly string[]): boolean =>
  keys.length === names.length && keys.every((k, i) => k === names[i]);

/**
 * Where the binding slot is `x402` and holds a `request` member, `request-mismatch` unless it is the commitment the
 * protocol package computes of the buyer's request in the same form: over HTTP `requestCommitment` with the header
 * names it lists, in order; over MCP `toolCallCommitment`. A refused request gives the package's code as the detail; a
 * member of neither form, its member names compared exactly, is declined, as is a request the package throws on.
 */
export async function requestHeld(binding: Binding, atr: unknown, resourceRequest: ResourceRequest): Promise<Declined | undefined> {
  if (String(binding.id).split("/")[0] !== "x402" || !isObject(atr)) return undefined;
  const slot = atr["x402"];
  if (!isObject(slot) || !Object.hasOwn(slot, "request")) return undefined;
  const committed: unknown = slot["request"];
  const mismatch = (detail: string): Declined => declined("request-mismatch", detail);
  if (!isObject(committed)) return mismatch("The ATR's request commitment is of no form the protocol package writes.");
  const keys = Object.keys(committed).sort();
  let computed: unknown;
  try {
    if (exactly(keys, HTTP_MEMBERS) || exactly(keys, HTTP_HEADERS_MEMBERS)) {
      const listed: unknown = committed["headers"];
      let names: string[] | undefined;
      if (listed !== undefined) {
        if (!Array.isArray(listed) || !listed.every((h) => isObject(h) && typeof h["name"] === "string")) {
          return mismatch("The ATR's request commitment is of no form the protocol package writes.");
        }
        names = listed.map((h) => (h as { name: string }).name);
      }
      computed = await requestCommitment(resourceRequest as HttpRequest, names);
    } else if (exactly(keys, MCP_MEMBERS)) {
      computed = await toolCallCommitment(resourceRequest as ToolCall);
    } else {
      return mismatch("The ATR's request commitment is of no form the protocol package writes.");
    }
  } catch {
    return mismatch("The protocol package could not compute the commitment of the buyer's request.");
  }
  if (isRefusal(computed)) return mismatch(computed.code);
  const want = canonical(committed);
  return want !== undefined && canonical(computed) === want
    ? undefined
    : mismatch("The ATR commits to another request than the buyer's.");
}

// ── The ceiling and the served floor (rules 8 and 9).

/** A pairing's ceiling where `ceilings` raises none and no service serves a floor: 600 seconds. */
export const DEFAULT_CEILING_S = 600;

/** The rails whose payment service serves a floor: the input that carries it, and the service's own margin. */
const FLOORS: ReadonlyMap<string, { readonly input: string; readonly margin: number }> = new Map([
  ["x402/exact/eip155/gateway-batched", { input: "minValiditySeconds", margin: 100 }],
]);

/**
 * The floor inputs of the rails whose payment service serves a floor, by pairing (terms' profile `buyer-gate.md`, rule
 * 9): the names `inputs` carries them under, which a host reads from the payment service and gives the gate.
 */
export const FLOOR_INPUTS: ReadonlyMap<string, readonly string[]> = new Map(
  [...FLOORS].map(([pairing, floor]) => [pairing, Object.freeze([floor.input])] as const),
);

/**
 * Seconds per unit of a deadline signed as a height, by the network's CAIP-2 namespace (the profile's pace table):
 * Cardano's networks are named in the `cardano` and the `cip34` namespaces alike.
 */
const PACE: { readonly [namespace: string]: number } = {
  algorand: 2.82,
  cardano: 1,
  cip34: 1,
  near: 0.6,
  polkadot: 6,
  solana: 0.3,
  stellar: 5,
  sui: 86_400,
  xrpl: 5,
};

const isPositiveSafe = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0;

/**
 * Whether `ceilings` has rule 8's form for a call that pays `pairing`: absent, or an object whose value for `pairing`,
 * where it has one, is a positive safe integer or `"no-end"`. Another pairing's value, an agreement payment's among
 * them, is read when that pairing is paid.
 */
export function isCeilings(v: unknown, pairing: string): v is Ceilings | undefined {
  return v === undefined || (isObject(v) && raisedOf(v as Ceilings, pairing) !== null);
}

/** `pairing`'s raised ceiling: a positive safe integer, `"no-end"`, undefined where none is given, or malformed. */
function raisedOf(ceilings: Ceilings | undefined, pairing: string): number | "no-end" | undefined | null {
  if (ceilings === undefined || !Object.hasOwn(ceilings, pairing)) return undefined;
  const v: unknown = ceilings[pairing];
  return v === "no-end" || isPositiveSafe(v) ? v : null;
}

/**
 * `floor-missing`, naming the input, where the pairing's rail serves a floor and `inputs` does not hold it as a positive
 * safe integer.
 */
export function floorMissing(pairing: string, inputs: Inputs): Declined | undefined {
  const floor = FLOORS.get(pairing);
  if (floor === undefined || isPositiveSafe(inputs[floor.input])) return undefined;
  return declined("floor-missing", floor.input);
}

/**
 * The input that gives the start of a deadline signed as a height where neither the request nor the build signs one, by
 * the network's CAIP-2 namespace: on the XRP Ledger `ledgerIndex`, the index of the validated ledger the caller read,
 * since the protocol package's XRPL builds take `LastLedgerSequence` itself from the caller and sign no start.
 */
const STARTS: { readonly [namespace: string]: string } = { xrpl: "ledgerIndex" };

const isIndex = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** The pairing's network namespace, from the summary's CAIP-2 network. */
const namespaceOfNetwork = (network: string): string => network.split(":")[0]!;

/** The start the caller gives in `inputs` for a deadline signed as a height on `network`, where its chain has one. */
function givenStart(network: string, inputs: Inputs): bigint | undefined {
  const name = STARTS[namespaceOfNetwork(network)];
  const v = name === undefined ? undefined : inputs[name];
  return isIndex(v) ? BigInt(v) : undefined;
}

/** `read.life` in the pairing's data, in seconds, or undefined where the data states none or no pace converts it. */
function lifeOf(binding: Binding, network: string): number | undefined {
  const data: unknown = (binding as { data?: unknown }).data;
  const read = isObject(data) ? data["read"] : undefined;
  const life = isObject(read) ? read["life"] : undefined;
  if (!isObject(life) || !isPositiveSafe(life["value"])) return undefined;
  if (life["unit"] === "seconds") return life["value"];
  const pace = PACE[namespaceOfNetwork(network)];
  return pace === undefined ? undefined : life["value"] * pace;
}

/** A decimal string as a bigint, or undefined. */
function big(v: string | null): bigint | undefined {
  return v !== null && /^[0-9]{1,78}$/.test(v) ? BigInt(v) : undefined;
}

/**
 * How long the signed payment stays payable, in seconds, from the summary's validity: a deadline in seconds less the
 * gate's clock; a deadline signed as a height less the start the request signs, else the height the caller gave the
 * build, else the start the caller gives in `inputs` (`ledgerIndex` on the XRP Ledger), times the chain's pace; where
 * the payer signs no deadline, the pairing's `read.life`; `"no-end"` where none of these bounds it; undefined where the
 * window cannot be read.
 */
function windowOf(binding: Binding, v: Validity, network: string, now: number, inputs: Inputs): number | "no-end" | undefined {
  const until = big(v.notAfter);
  if (v.notAfter === null) return lifeOf(binding, network) ?? "no-end";
  if (until === undefined) return undefined;
  if (v.unit === "seconds") return Number(until - BigInt(now));
  const pace = PACE[namespaceOfNetwork(network)];
  const from = big(v.notBefore) ?? startOf(String(binding.id), inputs) ?? givenStart(network, inputs);
  if (pace === undefined || from === undefined) return undefined;
  return Number(until - from) * pace;
}

/**
 * Check 11 on a summary: `no-end` for a payment that signs no end unless `ceilings` maps the pairing to `"no-end"`, and
 * `past-ceiling` for one payable longer than the pairing's ceiling: 600 seconds, or on a rail with a served floor that
 * floor plus the service's margin, raised to `ceilings`' value where it is larger. A deadline signed as a height on a
 * chain whose start the caller gives (`ledgerIndex` on the XRP Ledger), with no start signed or given, is
 * `no-payable-option` with the chain's namespace's `input-missing` (`xrpl/input-missing`).
 */
export function withinCeiling(
  binding: Binding,
  summary: Summary,
  inputs: Inputs,
  ceilings: Ceilings | undefined,
  now: number,
): Declined | undefined {
  const pairing = String(binding.id);
  const ns = pairing.split("/")[0]!;
  const raised = raisedOf(ceilings, pairing);
  if (raised === null) return declined("no-payable-option", `${ns}/input-malformed`);
  const v = summary.validity;
  const chain = namespaceOfNetwork(summary.network);
  const startName = STARTS[chain];
  if (v.unit !== "seconds" && v.notAfter !== null && v.notBefore === null && startName !== undefined) {
    if (startOf(pairing, inputs) === undefined && !isIndex(inputs[startName])) return declined("no-payable-option", `${chain}/input-missing`);
  }
  const window = windowOf(binding, v, summary.network, now, inputs);
  if (window === "no-end") {
    return raised === "no-end" ? undefined : declined("no-end", `The payment through ${pairing} signs no end.`);
  }
  if (raised === "no-end") return undefined;
  if (window === undefined) return declined("past-ceiling", `The gate cannot read how long the payment through ${pairing} stays payable.`);
  const floor = FLOORS.get(pairing);
  let ceiling = DEFAULT_CEILING_S;
  if (floor !== undefined) {
    const given = inputs[floor.input];
    if (!isPositiveSafe(given)) return declined("floor-missing", floor.input);
    ceiling = given + floor.margin;
  }
  if (raised !== undefined) ceiling = Math.max(ceiling, raised);
  return window > ceiling
    ? declined("past-ceiling", `The payment through ${pairing} stays payable ${window} s, past its ceiling of ${ceiling} s.`)
    : undefined;
}

// ── The approval (rule 11).

/** What the approver and the ceiling read beside each signing: the callback, the raised ceilings and the inputs. */
export interface Approval {
  readonly approver: Approver;
  readonly ceilings: Ceilings | undefined;
  readonly inputs: Inputs;
}

/**
 * A copy of `v` that shares no object or byte array with it, so nothing the approver does reaches the signer. Every
 * signing request kind is plain data, strings, numbers, bigints, booleans, null, byte arrays and arrays and objects of
 * them, holding no function, map, set or date, so the copy is the request as the signer is handed it.
 */
function copyOf<T>(v: T): T {
  if (v instanceof Uint8Array) return v.slice() as T;
  if (Array.isArray(v)) return v.map((x) => copyOf(x)) as T;
  if (typeof v === "object" && v !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = copyOf(x);
    return out as T;
  }
  return v;
}

/** The number of signings a build takes: two where it holds a funding and the voucher that follows it, else one. */
export function stepsOf(unsigned: unknown): number {
  return isObject(unsigned) && typeof unsigned["voucher"] === "function" && Object.hasOwn(unsigned, "funding") ? 2 : 1;
}

/**
 * The CAIP-2 network of a CAIP-10 account, `<namespace>:<reference>:<address>`: its first two parts; undefined for an
 * account of another form.
 */
export function networkOfAccount(account: unknown): string | undefined {
  if (typeof account !== "string") return undefined;
  const parts = account.split(":");
  return parts.length === 3 && parts.every((p) => p !== "") ? `${parts[0]}:${parts[1]}` : undefined;
}

/**
 * Checks 10 and 11 on a request handed to the signer: its summary, or the decline. `network` is the signing account's
 * CAIP-2 network where the caller knows it, which the summary names where the request names none; `opened`, for a later
 * step of a payment signed in steps, the step that opened its channel.
 */
export async function shown(
  binding: Binding,
  request: SigningRequest,
  bytes: Uint8Array,
  inputs: Inputs,
  ceilings: Ceilings | undefined,
  network?: string,
  opened?: Opened,
): Promise<Summary | Declined> {
  const summary = await summaryOf(String(binding.id), request, bytes, network, opened);
  if (summary === undefined) {
    return declined("summary-missing", `The gate has no summary of the ${String((request as { kind?: unknown }).kind)} request of ${String(binding.id)}.`);
  }
  return withinCeiling(binding, summary, inputs, ceilings, Math.floor(Date.now() / 1000)) ?? summary;
}

/**
 * Checks 10 to 12 on one signing: the summary, the ceiling, then the approver, asked once with `ToSign`; any answer but
 * `true`, a throw or a rejection is `not-approved`. `network` is the signing account's CAIP-2 network, and `opened`, for
 * a later step, the step that opened its channel. The summary the approver approved, or the decline.
 */
export async function approves(
  binding: Binding,
  act: "payment" | "agreement",
  request: SigningRequest,
  bytes: Uint8Array,
  step: SigningStep,
  approval: Approval,
  network?: string,
  opened?: Opened,
): Promise<Summary | Declined> {
  const summary = await shown(binding, request, bytes, approval.inputs, approval.ceilings, network, opened);
  if ("decline" in summary) return summary;
  const toSign: ToSign = { act, pairing: String(binding.id), request: copyOf(request), summary, step: { ...step } };
  let answer: unknown;
  try {
    answer = await approval.approver(toSign);
  } catch {
    answer = undefined;
  }
  return answer === true ? summary : declined("not-approved", `The approver did not approve step ${step.index + 1} of ${step.count}.`);
}

