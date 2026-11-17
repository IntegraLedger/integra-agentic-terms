/**
 * The summary of a `stellar-precondition` request, the buyer's two signings of `x402/exact/stellar/precondition`: the
 * Soroban authorization entry's `HashIDPreimage` (Stellar's XDR, `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` or its form with
 * the address), whose SHA-256 the buyer's key signs, and the 40-byte payload of the signed-payload precondition (CAP-40),
 * which it signs raw. Only an authorization of one `transfer(from, to, amount)` on a contract, from one account to
 * another, with no sub-invocation, is summarised, and only with a payload whose last 8 bytes are its nonce.
 */
import type { Shown } from "../summary.js";
import type { Inputs, SigningRequest } from "../types.js";
import { base32, hex } from "./encode.js";

/**
 * Each Stellar network by its network id, the SHA-256 of its passphrase ("Public Global Stellar Network ; September
 * 2015", "Test SDF Network ; September 2015"), which the preimage holds.
 */
export const NETWORK_IDS: ReadonlyMap<string, string> = new Map([
  ["7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979", "stellar:pubnet"],
  ["cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472", "stellar:testnet"],
]);

/** The strkey version bytes of an account (`G…`) and a contract (`C…`). */
const ACCOUNT = 6 << 3;
const CONTRACT = 2 << 3;
const TRANSFER = new TextEncoder().encode("transfer");

/** CRC16-XModem, the strkey checksum. */
function crc16(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

/** The strkey of a 32-byte key: the version byte, the key and its checksum, little-endian, in base32. */
function strkey(version: number, key: Uint8Array): string {
  const body = new Uint8Array(35);
  body[0] = version;
  body.set(key, 1);
  const sum = crc16(body.subarray(0, 33));
  body[33] = sum & 0xff;
  body[34] = sum >>> 8;
  return base32(body);
}

/** A reader of XDR: big-endian integers, fixed and padded opaque data, each read throwing past the end. */
function reader(b: Uint8Array) {
  let at = 0;
  const take = (n: number): Uint8Array => {
    if (at + n > b.length) throw RangeError();
    const out = b.subarray(at, at + n);
    at += n;
    return out;
  };
  const u32 = (): number => {
    const x = take(4);
    return ((x[0]! << 24) | (x[1]! << 16) | (x[2]! << 8) | x[3]!) >>> 0;
  };
  const u64 = (): bigint => (BigInt(u32()) << 32n) | BigInt(u32());
  return {
    take,
    u32,
    u64,
    i64: (): bigint => BigInt.asIntN(64, u64()),
    get done(): boolean {
      return at === b.length;
    },
  };
}
type Reader = ReturnType<typeof reader>;

/** An `SCAddress` of an account: `SC_ADDRESS_TYPE_ACCOUNT` and an Ed25519 `PublicKey`; its key, or undefined. */
function account(r: Reader): Uint8Array | undefined {
  return r.u32() === 0 && r.u32() === 0 ? r.take(32) : undefined;
}

/** An `SCVal` of type `SCV_ADDRESS` holding an account; its key, or undefined. */
function accountVal(r: Reader): Uint8Array | undefined {
  return r.u32() === 18 ? account(r) : undefined;
}

/**
 * `stellar-precondition`: the amount and the one payee's part are the transfer's `i128` amount, the payee its `to`
 * account, the asset its contract as a `C…` strkey, the network the one whose id the preimage holds, and the validity
 * none to the preimage's signature expiration ledger, in ledgers.
 */
export function stellarPrecondition(request: SigningRequest): Shown | undefined {
  const q = request as { kind?: unknown; preimage?: unknown; payload?: unknown };
  if (q.kind !== "stellar-precondition" || !(q.preimage instanceof Uint8Array) || !(q.payload instanceof Uint8Array)) return undefined;
  const { preimage, payload } = q;
  try {
    const r = reader(preimage);
    const type = r.u32();
    if (type !== 9 && type !== 10) return undefined;
    const network = NETWORK_IDS.get(hex(r.take(32)));
    const nonce = r.take(8);
    const expiration = r.u32();
    const signer = type === 10 ? account(r) : undefined;
    if (network === undefined || (type === 10 && signer === undefined)) return undefined;
    // The invocation: SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN, a contract, the function `transfer` and its three
    // arguments, then no sub-invocation.
    if (r.u32() !== 0 || r.u32() !== 1) return undefined;
    const contract = r.take(32);
    const nameLength = r.u32();
    if (nameLength !== TRANSFER.length || hex(r.take(nameLength)) !== hex(TRANSFER) || r.u32() !== 3) return undefined;
    const from = accountVal(r);
    const to = accountVal(r);
    if (from === undefined || to === undefined || r.u32() !== 10) return undefined;
    const amount = (r.i64() << 64n) | r.u64();
    if (amount < 0n || r.u32() !== 0 || !r.done) return undefined;
    if (signer !== undefined && hex(signer) !== hex(from)) return undefined;
    if (payload.length !== 40 || hex(payload.subarray(32)) !== hex(nonce)) return undefined;
    const value = amount.toString();
    return {
      amount: value,
      payees: [{ account: strkey(ACCOUNT, to), amount: value }],
      asset: strkey(CONTRACT, contract),
      network,
      validity: { notBefore: null, notAfter: String(expiration), unit: "ledger" },
    };
  } catch {
    return undefined;
  }
}

/** The ledger the caller gave the build, `currentLedger`, from which the entry's expiration was counted. */
export function stellarStart(inputs: Inputs): bigint | undefined {
  const v = inputs["currentLedger"];
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : undefined;
}
