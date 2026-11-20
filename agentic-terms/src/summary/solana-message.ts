/**
 * The summary of a Solana message handed to the signer, `solana-message` and `solana-session-open`, and of the `batch`
 * of x402's `batch-settlement` opening on Solana: the message is read with the protocol package's own transaction
 * decoder, and every instruction in it must be one the summary can state, or there is no summary. A message names no
 * cluster, so its network is the signer's account's; its blockhash bounds it for the rail's life, so its validity
 * names no height.
 */
import {
  COMPUTE_BUDGET,
  MEMO_V3,
  MEMO_V4,
  PAYMENT_CHANNELS,
  SYSTEM,
  TOKEN,
  TOKEN_2022,
  decodeSvmTx,
} from "@integraledger/lcp/svm";
import type { Shown } from "../summary.js";
import type { Payee, SigningRequest } from "../types.js";
import { base58, networkIn, uintLe } from "./encode.js";

/** The version byte of a version-1 message (SIMD-0385). */
const V1 = 0x81;
/** The rail's own life bounds a Solana message: no height is signed, so both ends are none. */
const VALIDITY = { notBefore: null, notAfter: null, unit: "block" } as const;
/** How the summary names native SOL, which a System `transfer` moves: the MPP `solana` method's own currency name. */
const SOL = "sol";

/**
 * The message as an unsigned wire transaction, one zero signature slot per required signer, as the Solana transaction
 * format lays one out: before a legacy or v0 message with their compact-u16 count, after a version-1 message.
 */
function unsignedWire(message: Uint8Array): Uint8Array | undefined {
  if (message.length < 2) return undefined;
  const v1 = message[0] === V1;
  const required = (message[0]! & 0x80) !== 0 ? message[1]! : message[0]!;
  if (required === 0 || required > 0x7f) return undefined;
  const wire = new Uint8Array((v1 ? 0 : 1) + 64 * required + message.length);
  if (v1) {
    wire.set(message, 0);
  } else {
    wire[0] = required;
    wire.set(message, 1 + 64 * required);
  }
  return wire;
}

/** A transfer the message signs: the destination, the amount and what moves, a mint or SOL. */
interface Transfer {
  readonly to: string;
  readonly amount: bigint;
  readonly asset: string;
}

/** A payment-channels `open` the message signs. */
interface Open {
  /** The account that funds the deposit, the `open`'s first. */
  readonly payer: string;
  readonly payee: string;
  readonly mint: string;
  /** The key the channel's vouchers are signed with, the `open`'s fifth account. */
  readonly signer: string;
  /** The channel's account, the `open`'s sixth. */
  readonly channel: string;
  readonly deposit: bigint;
  readonly recipients: readonly { recipient: string; bps: number }[];
}

/** What the message signs, by its instructions; undefined where one of them is not one the summary can state. */
function read(message: Uint8Array): { transfers: Transfer[]; opens: Open[] } | undefined {
  const wire = unsignedWire(message);
  if (wire === undefined) return undefined;
  const tx = decodeSvmTx(wire);
  if (!("instructions" in tx)) return undefined;
  const keys = tx.keys.map(base58);
  const transfers: Transfer[] = [];
  const opens: Open[] = [];
  for (const ix of tx.instructions) {
    const program = keys[ix.program];
    // An account loaded from an address table is not in the message: the summary cannot name it.
    if (program === undefined || ix.accounts.some((a) => a >= keys.length)) return undefined;
    const at = (i: number) => keys[ix.accounts[i]!]!;
    const d = ix.data;
    if (program === COMPUTE_BUDGET || program === MEMO_V3 || program === MEMO_V4) continue;
    if (program === TOKEN || program === TOKEN_2022) {
      // TransferChecked: 12, amount u64, decimals u8; accounts source, mint, destination, authority.
      if (d[0] !== 12 || d.length !== 10 || ix.accounts.length !== 4) return undefined;
      transfers.push({ to: at(2), amount: uintLe(d, 1, 8), asset: at(1) });
    } else if (program === SYSTEM) {
      // transfer: 2 as u32, lamports u64; accounts from, to. Every other System instruction, a durable nonce's
      // AdvanceNonceAccount among them, is not one the summary states.
      if (d.length !== 12 || uintLe(d, 0, 4) !== 2n || ix.accounts.length !== 2) return undefined;
      transfers.push({ to: at(1), amount: uintLe(d, 4, 8), asset: SOL });
    } else if (program === PAYMENT_CHANNELS) {
      // open: 1, salt u64, deposit u64, gracePeriod u32, openSlot u64, then a u32 count of (recipient, bps u16).
      if (d[0] !== 1 || d.length < 33 || ix.accounts.length !== 14) return undefined;
      const count = Number(uintLe(d, 29, 4));
      if (d.length !== 33 + 34 * count) return undefined;
      const recipients = Array.from({ length: count }, (_, i) => ({
        recipient: base58(d.subarray(33 + 34 * i, 65 + 34 * i)),
        bps: Number(uintLe(d, 65 + 34 * i, 2)),
      }));
      opens.push({ payer: at(0), payee: at(2), mint: at(3), signer: at(4), channel: at(5), deposit: uintLe(d, 9, 8), recipients });
    } else {
      return undefined;
    }
  }
  return { transfers, opens };
}

/**
 * Each payee's part of `total`: each recipient of the distribution its bps of `total`, rounded down, and the channel's
 * payee the rest where the distribution's bps sum to less than 10,000, as the payment-channels program pays the
 * remainder to the payee; the payee alone, with the whole, where the distribution names no recipient. A recipient of
 * 0 bps, or bps that sum past 10,000, which the program's `open` refuses, gives none.
 */
function shares(open: Open, total: bigint): Payee[] | undefined {
  if (open.recipients.length === 0) return [{ account: open.payee, amount: total.toString() }];
  const bps = open.recipients.reduce((s, r) => s + r.bps, 0);
  if (open.recipients.some((r) => r.bps === 0) || bps > 10_000) return undefined;
  const payees = open.recipients.map((r) => ({ account: r.recipient, amount: (total * BigInt(r.bps)) / 10_000n }));
  const rest = total - payees.reduce((s, p) => s + p.amount, 0n);
  const all = bps < 10_000 ? [...payees, { account: open.payee, amount: rest }] : payees;
  return all.map((p) => ({ account: p.account, amount: p.amount.toString() }));
}

/**
 * Who may close the channel an `open` opens, by the payment-channels program's rule (x402's
 * `scheme_batch_settlement_svm.md`, its lifecycle): its payee at any time, by `settle_and_seal`, and its payer, by
 * `request_close`, which returns the deposit's rest once the grace period has passed (`withdraw_payer`).
 */
function closers(open: Open): string[] {
  return open.payee === open.payer ? [open.payee] : [open.payee, open.payer];
}

/**
 * A message of token or SOL transfers and their compute budget and memos: the amount is their sum, each transfer's
 * destination a payee with its amount, all of one asset, its mint or `sol`.
 */
export function solanaTransfer(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; message?: unknown };
  const net = networkIn("solana", network);
  if (r.kind !== "solana-message" || !(r.message instanceof Uint8Array) || net === undefined) return undefined;
  const read_ = read(r.message);
  if (read_ === undefined || read_.opens.length !== 0 || read_.transfers.length === 0) return undefined;
  const asset = read_.transfers[0]!.asset;
  if (read_.transfers.some((t) => t.asset !== asset)) return undefined;
  const amount = read_.transfers.reduce((s, t) => s + t.amount, 0n);
  return {
    amount: amount.toString(),
    payees: read_.transfers.map((t) => ({ account: t.to, amount: t.amount.toString() })),
    asset,
    network: net,
    validity: VALIDITY,
  };
}

/** The one payment-channels `open` of a message that signs nothing else but its compute budget and memos. */
function openOf(message: unknown): Open | undefined {
  if (!(message instanceof Uint8Array)) return undefined;
  const read_ = read(message);
  return read_ === undefined || read_.transfers.length !== 0 || read_.opens.length !== 1 ? undefined : read_.opens[0];
}

/**
 * A one-request channel's `open` (`upto`): the deposit escrows the maximum the payee may charge, split by the
 * distribution, or the channel's payee's whole where it names none; who may close it, its payee and its payer; the asset
 * is its mint.
 */
export function solanaUptoOpen(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; message?: unknown };
  const net = networkIn("solana", network);
  if (r.kind !== "solana-message" || net === undefined) return undefined;
  const open = openOf(r.message);
  const payees = open === undefined ? undefined : shares(open, open.deposit);
  if (open === undefined || payees === undefined) return undefined;
  const deposit = open.deposit.toString();
  return { maximum: deposit, payees, deposit, closableBy: closers(open), asset: open.mint, network: net, validity: VALIDITY };
}

/**
 * A session's `open` (`solana-session-open`): the deposit, split by the distribution, or the channel's payee's whole
 * where it names none; who may close it, its payee and its payer; the asset is its mint. The vouchers that later charge it are signed apart.
 */
export function solanaSessionOpen(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; message?: unknown };
  const net = networkIn("solana", network);
  if (r.kind !== "solana-session-open" || net === undefined) return undefined;
  const open = openOf(r.message);
  const payees = open === undefined ? undefined : shares(open, open.deposit);
  if (open === undefined || payees === undefined) return undefined;
  return { payees, deposit: open.deposit.toString(), closableBy: closers(open), asset: open.mint, network: net, validity: VALIDITY };
}

/**
 * `x402/batch-settlement/solana`'s opening, a `batch` of the `open` message, then the first voucher, for the `open`'s
 * authorized signer, over the channel the `open` opens and with no expiry, as x402's scheme writes every voucher
 * (`scheme_batch_settlement_svm.md`: `expiresAt` "MUST be `0`"): the amount and each payee's part are the voucher's
 * amount, split by the `open`'s distribution; the deposit and who may close the channel the `open`'s; the asset its mint. A voucher of another
 * channel or signer, or with an expiry, gives none. A voucher signs 50 bytes: `56 01`, the channel id, the amount as a
 * u64 and the expiry as an i64, little-endian.
 */
export function solanaBatchOpening(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; requests?: unknown };
  const net = networkIn("solana", network);
  if (r.kind !== "batch" || !Array.isArray(r.requests) || r.requests.length !== 2 || net === undefined) return undefined;
  const [tx, voucher] = r.requests as { kind?: unknown; message?: unknown; signer?: unknown }[];
  if (tx?.kind !== "solana-message" || voucher?.kind !== "ed25519-raw") return undefined;
  const open = openOf(tx.message);
  const v = voucher.message;
  if (open === undefined || !(v instanceof Uint8Array) || v.length !== 50 || v[0] !== 0x56 || v[1] !== 0x01) return undefined;
  if (base58(v.subarray(2, 34)) !== open.channel || voucher.signer !== open.signer || uintLe(v, 42, 8) !== 0n) return undefined;
  const amount = uintLe(v, 34, 8);
  const payees = shares(open, amount);
  if (payees === undefined) return undefined;
  return {
    amount: amount.toString(),
    payees,
    deposit: open.deposit.toString(),
    closableBy: closers(open),
    asset: open.mint,
    network: net,
    validity: VALIDITY,
  };
}
