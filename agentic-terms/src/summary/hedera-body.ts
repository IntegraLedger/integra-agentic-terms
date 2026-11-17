/**
 * The summary of a Hedera request handed to the signer: `hedera-body`, the `TransactionBody` bytes the payer signs,
 * read with the protocol package's own transaction decoder; and `hedera-executor`, what the buyer's executor tooling
 * is asked to authorize, as the request names it. A body names no ledger, so its network is the signer's account's.
 */
import { decodeHederaTx } from "@integraledger/lcp/hedera";
import type { Json } from "@integraledger/lcp/core";
import type { Shown } from "../summary.js";
import type { Payee, SigningRequest } from "../types.js";
import { networkIn } from "./encode.js";

/** How the protocol package names HBAR as an x402 asset: the entity id `0.0.0`. */
const HBAR = "0.0.0";
/**
 * The `TransactionBody` fields a crypto transfer's body may hold beside its transfer, none granting more than the
 * summary states: `transactionID` (1), `nodeAccountID` (2), `transactionFee` (3), `transactionValidDuration` (4),
 * `memo` (6) and `cryptoTransfer` (14) (Hedera's `transaction_body.proto`).
 */
const FIELDS = new Set([1, 2, 3, 4, 6, 14]);

/** The field numbers of a protobuf message's top level, in order; undefined where the bytes are not one message. */
function fieldNumbers(b: Uint8Array): number[] | undefined {
  const out: number[] = [];
  let at = 0;
  const varint = (): bigint => {
    let v = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      const x = b[at++];
      if (x === undefined) throw RangeError();
      v |= BigInt(x & 0x7f) << shift;
      if ((x & 0x80) === 0) return v;
    }
    throw RangeError();
  };
  try {
    while (at < b.length) {
      const tag = varint();
      const wt = Number(tag & 7n);
      out.push(Number(tag >> 3n));
      if (wt === 0) varint();
      else if (wt === 2) {
        const length = Number(varint());
        at += length;
      } else if (wt === 1) at += 8;
      else if (wt === 5) at += 4;
      else return undefined;
      if (at > b.length) return undefined;
    }
    return out;
  } catch {
    return undefined;
  }
}

/** A protobuf length-delimited field: its tag, the length as a varint, the bytes. */
function lenField(n: number, bytes: Uint8Array): Uint8Array {
  const len: number[] = [];
  for (let v = bytes.length; ; v >>>= 7) {
    if (v < 0x80) {
      len.push(v);
      break;
    }
    len.push((v & 0x7f) | 0x80);
  }
  const out = new Uint8Array(1 + len.length + bytes.length);
  out[0] = (n << 3) | 2;
  out.set(len, 1);
  out.set(bytes, 1 + len.length);
  return out;
}

/**
 * `hedera-body`, a crypto transfer: the payees are the rows it credits, each with its credit, and the amount their
 * sum, all of one asset, HBAR (`0.0.0`) or one token; the validity from the transaction id's valid start to that plus
 * `transactionValidDuration`, in seconds.
 */
export function hederaTransfer(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; bodyBytes?: unknown };
  const net = networkIn("hedera", network);
  if (r.kind !== "hedera-body" || !(r.bodyBytes instanceof Uint8Array) || net === undefined) return undefined;
  const fields = fieldNumbers(r.bodyBytes);
  if (fields === undefined || !fields.every((n) => FIELDS.has(n))) return undefined;
  // A `Transaction` {5: `SignedTransaction` {1: the body}}, the wire form the decoder reads, with no signature.
  const decoded = decodeHederaTx(lenField(5, lenField(1, r.bodyBytes)));
  if (!("bodies" in decoded) || decoded.bodies.length !== 1) return undefined;
  const body = decoded.bodies[0]!;
  const t = body.transfer;
  if (t === undefined) return undefined;
  const lists = [...(t.hbar.length > 0 ? [{ asset: HBAR, rows: t.hbar }] : []), ...t.tokens.map((x) => ({ asset: x.token, rows: x.rows }))];
  if (lists.length !== 1) return undefined;
  const { asset, rows } = lists[0]!;
  const payees: Payee[] = rows.filter((row) => BigInt(row.amount) > 0n).map((row) => ({ account: row.account, amount: row.amount }));
  if (payees.length === 0) return undefined;
  const amount = payees.reduce((s, p) => s + BigInt(p.amount), 0n);
  const end = body.id.seconds + BigInt(body.validDuration) + (body.id.nanos > 0 ? 1n : 0n);
  return {
    amount: amount.toString(),
    payees,
    asset,
    network: net,
    validity: { notBefore: body.id.seconds.toString(), notAfter: end.toString(), unit: "seconds" },
  };
}

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;

/**
 * `hedera-executor`: the amount and the one payee's part are `amount`, the payee `payTo`, the asset `asset`, the
 * network `network`, the validity none to `validBefore`, in seconds; the grant is the authorization the executor
 * tooling is asked for, `{executors, asset, payTo, amount}`.
 */
export function hederaExecutor(request: SigningRequest): Shown | undefined {
  const r = request as Record<string, unknown>;
  if (r["kind"] !== "hedera-executor") return undefined;
  const { executors, asset, payTo, amount, validBefore } = r;
  const network = networkIn("hedera", r["network"]);
  if (network === undefined || typeof asset !== "string" || typeof payTo !== "string") return undefined;
  if (typeof amount !== "string" || !DECIMAL.test(amount) || !Number.isSafeInteger(validBefore) || (validBefore as number) < 0) return undefined;
  if (!Array.isArray(executors) || !executors.every((e) => typeof e === "string")) return undefined;
  const grant: Json = { executors: [...(executors as string[])], asset, payTo, amount };
  return {
    amount,
    payees: [{ account: payTo, amount }],
    asset,
    network,
    validity: { notBefore: null, notAfter: String(validBefore), unit: "seconds" },
    grant,
  };
}
