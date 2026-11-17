/**
 * The summary of an XRP Ledger transaction handed to the signer as its JSON, `xrpl-tx` (a `Payment`) and
 * `xrpl-session-open` (a `PaymentChannelCreate` and the first claim's bytes). Every member of the JSON must be one the
 * summary reads or one that grants nothing, or there is no summary. The deadline is `LastLedgerSequence`, a ledger
 * index; the transaction signs no start. A transaction names its network only by `NetworkID`, which a network whose id
 * is at most 1024 refuses, so without one its network is the signer's account's.
 */
import { xrplChannelId } from "@integraledger/lcp/xrpl";
import type { Shown } from "../summary.js";
import type { SigningRequest } from "../types.js";
import { hex, isRecord, networkIn } from "./encode.js";

/** XRP in drops, as a `Payment`'s `Amount` writes it: a decimal string. */
const DROPS = /^(0|[1-9][0-9]{0,18})$/;
/** The members every transaction carries that grant nothing beyond what the summary states: identity, fee, memo. */
const COMMON = ["TransactionType", "Flags", "Account", "Fee", "Sequence", "LastLedgerSequence", "NetworkID", "Memos", "SourceTag"];
/** Seconds from the Unix epoch to the XRP Ledger's, 2000-01-01T00:00:00Z, which `CancelAfter` counts from. */
const RIPPLE_EPOCH = 946_684_800n;
/** The claim's prefix, `CLM\0`. */
const CLM = [0x43, 0x4c, 0x4d, 0x00];

const isU32 = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 0xffffffff;

/**
 * The members both forms read: the network (`NetworkID`, else the signer's account's), the validity
 * (`LastLedgerSequence`, ledgers), and `Flags`, which must be 0, so no flag widens what moves.
 */
function frame(tx: Record<string, unknown>, network: string | undefined, allowed: readonly string[]) {
  if (!Object.keys(tx).every((k) => COMMON.includes(k) || allowed.includes(k))) return undefined;
  if (tx["Flags"] !== undefined && tx["Flags"] !== 0) return undefined;
  if (typeof tx["Account"] !== "string" || !isU32(tx["LastLedgerSequence"])) return undefined;
  const id = tx["NetworkID"];
  if (id !== undefined && !isU32(id)) return undefined;
  const net = id !== undefined ? `xrpl:${id}` : networkIn("xrpl", network);
  if (net === undefined) return undefined;
  return { network: net, validity: { notBefore: null, notAfter: String(tx["LastLedgerSequence"]), unit: "ledger" } };
}

/**
 * `xrpl-tx`, a `Payment` of XRP: the amount and the one payee's part are `Amount`, in drops, the payee
 * `Destination`; `InvoiceID` and `DestinationTag` grant nothing more. An issued currency's `Amount` is a decimal value
 * with no base unit, and is not summarised.
 */
export function xrplPayment(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; txJson?: unknown };
  if (r.kind !== "xrpl-tx" || !isRecord(r.txJson)) return undefined;
  const tx = r.txJson;
  if (tx["TransactionType"] !== "Payment") return undefined;
  const f = frame(tx, network, ["Destination", "Amount", "DestinationTag", "InvoiceID", "TicketSequence"]);
  const amount = tx["Amount"];
  const to = tx["Destination"];
  if (f === undefined || typeof amount !== "string" || !DROPS.test(amount) || typeof to !== "string") return undefined;
  return { amount, payees: [{ account: to, amount }], asset: "XRP", ...f };
}

/**
 * `xrpl-session-open`: the `PaymentChannelCreate`'s `Amount` is the deposit, in drops, and its `Destination` the payee;
 * the first claim's bytes, `CLM\0`, the channel the create makes and drops as a big-endian u64, are the amount the
 * payee may redeem at once. The destination may close the channel at any time and the source once `SettleDelay` has
 * passed (XRP Ledger, PaymentChannelClaim), so both may close it; `CancelAfter`, where set, is when it ends.
 */
export function xrplSessionOpen(request: SigningRequest, network?: string): Shown | undefined {
  const r = request as { kind?: unknown; txJson?: unknown; claim?: unknown };
  if (r.kind !== "xrpl-session-open" || !isRecord(r.txJson) || !isRecord(r.claim)) return undefined;
  const tx = r.txJson;
  if (tx["TransactionType"] !== "PaymentChannelCreate") return undefined;
  const f = frame(tx, network, ["Destination", "Amount", "SettleDelay", "PublicKey", "CancelAfter"]);
  const deposit = tx["Amount"];
  const to = tx["Destination"];
  const cancelAfter = tx["CancelAfter"];
  const bytes = r.claim["bytes"];
  if (f === undefined || typeof deposit !== "string" || !DROPS.test(deposit) || typeof to !== "string") return undefined;
  if (!isU32(tx["Sequence"]) || (cancelAfter !== undefined && !isU32(cancelAfter))) return undefined;
  if (!(bytes instanceof Uint8Array) || bytes.length !== 44 || CLM.some((b, i) => bytes[i] !== b)) return undefined;
  const channel = xrplChannelId(tx["Account"] as string, to, tx["Sequence"]);
  if (typeof channel !== "string" || hex(bytes.subarray(4, 36)).toUpperCase() !== channel.toUpperCase()) return undefined;
  const drops = new DataView(bytes.buffer, bytes.byteOffset + 36, 8).getBigUint64(0, false).toString();
  return {
    amount: drops,
    payees: [{ account: to, amount: drops }],
    ...(cancelAfter === undefined ? {} : { end: (BigInt(cancelAfter) + RIPPLE_EPOCH).toString() }),
    deposit,
    closableBy: [tx["Account"] as string, to],
    asset: "XRP",
    ...f,
  };
}
