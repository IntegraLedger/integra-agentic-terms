/**
 * The buyer pieces shared by MPP's pairings: the first challenge, in document order, that offers the pairing on the
 * signer's chain; the build's request exactly as built; and the credential the signer's answer completes.
 */
import type { AtrHash, Json, Refusal } from "@integraledger/lcp";
import { parseJson } from "@integraledger/lcp";
import type { Hex } from "@integraledger/lcp/evm";
import { network, pairingsOfPlaced, type MppChallenge, type MppCredential, type MppUnsigned } from "@integraledger/lcp/mpp";
import { memoCalldata } from "@integraledger/lcp/tempo";
import type { BuyerPiece, Choose, Chosen, Inputs, Presented, Read, Signature, SigningRequest, TempoCalls } from "../types.js";
import { accountOf, bigintOf, broadcasts, choiceOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

type Spec = Parameters<typeof inputsOf>[2];

/** The request a challenge carries, decoded from base64url JSON, or undefined. */
export function requestOf(c: MppChallenge): Record<string, unknown> | undefined {
  if (typeof c.request !== "string") return undefined;
  try {
    const b64 = c.request.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    const v: unknown = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return isObject(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

/** Whether a placed challenge offers the pairing, by the protocol package's `pairingsOfPlaced`. */
export function offers(c: MppChallenge, pairing: string): boolean {
  return pairingsOfPlaced(c).some((p) => p === pairing);
}

/**
 * The first challenge offering `pairing` on the account's EVM network, as MPP's `network` reads it, with the choice
 * MPP's build takes: the challenge, `from`, `now`, and the buyer's own inputs named in `spec`.
 */
export function mppChoose(
  pairing: string,
  spec: Spec,
  accept?: (c: MppChallenge) => Refusal | null,
): Choose {
  return (read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal => {
    const a = accountOf(account);
    if (a === undefined || a.namespace !== "eip155" || !EVM_ADDRESS.test(a.address)) return refuse("mpp/no-payable-option");
    const offer = read.offer;
    const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
    const challenge = challenges.find((c) => offers(c, pairing) && network(c) === a.network);
    if (challenge === undefined) return refuse("mpp/no-payable-option");
    const refused = accept?.(challenge) ?? null;
    if (refused !== null) return refused;
    const given = inputsOf(inputs, pairing, spec);
    if (isRefusal(given)) return given;
    return { pairing, choice: { challenge: challenge as unknown as Json, from: a.address, now, ...given }, ref };
  };
}

/** The choice as MPP's build takes it, with `deposit` as a bigint where the choice carries one. */
export function mppChoice(chosen: Chosen): unknown {
  const c = choiceOf(chosen);
  if (c === undefined) return refuse("mpp/choice-malformed");
  if (c["deposit"] === undefined) return c;
  const deposit = bigintOf(c["deposit"]);
  return deposit === undefined ? refuse("mpp/choice-malformed") : { ...c, deposit };
}

/** The build's request, exactly as built. */
export function mppRequest(unsigned: unknown): SigningRequest | Refusal {
  return (unsigned as MppUnsigned).request;
}

/** The credential for a one-value answer: a signature, a signed transaction or a transaction hash, as `0x` hex. */
export async function mppComplete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
  if (typeof signature !== "string") return refuse("mpp/credential-malformed");
  return (unsigned as { complete(s: Hex): MppCredential | Refusal }).complete(signature as Hex);
}

/** A buyer piece for an MPP charge pairing whose answer is one value. */
export function mppChargePiece(pairing: string, spec: Spec, accept?: (c: MppChallenge) => Refusal | null): BuyerPiece {
  return Object.freeze({
    choose: mppChoose(pairing, spec, accept),
    choice: mppChoice,
    request: mppRequest,
    complete: mppComplete,
    moves: broadcasts,
  });
}

const MAX_SPLITS = 10;
const DECIMAL = /^[0-9]{1,78}$/;
const WORD = /^0x[0-9a-fA-F]{64}$/;
const TRANSFER_SELECTOR = "a9059cbb";

interface Split {
  recipient: Hex;
  amount: bigint;
  memo?: Hex;
}

/**
 * A Tempo challenge's `methodDetails.splits`: none, or 1–10 entries, each with a recipient address, an amount above
 * zero and an optional 32-byte memo.
 */
function tempoSplits(c: MppChallenge): readonly Split[] | Refusal {
  const details = requestOf(c)?.["methodDetails"];
  const splits = isObject(details) ? details["splits"] : undefined;
  if (splits === undefined) return [];
  if (!Array.isArray(splits) || splits.length < 1 || splits.length > MAX_SPLITS) return refuse("mpp/splits-malformed");
  const out: Split[] = [];
  for (const s of splits) {
    if (!isObject(s)) return refuse("mpp/splits-malformed");
    const { recipient, amount, memo } = s;
    if (typeof recipient !== "string" || !EVM_ADDRESS.test(recipient)) return refuse("mpp/splits-malformed");
    if (typeof amount !== "string" || !DECIMAL.test(amount) || BigInt(amount) === 0n) return refuse("mpp/splits-malformed");
    if (memo !== undefined && (typeof memo !== "string" || !WORD.test(memo))) return refuse("mpp/splits-malformed");
    out.push({ recipient: recipient as Hex, amount: BigInt(amount), ...(memo !== undefined ? { memo: memo as Hex } : {}) });
  }
  return out;
}

/** What the primary recipient receives: `amount` less the splits, which must leave more than zero. */
function primaryAmount(c: MppChallenge, splits: readonly Split[]): bigint | Refusal {
  const amount = requestOf(c)?.["amount"];
  if (typeof amount !== "string" || !DECIMAL.test(amount)) return refuse("mpp/request-malformed");
  const primary = BigInt(amount) - splits.reduce((sum, s) => sum + s.amount, 0n);
  return primary > 0n ? primary : refuse("mpp/input-malformed");
}

/** Accepts a Tempo challenge whose splits are well formed and leave the primary recipient more than zero. */
export function acceptSplits(c: MppChallenge): Refusal | null {
  const splits = tempoSplits(c);
  if (isRefusal(splits)) return splits;
  const primary = primaryAmount(c, splits);
  return isRefusal(primary) ? primary : null;
}

/** `transfer(address,uint256)` calldata. */
function transferCalldata(to: Hex, amount: bigint): Hex {
  return `0x${TRANSFER_SELECTOR}${"0".repeat(24)}${to.slice(2).toLowerCase()}${amount.toString(16).padStart(64, "0")}`;
}

type TempoBinding = { build(choice: never, h: AtrHash): Promise<MppUnsigned | Refusal> };

/**
 * A Tempo charge's build. Without splits it is the binding's own `tempo-call`. With splits it is `tempo-calls`: the
 * binding's primary call, carrying its attribution memo, for `amount` less the splits, then one call per split in
 * array order, `transferWithMemo` where the split names a memo and `transfer` otherwise, all on `currency`.
 */
export function tempoBuild(binding: TempoBinding): NonNullable<BuyerPiece["build"]> {
  return async (choice: unknown, h: AtrHash): Promise<unknown> => {
    const unsigned = await binding.build(choice as never, h);
    if (isRefusal(unsigned)) return unsigned;
    const challenge = (choice as { challenge: MppChallenge }).challenge;
    const splits = tempoSplits(challenge);
    if (isRefusal(splits) || splits.length === 0) return isRefusal(splits) ? splits : unsigned;
    const primary = primaryAmount(challenge, splits);
    if (isRefusal(primary)) return primary;
    const request = unsigned.request;
    if (request.kind !== "tempo-call") return refuse("mpp/request-malformed");
    const recipient = requestOf(challenge)?.["recipient"] as Hex;
    const memo: Hex = `0x${request.call.data.slice(-64)}`;
    const primaryCall = memoCalldata(recipient, primary, memo);
    if (isRefusal(primaryCall)) return primaryCall;
    const currency = request.call.to;
    const calls: { to: Hex; data: Hex }[] = [{ to: currency, data: primaryCall }];
    for (const s of splits) {
      const data = s.memo !== undefined ? memoCalldata(s.recipient, s.amount, s.memo) : transferCalldata(s.recipient, s.amount);
      if (isRefusal(data)) return data;
      calls.push({ to: currency, data });
    }
    const tempoCalls: TempoCalls = {
      kind: "tempo-calls",
      chainId: request.chainId,
      calls,
      validBefore: request.validBefore,
      broadcast: request.broadcast,
    };
    return { request: tempoCalls, complete: (s: Hex) => unsigned.complete(s) };
  };
}

/**
 * The credential for a pushed Tempo transfer: the answer is `{hash, landed?: {transaction, blockNumber, logs}}`, the
 * hash the signer broadcast and, where the signer gives it, its landed receipt, which carries the memo `bound` reads.
 */
export async function pushComplete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
  if (!isObject(signature) || typeof signature["hash"] !== "string") return refuse("mpp/credential-malformed");
  const credential = (unsigned as { complete(s: Hex): MppCredential | Refusal }).complete(signature["hash"] as Hex);
  if ("refused" in credential) return credential;
  const landed = signature["landed"];
  if (landed === undefined) return credential;
  if (!isObject(landed) || typeof landed["transaction"] !== "string" || !Array.isArray(landed["logs"])) {
    return refuse("mpp/credential-malformed");
  }
  const blockNumber = bigintOf(landed["blockNumber"]);
  if (blockNumber === undefined) return refuse("mpp/credential-malformed");
  return {
    ...credential,
    landed: { transaction: landed["transaction"] as Hex, blockNumber, logs: landed["logs"] as never },
  } as MppCredential;
}
