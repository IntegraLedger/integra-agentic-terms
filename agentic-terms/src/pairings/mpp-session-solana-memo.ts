/**
 * The buyer piece for `mpp/session/solana/memo`, MPP's `session` intent with the stock method `solana` under the
 * challenge whose `modes` is exactly `["pull"]` and whose `pullVoucherStrategy` is `clientVoucher`: the first challenge,
 * in document order, that offers the pairing on the account's network. The protocol package composes the stock `open`
 * of a payment channel, its fee payer and rent payer the challenge's `operator`, with one Memo instruction carrying H's
 * LCP string, and hands the payer its message as the `solana-session-open` request, exactly as built; the payer signs
 * the message once, and its 64-byte Ed25519 signature, as `0x` hex, completes the build's own open credential, the
 * operator's signature left for the seller's server, which co-signs and submits the opening. The channel's salt is the
 * buyer's when given, else a random u64, as the stock client draws one; the session key that signs vouchers
 * (`authorizedSigner`) is the buyer's when given, else the payer's own key. The deposit (the request's `cap` where
 * absent), the grace period, and the open slot, blockhash, mint and token program the request leaves out are the
 * buyer's.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { Inputs } from "../types.js";
import { bigintOf, inputsOf, isRefusal, refuse } from "./common.js";
import { completeWith, mppRailPiece, signature64 } from "./mpp-rails.js";
import { SOLANA_ADDRESS } from "./x402-exact-solana.js";

const PAIRING = "mpp/session/solana/memo";
const U64_LIMIT = 1n << 64n;

/** A u64 from the platform's CSPRNG, in decimal. */
function randomU64(): string {
  return crypto.getRandomValues(new BigUint64Array(1))[0]!.toString();
}

function inputs(_request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, PAIRING, {
    salt: "optional-decimal",
    authorizedSigner: "optional-string",
    deposit: "optional-decimal",
    gracePeriod: "optional-uint",
    openSlot: "optional-decimal",
    recentBlockhash: "optional-string",
    mint: "optional-string",
    tokenProgram: "optional-string",
  });
  if (isRefusal(read)) return read;
  const salt = read["salt"] ?? randomU64();
  const signer = read["authorizedSigner"];
  if (bigintOf(salt)! >= U64_LIMIT || (signer !== undefined && !SOLANA_ADDRESS.test(signer as string))) {
    return refuse("mpp/input-missing");
  }
  return { ...read, salt };
}

/** The choice as the build takes it: the salt, deposit and open slot as bigints, the voucher key the payer's by default. */
function revive(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  const salt = bigintOf(c["salt"]);
  const deposit = c["deposit"] === undefined ? undefined : bigintOf(c["deposit"]);
  const openSlot = c["openSlot"] === undefined ? undefined : bigintOf(c["openSlot"]);
  if (salt === undefined || (c["deposit"] !== undefined && deposit === undefined) || (c["openSlot"] !== undefined && openSlot === undefined)) {
    return refuse("mpp/choice-malformed");
  }
  return {
    ...c,
    salt,
    authorizedSigner: c["authorizedSigner"] ?? c["payer"],
    ...(deposit === undefined ? {} : { deposit }),
    ...(openSlot === undefined ? {} : { openSlot }),
  };
}

export const mppSessionSolanaMemo = mppRailPiece({
  pairing: PAIRING,
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "payer",
  now: false,
  inputs,
  revive,
  complete: completeWith(signature64),
});
