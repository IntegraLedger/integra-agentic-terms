/**
 * The buyer piece for `x402/batch-settlement/solana`: the first option on the signer's cluster; the opening's
 * transaction message and first voucher, signed in order, each answered in base58; the deposit from `extra.minDeposit`
 * or the buyer's input, within the buyer's maximum; the recent blockhash from `extra.recentBlockhash` when the offer
 * carries one; and the channel salt, drawn once and kept in `chosen`.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { BuyerPiece, Chosen, Inputs, Read } from "../types.js";
import { batchComplete, batchRequest, depositOf, optionalInputs, randomU64, reviveDecimals } from "./batch.js";
import { firstOption, inputsOf, isObject, isRefusal, refuse, uintOf, x402Chosen } from "./common.js";

const PAIRING = "x402/batch-settlement/solana";
const KEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const U64 = /^[0-9]{1,20}$/;
const U64_LIMIT = 1n << 64n;

const isU64 = (v: Json | undefined): boolean => typeof v === "string" && U64.test(v) && BigInt(v) < U64_LIMIT;

export const x402BatchSettlementSolana: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const o = firstOption(read, account, "solana", PAIRING, KEY);
    if ("refused" in o) return refuse("x402/no-payable-option");
    const extra = isObject(o.accepted.extra) ? o.accepted.extra : {};
    const offered = extra["recentBlockhash"];
    const required = inputsOf(inputs, PAIRING, {
      payerAuthorizer: "string",
      openSlot: "decimal",
      tokenProgram: "string",
      ...(offered === undefined ? { recentBlockhash: "string" } : {}),
      computeUnitLimit: "optional-uint",
      computeUnitPrice: "optional-decimal",
    });
    if (isRefusal(required)) return required;
    const salt = optionalInputs(inputs, "x402", { salt: U64 });
    if (isRefusal(salt)) return salt;
    const blockhash = offered ?? required["recentBlockhash"];
    if (typeof blockhash !== "string" || !KEY.test(blockhash)) return refuse("x402/input-missing");
    if (!KEY.test(String(required["payerAuthorizer"])) || !isU64(required["openSlot"])) return refuse("x402/input-missing");
    if (salt["salt"] !== undefined && !isU64(salt["salt"])) return refuse("x402/input-missing");
    if (required["computeUnitLimit"] !== undefined && uintOf(required["computeUnitLimit"]) === undefined) {
      return refuse("x402/input-missing");
    }
    const deposit = depositOf(o.accepted, inputs);
    if (isRefusal(deposit)) return deposit;
    return x402Chosen(
      PAIRING,
      {
        required: o.required,
        accepted: o.accepted,
        payer: o.address,
        now,
        ...required,
        recentBlockhash: blockhash,
        deposit,
        salt: salt["salt"] ?? randomU64(),
      },
      ref,
    );
  },
  choice: (chosen: Chosen) => reviveDecimals(chosen, ["deposit", "salt", "openSlot", "computeUnitPrice"]),
  request: batchRequest,
  complete: batchComplete,
});
