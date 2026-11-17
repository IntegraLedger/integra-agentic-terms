/**
 * The buyer piece for `x402/batch-settlement/eip155`: the first option on the signer's chain; the opening's token
 * authorization and first voucher, signed in order, with the channel's configuration and the deposit's salt beside them
 * for the approval summary, as the protocol package's build gives them; the deposit from `extra.minDeposit` or the
 * buyer's input; and the authorization salt, drawn once and kept in `chosen`.
 */
import type { Refusal } from "@integraledger/lcp/core";
import type { BatchUnsigned } from "@integraledger/lcp/x402-batch-settlement";
import type { BuyerPiece, Chosen, Inputs, Read, SigningRequest } from "../types.js";
import { batchComplete, depositOf, optionalInputs, randomSalt32, reviveDecimals } from "./batch.js";
import { firstOption, isRefusal, refuse, x402Chosen } from "./common.js";

const PAIRING = "x402/batch-settlement/eip155";
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;

export const x402BatchSettlementEip155: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const o = firstOption(read, account, "eip155", PAIRING, EVM_ADDRESS);
    if (isRefusal(o)) return refuse("x402/no-payable-option");
    const given = optionalInputs(inputs, "x402", { payerAuthorizer: EVM_ADDRESS, authSalt: HASH32 });
    if (isRefusal(given)) return given;
    if (given["payerAuthorizer"] === undefined) return refuse("x402/input-missing");
    const deposit = depositOf(o.accepted, inputs);
    if (isRefusal(deposit)) return deposit;
    return x402Chosen(
      PAIRING,
      {
        required: o.required,
        accepted: o.accepted,
        from: o.address,
        now,
        payerAuthorizer: given["payerAuthorizer"],
        deposit,
        authSalt: given["authSalt"] ?? randomSalt32(),
      },
      ref,
    );
  },
  choice: (chosen: Chosen) => reviveDecimals(chosen, ["deposit"]),
  /**
   * The build's two requests as one `batch` request, with the channel's `config` and the deposit authorization's salt,
   * `authSalt`, as the protocol package's build gives them: the buyer's salt, or H in the scheme's refund-authorizer mode.
   */
  request(unsigned: unknown): SigningRequest {
    const u = unsigned as BatchUnsigned;
    const config = u.config === undefined ? {} : { config: { ...u.config } };
    const authSalt = typeof u.authSalt === "string" ? { authSalt: u.authSalt } : {};
    return { kind: "batch", requests: u.requests, ...config, ...authSalt };
  },
  complete: batchComplete,
});
