/**
 * The buyer piece for `x402/batch-settlement/eip155`: the first option on the signer's chain; the opening's token
 * authorization and first voucher, signed in order, with the channel's configuration and the deposit's salt beside them
 * for the approval summary; the deposit from `extra.minDeposit` or the buyer's input; and the authorization salt, drawn
 * once and kept in `chosen`.
 */
import type { AtrHash, Refusal } from "@integraledger/lcp/core";
import { batchEvm, type BatchUnsigned } from "@integraledger/lcp/x402-batch-settlement";
import type { BuyerPiece, Chosen, Inputs, Read, SigningRequest } from "../types.js";
import { batchComplete, depositOf, optionalInputs, randomSalt32, reviveDecimals } from "./batch.js";
import { firstOption, isObject, isRefusal, refuse, x402Chosen } from "./common.js";

const PAIRING = "x402/batch-settlement/eip155";
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;
const ZERO_ADDRESS = /^0x0{40}$/;

/**
 * The salt of the opening's ERC-3009 deposit nonce, `keccak256(abi.encode(channelId, salt))`: H in the scheme's
 * refund-authorizer mode, an option whose `extra.voucherManager` is `"facilitator"` and whose `extra.refundAuthorizer` is
 * an address other than the zero address (the protocol package's `x402-batch-settlement-eip155` profile, rule 7), and
 * otherwise the choice's `authSalt`.
 */
function depositSalt(choice: unknown, h: AtrHash): unknown {
  const c = isObject(choice) ? choice : {};
  const accepted = c["accepted"];
  const extra = isObject(accepted) && isObject(accepted["extra"]) ? accepted["extra"] : {};
  const ra = extra["refundAuthorizer"];
  const mode = extra["voucherManager"] === "facilitator" && typeof ra === "string" && EVM_ADDRESS.test(ra) && !ZERO_ADDRESS.test(ra);
  return mode ? h : c["authSalt"];
}

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
  async build(choice: unknown, h: AtrHash): Promise<unknown> {
    const u = await batchEvm.build(choice as never, h);
    return isRefusal(u) ? u : { ...u, authSalt: depositSalt(choice, h) };
  },
  /** The build's two requests as one `batch` request, with the channel's `config` and the deposit's `authSalt`. */
  request(unsigned: unknown): SigningRequest {
    const u = unsigned as BatchUnsigned & { authSalt?: unknown };
    const config = u.config === undefined ? {} : { config: { ...u.config } };
    const authSalt = typeof u.authSalt === "string" ? { authSalt: u.authSalt } : {};
    return { kind: "batch", requests: u.requests, ...config, ...authSalt };
  },
  complete: batchComplete,
});
