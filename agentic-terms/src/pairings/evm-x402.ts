/**
 * The buyer piece shared by the x402 pairings on EVM: the first option on the signer's chain, the typed data or
 * delegation request exactly as built, and the payment the answer completes, with the payment identifier appended
 * where the challenge advertises it.
 */
import type { Refusal } from "@integraledger/lcp";
import type { Hex } from "@integraledger/lcp/evm";
import type { PaymentPayload, Unsigned, X402Unsigned } from "@integraledger/lcp/x402";
import type { BuyerPiece, Chosen, Presented, Read, Signature, SigningRequest } from "../types.js";
import { choiceOf, firstOption, isObject, refuse, withPaymentIdentifier, x402Chosen } from "./common.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

type Built = Unsigned | X402Unsigned;

/** An EIP-712 signing request, from either form of an EVM x402 build. */
function request(unsigned: unknown): SigningRequest | Refusal {
  const u = unsigned as Built;
  if ("typedData" in u) return { kind: "eip712", typedData: u.typedData };
  return u.request;
}

async function complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
  const u = unsigned as Built;
  let signed: PaymentPayload | Refusal;
  if ("typedData" in u || u.request.kind === "eip712") {
    if (typeof signature !== "string") return refuse("x402/signature-malformed");
    signed = (u as { complete(s: Hex): PaymentPayload | Refusal }).complete(signature as Hex);
  } else {
    if (!isObject(signature)) return refuse("x402/signature-malformed");
    const { delegationManager, permissionContext, delegator } = signature;
    if (typeof delegationManager !== "string" || typeof permissionContext !== "string" || typeof delegator !== "string") {
      return refuse("x402/signature-malformed");
    }
    const delegated = u as Extract<X402Unsigned, { request: { kind: "erc7710" } }>;
    signed = delegated.complete({
      delegationManager: delegationManager as Hex,
      permissionContext: permissionContext as Hex,
      delegator: delegator as Hex,
    });
  }
  if ("refused" in signed) return signed;
  return withPaymentIdentifier(signed, choiceOf(chosen)?.["required"], chosen.ref);
}

/** The buyer piece for one x402 EVM pairing. */
export function evmX402Piece(pairing: string): BuyerPiece {
  return Object.freeze({
    choose(read: Read, account: string, _inputs: unknown, now: number, ref: string): Chosen | Refusal {
      const o = firstOption(read, account, "eip155", pairing, EVM_ADDRESS);
      if ("refused" in o) return refuse("x402/no-payable-option");
      return x402Chosen(pairing, { required: o.required, accepted: o.accepted, from: o.address, now }, ref);
    },
    choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
    request,
    complete,
  });
}
