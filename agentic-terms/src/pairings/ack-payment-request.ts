/**
 * The buyer piece for `ack/payment-request`: ACK defines no payer signature, so the gate confirms only. The option to
 * pay is the first of the signed request's payment options, in order, whose `network` is the account's CAIP-2.
 */
import type { Json } from "@integraledger/lcp";
import type { Inputs, Read } from "../types.js";
import { accountOf, isObject, refuse } from "./common.js";
import { confirmOnlyPiece } from "./protocol-groups.js";

export const ackPaymentRequest = confirmOnlyPiece("ack/payment-request", (read: Read, account: string, _inputs: Inputs) => {
  const a = accountOf(account);
  const options = isObject(read.offer) ? read.offer["options"] : undefined;
  if (a === undefined || !Array.isArray(options)) return refuse("ack/no-payable-option");
  const option: unknown = options.find((o: unknown) => isObject(o) && o["network"] === a.network);
  if (option === undefined) return refuse("ack/no-payable-option");
  return { option: option as Json };
});
