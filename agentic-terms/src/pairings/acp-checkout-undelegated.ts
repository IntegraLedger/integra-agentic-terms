/** The buyer piece for `acp/checkout/undelegated`: the handler does not delegate, so the gate confirms only. */
import type { Json } from "@integraledger/lcp";
import type { Inputs, Read } from "../types.js";
import { isObject, refuse } from "./common.js";
import { confirmOnlyPiece, unnamedBuyer } from "./protocol-groups.js";

export const acpCheckoutUndelegated = confirmOnlyPiece(
  "acp/checkout/undelegated",
  (read: Read, account: string, _inputs: Inputs) => {
    const unnamed = unnamedBuyer(account, "acp");
    if (unnamed !== undefined) return unnamed;
    const session = isObject(read.offer) ? read.offer["session"] : undefined;
    if (!isObject(session)) return refuse("acp/no-payable-option");
    return { session: session as Json };
  },
);
