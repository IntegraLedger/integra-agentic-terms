/**
 * The buyer piece for `acp/checkout/delegated`. The build input is the session `read` gives and the buyer's own
 * allowance values, as inputs: `max_amount` (minor units), `currency`, `merchant_id` and `expires_at`. The allowance
 * goes to the agent, which answers the `delegate_payment` request it signed, as an object.
 */
import type { Refusal } from "@integraledger/lcp";
import type { Presented as AcpPresented, Unsigned } from "@integraledger/lcp/acp";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { objectChoice, unnamedBuyer } from "./protocol-groups.js";

const PAIRING = "acp/checkout/delegated";
const ALLOWANCE_INPUTS = { max_amount: "uint", currency: "string", merchant_id: "string", expires_at: "string" } as const;

export const acpCheckoutDelegated: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, _now: number, ref: string): Chosen | Refusal {
    const unnamed = unnamedBuyer(account, "acp");
    if (unnamed !== undefined) return unnamed;
    const session = isObject(read.offer) ? read.offer["session"] : undefined;
    if (!isObject(session)) return refuse("acp/no-payable-option");
    const values = inputsOf(inputs, PAIRING, ALLOWANCE_INPUTS);
    if (isRefusal(values)) return values;
    return { pairing: PAIRING, choice: { session: session as Chosen["choice"], ...values }, ref };
  },
  choice: (chosen: Chosen) => objectChoice(chosen, "acp"),
  request: (unsigned: unknown): SigningRequest => ({
    kind: "acp-allowance",
    allowance: (unsigned as Unsigned).allowance,
  }),
  async complete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
    if (!isObject(signature)) return refuse("acp/signature-malformed");
    return (unsigned as Unsigned).complete(signature as AcpPresented);
  },
});
