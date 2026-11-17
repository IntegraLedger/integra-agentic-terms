/**
 * The buyer piece for `ucp/checkout/agent-signed`: the build input is the offer `read` gives, `{checkout}`. The protocol
 * package's build gives the `legal_context` member, `{type: "sha256", value: H}`, once the checkout's `legal_context`
 * link carries H. The platform's signer is handed that member exactly as built, beside the checkout its request
 * completes: it writes the member at the top level of the JSON body of the request that completes the checkout,
 * signs the request with HTTP Message Signatures (RFC 9421) covering `content-digest`, as UCP has a platform sign its
 * requests, and answers `{body, contentDigest}`, the body as sent, as text, and its `Content-Digest` value.
 */
import { agentSigned, type AgentSignedPresented, type AgentSignedUnsigned, type Checkout } from "@integraledger/lcp/ucp";
import type { AtrHash, Refusal } from "@integraledger/lcp/core";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { isObject, isRefusal, refuse } from "./common.js";
import { objectChoice } from "./protocol-groups.js";
import { chooseCheckout } from "./ucp.js";

const PAIRING = "ucp/checkout/agent-signed";

/** The member the protocol package builds, with the checkout the platform's request completes. */
interface Built {
  readonly checkout: Checkout;
  readonly member: AgentSignedUnsigned;
}

export const ucpCheckoutAgentSigned: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const choice = chooseCheckout(read, account, inputs, now, ref);
    if (isRefusal(choice)) return choice;
    return { pairing: PAIRING, choice, ref };
  },
  choice: (chosen: Chosen) => objectChoice(chosen, "ucp"),
  async build(choice: unknown, h: AtrHash): Promise<Built | Refusal> {
    const member = await agentSigned.build(choice as { checkout: Checkout }, h);
    if (isRefusal(member)) return member;
    return { checkout: (choice as { checkout: Checkout }).checkout, member };
  },
  request: (unsigned: unknown): SigningRequest => {
    const { checkout, member } = unsigned as Built;
    return { kind: "ucp-legal-context", checkout, legal_context: member.legal_context };
  },
  async complete(_unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
    if (!isObject(signature) || Object.keys(signature).length !== 2) return refuse("ucp/signature-malformed");
    const { body, contentDigest } = signature;
    if (typeof body !== "string" || typeof contentDigest !== "string") return refuse("ucp/signature-malformed");
    const presented: AgentSignedPresented = { body, contentDigest };
    return presented;
  },
});
