import type { GateDecision } from "./decision.js";
import { evaluate, type GatePorts } from "./evaluate.js";
import type { BuyerPolicy } from "./policy.js";
import type { GateProposal } from "./proposal.js";

/** A signer the gate invokes ONLY on Proceed. The gate binds the atrHash it verified; the signer signs THROUGH
 *  an authority artifact (the grant/acceptance) by its own contract, never a bare hash. On Decline/Escalate the
 *  signer is never called — the key is structurally gated (the "before any signing key is invoked" guarantee). */
export interface GatedSigner {
  sign(
    verifiedAtrHash: `0x${string}`,
  ): Promise<{ readonly signature: `0x${string}` }>;
}
export type TransactResult =
  | {
      readonly kind: "signed";
      readonly signature: `0x${string}`;
      readonly atrHash: `0x${string}`;
    }
  | { readonly kind: "halted"; readonly decision: GateDecision };

/** Verify-before-sign as a type + a runtime gate: evaluate the proposal, and invoke the signing key ONLY when
 *  the decision is Proceed. On Decline/Escalate the signer is never reached (LCP §5.3), by construction. */
export async function transact(
  proposal: GateProposal,
  policy: BuyerPolicy,
  ports: GatePorts,
  signer: GatedSigner,
): Promise<TransactResult> {
  const decision = await evaluate(proposal, policy, ports);
  if (decision.kind !== "proceed") return { kind: "halted", decision };
  const { signature } = await signer.sign(proposal.advertisedAtrHash);
  return { kind: "signed", signature, atrHash: proposal.advertisedAtrHash };
}
