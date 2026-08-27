import type { HaltClass } from "@integraledger/lcp-binding-core";
export type StepStatus =
  | "proved"
  | "failed"
  | "indeterminate"
  | "not-attempted";
export type Disposition = "proceed" | "decline" | "escalate";
export type GateDecision =
  | { readonly kind: "proceed" }
  | {
      readonly kind: "decline";
      readonly haltClass: HaltClass;
      readonly code: string;
      readonly detail: string;
    }
  | {
      readonly kind: "escalate";
      readonly bytes: Uint8Array;
      readonly hash: `0x${string}`;
      readonly reason: string;
    };

/** The TOTAL map from a step's four-valued status onto a disposition. `failed` is ALWAYS decline (a policy
 *  can never proceed past a failure). `indeterminate`/`not-attempted` are the buyer's STATED dispositions
 *  (never silent defaults). The switch is exhaustive — the `never` default fails the build if StepStatus grows. */
export function decideOutcome(
  status: StepStatus,
  gaps: {
    readonly onIndeterminate: Disposition;
    readonly onNotAttempted: Disposition;
  },
): Disposition {
  switch (status) {
    case "proved":
      return "proceed";
    case "failed":
      return "decline";
    case "indeterminate":
      return gaps.onIndeterminate;
    case "not-attempted":
      return gaps.onNotAttempted;
    default: {
      const _exhaustive: never = status;
      return _exhaustive;
    }
  }
}

/** Fold per-step dispositions into one: any decline ⇒ Decline-dominant; else any escalate ⇒ Escalate; else proceed. */
export function foldDispositions(ds: readonly Disposition[]): Disposition {
  if (ds.includes("decline")) return "decline";
  if (ds.includes("escalate")) return "escalate";
  return "proceed";
}
