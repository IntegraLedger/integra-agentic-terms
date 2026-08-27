import { describe, expect, it } from "vitest";
import {
  type Disposition,
  decideOutcome,
  foldDispositions,
  type StepStatus,
} from "../src/decision.js";

const proceedOnGaps = {
  onIndeterminate: "escalate" as Disposition,
  onNotAttempted: "decline" as Disposition,
};

describe("decideOutcome — total four-valued map, gaps never silently proceed", () => {
  it("proved → proceed", () =>
    expect(decideOutcome("proved", proceedOnGaps)).toBe("proceed"));
  it("failed → decline", () =>
    expect(decideOutcome("failed", proceedOnGaps)).toBe("decline"));
  it("indeterminate → the stated policy disposition", () =>
    expect(decideOutcome("indeterminate", proceedOnGaps)).toBe("escalate"));
  it("not-attempted → the stated policy disposition", () =>
    expect(decideOutcome("not-attempted", proceedOnGaps)).toBe("decline"));
  it("a policy can never turn a failed step into proceed", () =>
    expect(
      decideOutcome("failed", {
        onIndeterminate: "proceed",
        onNotAttempted: "proceed",
      }),
    ).toBe("decline"));

  // The two gap statuses read DIFFERENT policy fields. Without this, swapping the two reads is invisible:
  // every other case in this file happens to give them the same answer or exercises only one of them.
  it("reads onIndeterminate and onNotAttempted from their own fields, not each other's", () => {
    const gaps = {
      onIndeterminate: "proceed" as Disposition,
      onNotAttempted: "decline" as Disposition,
    };
    expect(decideOutcome("indeterminate", gaps)).toBe("proceed");
    expect(decideOutcome("not-attempted", gaps)).toBe("decline");
  });

  it("proved ignores the gap policy entirely", () => {
    // `proved` must not be routed through either stated disposition — pins the case arm, not just the value.
    expect(
      decideOutcome("proved", {
        onIndeterminate: "decline",
        onNotAttempted: "decline",
      }),
    ).toBe("proceed");
  });

  it.each<[StepStatus, Disposition]>([
    ["proved", "proceed"],
    ["failed", "decline"],
    ["indeterminate", "escalate"],
    ["not-attempted", "decline"],
  ])("is total over StepStatus: %s", (status, expected) => {
    expect(decideOutcome(status, proceedOnGaps)).toBe(expected);
  });
});

/**
 * `foldDispositions` is the gate's Decline-dominant rule — the single safety property that makes a
 * many-step evaluation trustworthy: one failing step must sink the whole decision no matter what any other
 * step said, and an escalation must never be downgraded to a proceed by a majority of proceeds. Precedence
 * is the whole content of the function, so these are written as precedence pairs rather than one case per
 * input.
 */
describe("foldDispositions — decline dominates, then escalate, then proceed", () => {
  it("an empty fold proceeds (nothing objected)", () =>
    expect(foldDispositions([])).toBe("proceed"));

  it("all-proceed folds to proceed", () =>
    expect(foldDispositions(["proceed", "proceed", "proceed"])).toBe(
      "proceed",
    ));

  it("a single decline sinks a fold of otherwise-proceeds", () =>
    expect(foldDispositions(["proceed", "proceed", "decline"])).toBe(
      "decline",
    ));

  it("a single escalate lifts a fold of otherwise-proceeds", () =>
    expect(foldDispositions(["proceed", "escalate", "proceed"])).toBe(
      "escalate",
    ));

  it("decline beats escalate regardless of order", () => {
    // Both orders, because a fold that short-circuits on first-seen rather than by precedence passes one
    // and fails the other — and first-seen is the plausible wrong implementation.
    expect(foldDispositions(["escalate", "decline"])).toBe("decline");
    expect(foldDispositions(["decline", "escalate"])).toBe("decline");
  });

  it("decline beats every combination it appears in", () => {
    expect(
      foldDispositions(["proceed", "escalate", "decline", "proceed"]),
    ).toBe("decline");
    expect(foldDispositions(["decline"])).toBe("decline");
  });

  it("escalate beats proceed regardless of order", () => {
    expect(foldDispositions(["escalate", "proceed"])).toBe("escalate");
    expect(foldDispositions(["proceed", "escalate"])).toBe("escalate");
  });

  it("a lone escalate does not become a decline", () =>
    expect(foldDispositions(["escalate"])).toBe("escalate"));

  it("a lone proceed stays a proceed", () =>
    expect(foldDispositions(["proceed"])).toBe("proceed"));

  it("repetition changes nothing — this is precedence, not a tally", () => {
    // Ten proceeds cannot outvote one decline. Pins that the fold is not counting.
    const many: Disposition[] = Array.from({ length: 10 }, () => "proceed");
    expect(foldDispositions([...many, "decline"])).toBe("decline");
    expect(foldDispositions([...many, "escalate"])).toBe("escalate");
  });
});
