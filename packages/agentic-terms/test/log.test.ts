import { describe, expect, it } from "vitest";
import { InMemoryOrc4Log, type Orc4Entry } from "../src/log.js";

describe("InMemoryOrc4Log — a real ORC-4 sink (not a mock)", () => {
  it("appends a decline entry with its FRC-3 halt class", () => {
    const log = new InMemoryOrc4Log();
    const e: Orc4Entry = {
      timestamp: "2025-10-09T00:00:00Z",
      decision: "decline",
      haltClass: "verification-failure",
      code: "gate/fingerprint-mismatch",
      detail: "recomputed ≠ advertised",
      atrHash: "0xabc",
    };
    log.append(e);
    expect(log.entries).toHaveLength(1);
    expect(log.entries[0]).toEqual(e);
    expect(log.entries[0]?.haltClass).toBe("verification-failure");
  });
  it("records proceed and escalate entries in order (no haltClass)", () => {
    const log = new InMemoryOrc4Log();
    log.append({
      timestamp: "t1",
      decision: "proceed",
      code: "gate/proceed",
      detail: "ok",
    });
    log.append({
      timestamp: "t2",
      decision: "escalate",
      code: "gate/escalate",
      detail: "review",
    });
    expect(log.entries.map((x) => x.decision)).toEqual(["proceed", "escalate"]);
  });
});
