// What the gate reads as a refusal: a value the protocol package made (its root `isRefusal`, which recognises only the
// refusals it made) or one the gate made. A value shaped `{ refused: true, code }` that neither made is data, as
// @integraledger/lcp 0.2.0's `isRefusal` states: "A caller's value shaped { refused: true, … } is not a refusal".
import { describe, expect, it } from "vitest";
import { canonicalJson, isRefusal as isLcpRefusal } from "@integraledger/lcp";
import { isRefusal, refuse } from "../src/pairings/common.js";

describe("the gate's refusals", () => {
  it("a refusal the protocol package made is one, and so is one the gate made", () => {
    // `canonicalJson` refuses a value that is not JSON, such as a non-finite number (RFC 8785 section 3.2.2.3).
    const made = canonicalJson(Number.NaN);
    expect(isLcpRefusal(made)).toBe(true);
    expect(isRefusal(made)).toBe(true);
    expect(isRefusal(refuse("x402/no-payable-option"))).toBe(true);
  });

  it("a value shaped like a refusal that neither made is not one", () => {
    for (const v of [{ refused: true, code: "x402/no-payable-option" }, JSON.parse('{"refused":true,"code":"mpp/x"}')]) {
      expect(isLcpRefusal(v)).toBe(false);
      expect(isRefusal(v)).toBe(false);
    }
  });
});
