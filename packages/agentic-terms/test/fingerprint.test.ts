import { hashAtr } from "@integraledger/lcp-kernel";
import { describe, expect, it } from "vitest";
import { recomputeAndCompare } from "../src/fingerprint.js";

describe("recomputeAndCompare — the halt-before-sign fingerprint (LCP §5.3)", () => {
  it("proved when the recomputed fingerprint equals the advertised atrHash", async () => {
    const bytes = new TextEncoder().encode("# Terms\n");
    const advertised = await hashAtr(bytes);
    expect((await recomputeAndCompare(bytes, advertised)).status).toBe(
      "proved",
    );
  });
  it("failed (verification-failure) when the bytes do not hash to the advertised atrHash — HALT", async () => {
    const advertised = await hashAtr(new TextEncoder().encode("real terms"));
    const tampered = new TextEncoder().encode("swapped terms");
    const r = await recomputeAndCompare(tampered, advertised);
    expect(r.status).toBe("failed");
    if (r.status === "failed") expect(r.haltClass).toBe("verification-failure");
  });
});
