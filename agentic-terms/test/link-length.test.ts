// An agreement URL is bounded at 2048 UTF-16 code units, as String.prototype.length counts them. A document whose
// agreement URL is 2049 UTF-16 code units, and fewer code points, is declined at the read, before any fetch, by this
// gate and by the Python gate (test_eip3009_field_rules.py). The option, hash and resource are
// x402-exact-eip155-eip3009.json's.
import { describe, expect, it } from "vitest";
import { exactEip3009, type PaymentRequirements } from "@integraledger/lcp/x402";
import { confirm } from "../src/index.js";
import { ABC, serving, vectors } from "./support.js";

const X = vectors<{ fixed: { H: string; O: PaymentRequirements; resource: { url: string }; payer: string } }>(
  "x402-exact-eip155-eip3009.json",
).fixed;
const LONG_AGREEMENT = "https://api.seller.example/agreement/" + "\u{1F600}".repeat(1006);

describe("an agreement URL over 2048 UTF-16 code units", () => {
  it("is 2049 UTF-16 code units and fewer code points", () => {
    expect(LONG_AGREEMENT.length).toBe(2049);
    expect([...LONG_AGREEMENT].length).toBeLessThan(2048);
  });

  it("is declined offer-unreadable, x402/legal-context-malformed, with no fetch", async () => {
    const doc = {
      x402Version: 2,
      resource: X.resource,
      accepts: [X.O],
      extensions: {
        legalContext: {
          info: {
            type: "sha256",
            value: X.H,
            legalContextUrl: `https://atr.seller.example/${X.H}`,
            legalContextAgreementUrl: LONG_AGREEMENT,
          },
        },
      },
    };
    const f = serving(ABC);
    expect(await confirm(doc, exactEip3009, `eip155:84532:${X.payer}`, f)).toEqual({
      decline: { code: "offer-unreadable", detail: "x402/legal-context-malformed" },
    });
    expect(f.calls).toBe(0);
  });
});
