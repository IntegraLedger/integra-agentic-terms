import type { Assurance } from "@integraledger/lcp-authority";
import { hashAtr } from "@integraledger/lcp-kernel";
import { describe, expect, it } from "vitest";
import type { FetchedTerms, TermsFetcher } from "../src/fetch.js";
import type { BuyerPolicy } from "../src/policy.js";
import type { GateProposal } from "../src/proposal.js";
import { type GatedSigner, transact } from "../src/transact.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
function fixedFetcher(
  bytes: Uint8Array,
  format = "application/json",
): TermsFetcher {
  return {
    async fetch(_u: string): Promise<FetchedTerms> {
      return { bytes, format, fetchedAt: "t" };
    },
  };
}
const policy: BuyerPolicy = {
  requiredLevel: 2,
  acceptableJurisdictions: ["US-NY"],
  acceptableDisputeMethods: ["arbitration"],
  maxCommitment: { "base-sepolia:0xUSDC": "1000000" },
  forbiddenClauseCategories: [],
  requiredAssurance: "wallet-signature-only",
  onNotAttempted: "decline",
};
const termsJson = JSON.stringify({
  terms: "https://s.example/body",
  disputeResolution: { jurisdiction: "US-NY", method: "arbitration" },
});
async function proposalFor(bytes: Uint8Array): Promise<GateProposal> {
  return {
    advertisedAtrHash: await hashAtr(bytes),
    legalContextUrl: "https://s.example/terms",
    level: 2,
    offer: {
      amount: "1000",
      unit: "base-sepolia:0xUSDC",
    },
    sellerAssurance: "wallet-signature-only" as Assurance,
  };
}
const now = (): string => "t";

describe("transact — the signer is invoked ONLY on Proceed (verify-before-sign, LCP §5.3)", () => {
  it("a Decline never invokes the signing key; a Proceed invokes it exactly once", async () => {
    let signCalls = 0;
    const signer: GatedSigner = {
      async sign(_h: `0x${string}`) {
        signCalls++;
        return { signature: "0xsig" as const };
      },
    };
    const goodBytes = enc(termsJson);
    const good = await proposalFor(goodBytes);

    // Decline: fetcher serves TAMPERED bytes → fingerprint mismatch → evaluate declines → halted, NO sign call.
    const declined = await transact(
      good,
      policy,
      { fetcher: fixedFetcher(enc(`TAMPERED ${termsJson}`)), now },
      signer,
    );
    expect(declined.kind).toBe("halted");
    expect(signCalls).toBe(0);

    // Proceed: fetcher serves the matching valid terms → evaluate proceeds → signer called once.
    const ok = await transact(
      good,
      policy,
      { fetcher: fixedFetcher(goodBytes), now },
      signer,
    );
    expect(ok.kind).toBe("signed");
    if (ok.kind === "signed") expect(ok.atrHash).toBe(good.advertisedAtrHash);
    expect(signCalls).toBe(1);
  });
});
