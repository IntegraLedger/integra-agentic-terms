import type { Assurance } from "@integraledger/lcp-authority";
import { hashAtr } from "@integraledger/lcp-kernel";
import { describe, expect, it } from "vitest";
import { evaluate } from "../src/evaluate.js";
import type { FetchedTerms, TermsFetcher } from "../src/fetch.js";
import { InMemoryOrc4Log } from "../src/log.js";
import type { BuyerPolicy } from "../src/policy.js";
import type { GateProposal } from "../src/proposal.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

function fixedFetcher(
  bytes: Uint8Array,
  format = "application/json",
): TermsFetcher & { calls: number } {
  const f = {
    calls: 0,
    async fetch(_url: string): Promise<FetchedTerms> {
      f.calls++;
      return { bytes, format, fetchedAt: "2025-10-09T00:00:00Z" };
    },
  };
  return f;
}

const basePolicy: BuyerPolicy = {
  requiredLevel: 2,
  acceptableJurisdictions: ["US-NY"],
  acceptableDisputeMethods: ["arbitration"],
  maxCommitment: { "base-sepolia:0xUSDC": "1000000" },
  forbiddenClauseCategories: ["class-action-waiver"],
  requiredAssurance: "wallet-signature-only",
  onNotAttempted: "decline",
};

const validTermsJson = JSON.stringify({
  terms: "https://s.example/terms-body",
  disputeResolution: { jurisdiction: "US-NY", method: "arbitration" },
});

async function proposalFor(
  termsBytes: Uint8Array,
  level: 1 | 2 | 3 | 4 = 2,
): Promise<GateProposal> {
  const atrHash = await hashAtr(termsBytes);
  return {
    advertisedAtrHash: atrHash,
    legalContextUrl: "https://s.example/terms",
    level,
    offer: {
      amount: "1000",
      unit: "base-sepolia:0xUSDC",
    },
    sellerAssurance: "wallet-signature-only" as Assurance,
  };
}
const now = (): string => "2025-10-09T00:00:00Z";

describe("evaluate — discover→halt→level→typed-policy→escalate (LCP §12.7/5, LCP §5.4, LCP §12.7)", () => {
  it("in-policy + fingerprint proved → Proceed", async () => {
    const bytes = enc(validTermsJson);
    const proposal = await proposalFor(bytes);
    const d = await evaluate(proposal, basePolicy, {
      fetcher: fixedFetcher(bytes),
      now,
    });
    expect(d.kind).toBe("proceed");
  });

  it("fingerprint mismatch → Decline(verification-failure); terms fetched, no proceed (halt-before-sign)", async () => {
    const proposal = await proposalFor(enc(validTermsJson));
    const fetcher = fixedFetcher(enc(`TAMPERED ${validTermsJson}`));
    const d = await evaluate(proposal, basePolicy, { fetcher, now });
    expect(d.kind).toBe("decline");
    if (d.kind === "decline") expect(d.haltClass).toBe("verification-failure");
    expect(fetcher.calls).toBe(1);
  });

  it("level below requiredLevel → Decline(policy-rejection); terms still fetched+retained (LCP §5.4)", async () => {
    const bytes = enc(validTermsJson);
    const proposal = await proposalFor(bytes, 1);
    const fetcher = fixedFetcher(bytes);
    const d = await evaluate(proposal, basePolicy, { fetcher, now });
    expect(d.kind).toBe("decline");
    if (d.kind === "decline") expect(d.haltClass).toBe("policy-rejection");
    expect(fetcher.calls).toBe(1);
  });

  it("coverage gap (non-JSON terms) + onNotAttempted:escalate → Escalate(bytes,hash), display-equals-signed LCP §12.7", async () => {
    const text = "# Terms\nHuman-readable, not JSON.\n";
    const bytes = enc(text);
    const proposal = await proposalFor(bytes); // hash matches → fingerprint proved; body is non-JSON → coverage gap
    const d = await evaluate(
      proposal,
      { ...basePolicy, onNotAttempted: "escalate" },
      { fetcher: fixedFetcher(bytes, "text/markdown"), now },
    );
    expect(d.kind).toBe("escalate");
    if (d.kind === "escalate") {
      expect(d.hash.toLowerCase()).toBe((await hashAtr(d.bytes)).toLowerCase()); // hash is OF the displayed bytes
      expect(new TextDecoder().decode(d.bytes)).toBe(text); // bytes ARE what was fetched
    }
  });

  it("coverage gap + onNotAttempted:decline → Decline, never Proceed", async () => {
    const bytes = enc("# Terms\nnot json\n");
    const proposal = await proposalFor(bytes);
    const d = await evaluate(
      proposal,
      { ...basePolicy, onNotAttempted: "decline" },
      { fetcher: fixedFetcher(bytes, "text/markdown"), now },
    );
    expect(d.kind).toBe("decline");
    if (d.kind === "decline") expect(d.haltClass).toBe("policy-rejection");
  });

  it("assurance floor gates the coverage-gap proceed path (insufficient assurance Declines even with onNotAttempted:proceed)", async () => {
    const bytes = enc("# Terms\nnot json\n");
    const proposal = await proposalFor(bytes); // fingerprint proves (hash matches); non-JSON body → coverage gap
    const d = await evaluate(
      proposal,
      {
        ...basePolicy,
        onNotAttempted: "proceed",
        requiredAssurance: "legal-party",
      },
      { fetcher: fixedFetcher(bytes, "text/markdown"), now },
    );
    expect(d.kind).toBe("decline");
    if (d.kind === "decline") {
      expect(d.haltClass).toBe("policy-rejection");
      expect(d.code).toBe("gate/assurance");
    }
  });
});

/**
 * THE ACCOUNTABLE LOG — the half of `evaluate` the suite above never read.
 *
 * Every branch calls `ports.log?.append(...)`, and every field of that entry is asserted here. Without
 * these, each `code` and `detail` could be emptied, the whole append block deleted, or the
 * decline/proceed/escalate entries could all claim the same decision, with the suite green throughout.
 * The log is what makes the gate ACCOUNTABLE rather than merely obstructive; an unasserted log is a log
 * nobody has checked exists.
 */
describe("a counterparty cannot make the gate throw", () => {
  // SECURITY.md names this class in its own words: a counterparty-authored document that makes `evaluate`
  // THROW rather than return a decision fails closed, but escapes the accountable log and gives the buyer
  // nothing to act on. Every failure below is one the seller controls — the URL it published, the document
  // it serves, the host that URL resolves to.
  const unfetchable = async (message: string) => {
    // The bytes never arrive, so which document the proposal names does not matter — only that it names one.
    const proposal = await proposalFor(
      enc("irrelevant: the fetch never returns"),
    );
    const log = new InMemoryOrc4Log();
    const decision = await evaluate(proposal, basePolicy, {
      fetcher: {
        fetch: async () => {
          throw new Error(message);
        },
      },
      now,
      log,
    });
    return { decision, entries: log.entries, proposal };
  };

  it.each([
    ["a 404 on the seller's own URL", "terms fetch failed: 404"],
    [
      "a host resolving to a private address (the SSRF guard)",
      "seller.example resolves to a non-public address (127.0.0.1) — refused (SSRF guard)",
    ],
    ["a body over the size cap", "terms body exceeded the 1 MiB cap"],
    ["a TLS failure", "unable to verify the first certificate"],
  ])("declines rather than throwing on %s", async (_label, message) => {
    const { decision } = await unfetchable(message);
    expect(decision.kind).toBe("decline");
    if (decision.kind !== "decline") return;
    expect(decision.code).toBe("gate/terms-unfetchable");
    // NOT `policy-rejection`: no policy of the buyer's rejected anything. The terms could not be obtained,
    // so the fingerprint could not be recomputed, so the guard cannot say the document is the advertised one.
    expect(decision.haltClass).toBe("verification-failure");
    // The fetcher's own message is carried through, because it names WHICH failure it was and that is the
    // only thing a buyer can report to the seller.
    expect(decision.detail).toContain(message);
  });

  it("writes exactly one ORC-4 entry, naming the document it could not read", async () => {
    // The defect this closes: the log recorded NOTHING on the most common counterparty failure there is.
    const { entries, proposal } = await unfetchable("terms fetch failed: 404");
    expect(entries).toHaveLength(1);
    expect(entries[0]?.decision).toBe("decline");
    expect(entries[0]?.code).toBe("gate/terms-unfetchable");
    expect(entries[0]?.legalContextUrl).toBe(proposal.legalContextUrl);
  });

  it("still reaches no signing key — the fix changes the shape of the halt, not whether it halts", async () => {
    const { decision } = await unfetchable("terms fetch failed: 404");
    expect(decision.kind).not.toBe("proceed");
  });
});

describe("evaluate — the ORC-4 entry each decision writes", () => {
  const withLog = async (
    policy: BuyerPolicy,
    termsBytes: Uint8Array,
    level: 1 | 2 | 3 | 4 = 2,
    format = "application/json",
    mutate: (p: GateProposal) => GateProposal = (p) => p,
  ) => {
    const log = new InMemoryOrc4Log();
    const decision = await evaluate(
      mutate(await proposalFor(termsBytes, level)),
      policy,
      { fetcher: fixedFetcher(termsBytes, format), now, log },
    );
    return { decision, entries: log.entries };
  };

  it("a proceed writes exactly one proceed entry, with the injected time and the advertised hash", async () => {
    const bytes = enc(validTermsJson);
    const { decision, entries } = await withLog(basePolicy, bytes);
    expect(decision.kind).toBe("proceed");
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({
      timestamp: "2025-10-09T00:00:00Z",
      decision: "proceed",
      code: "gate/proceed",
      detail: "verified + in policy",
      atrHash: await hashAtr(bytes),
      // The document the decision was reached ABOUT. An entry naming a verdict without its subject cannot
      // be acted on by the party that can fix it — on a mismatch the advertised hash is by construction not
      // the hash of what was served, so the URL is the only handle a reader can refetch.
      legalContextUrl: "https://s.example/terms",
    });
    // A proceed carries NO halt class — a halt class on a proceed would be incoherent in an audit.
    expect(Object.hasOwn(entries[0] ?? {}, "haltClass")).toBe(false);
  });

  it("a below-level decline records policy-rejection and names both levels", async () => {
    const bytes = enc(validTermsJson);
    const { entries } = await withLog(
      { ...basePolicy, requiredLevel: 3 },
      bytes,
      2,
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]?.decision).toBe("decline");
    expect(entries[0]?.haltClass).toBe("policy-rejection");
    expect(entries[0]?.code).toBe("gate/below-required-level");
    expect(entries[0]?.detail).toContain("2");
    expect(entries[0]?.detail).toContain("3");
  });

  it("a fingerprint mismatch records verification-failure, not policy-rejection", async () => {
    // The distinction is the point: a policy rejection is the buyer's choice, a verification failure is the
    // seller's record failing to be what it claimed. Collapsing them would misattribute every drift event.
    const { entries } = await withLog(
      basePolicy,
      enc(validTermsJson),
      2,
      "application/json",
      (p) => ({ ...p, advertisedAtrHash: `0x${"cd".repeat(32)}` }),
    );
    expect(entries[0]?.decision).toBe("decline");
    expect(entries[0]?.haltClass).toBe("verification-failure");
    expect(entries[0]?.code).toBe("gate/fingerprint-mismatch");
    expect(entries[0]?.detail).toMatch(/HALTING before sign/);
  });

  it("an assurance-floor decline records gate/assurance and names the required level", async () => {
    const { entries } = await withLog(
      { ...basePolicy, requiredAssurance: "legal-party" as Assurance },
      enc(validTermsJson),
    );
    expect(entries[0]?.haltClass).toBe("policy-rejection");
    expect(entries[0]?.code).toBe("gate/assurance");
    expect(entries[0]?.detail).toContain("legal-party");
  });

  it("an unparseable-terms decline records gate/unparseable-terms", async () => {
    const { entries } = await withLog(
      { ...basePolicy, onNotAttempted: "decline" },
      enc("not json at all"),
    );
    expect(entries[0]?.haltClass).toBe("policy-rejection");
    expect(entries[0]?.code).toBe("gate/unparseable-terms");
    expect(entries[0]?.detail).toContain("machine-readable");
  });

  it("an escalation writes an escalate entry carrying the reason", async () => {
    const { decision, entries } = await withLog(
      { ...basePolicy, onNotAttempted: "escalate" },
      enc("not json at all"),
    );
    expect(decision.kind).toBe("escalate");
    expect(entries).toHaveLength(1);
    expect(entries[0]?.decision).toBe("escalate");
    expect(entries[0]?.code).toBe("gate/escalate");
    expect(entries[0]?.detail).toContain("machine-readable");
    expect(entries[0]?.timestamp).toBe("2025-10-09T00:00:00Z");
    // No halt class: an escalation is not a halt, it is a hand-off to a human.
    expect(Object.hasOwn(entries[0] ?? {}, "haltClass")).toBe(false);
  });

  it("an ATA-2 policy violation records the policy's OWN code, not a generic one", async () => {
    // evaluatePolicy's code is forwarded verbatim so the log says which clause failed.
    const bytes = enc(
      JSON.stringify({
        terms: "https://s.example/terms-body",
        disputeResolution: { jurisdiction: "XX", method: "arbitration" },
      }),
    );
    const { entries } = await withLog(basePolicy, bytes);
    expect(entries[0]?.decision).toBe("decline");
    expect(entries[0]?.haltClass).toBe("policy-rejection");
    expect(entries[0]?.code).toBe("policy/jurisdiction");
  });

  it("evaluate works with no log injected at all — the sink is optional, not required", async () => {
    const bytes = enc(validTermsJson);
    const decision = await evaluate(await proposalFor(bytes), basePolicy, {
      fetcher: fixedFetcher(bytes),
      now,
    });
    expect(decision.kind).toBe("proceed");
  });
});

describe("evaluate — branches the decision tests did not reach", () => {
  it('requiredAssurance "any" waives the floor entirely', async () => {
    // The `!== "any"` guard short-circuits before the comparison; without this the guard could be deleted
    // and every "any" policy would start enforcing whatever the seller happened to state.
    const bytes = enc(validTermsJson);
    const decision = await evaluate(
      {
        ...(await proposalFor(bytes)),
        sellerAssurance: "unattested" as Assurance,
      },
      { ...basePolicy, requiredAssurance: "any" },
      { fetcher: fixedFetcher(bytes), now },
    );
    expect(decision.kind).toBe("proceed");
  });

  it("onNotAttempted:proceed is a STATED election — unparseable terms still proceed", async () => {
    // The third disposition. It must reach the proceed path and log a proceed,
    // not fall through to a decline or an escalate.
    const log = new InMemoryOrc4Log();
    const bytes = enc("not json at all");
    const decision = await evaluate(
      await proposalFor(bytes),
      { ...basePolicy, onNotAttempted: "proceed" },
      { fetcher: fixedFetcher(bytes), now, log },
    );
    expect(decision.kind).toBe("proceed");
    expect(log.entries[0]?.decision).toBe("proceed");
    expect(log.entries[0]?.code).toBe("gate/proceed");
  });

  it("the assurance floor is checked BEFORE the typed/coverage-gap branch", async () => {
    // Stated in the source as load-bearing: a buyer who tolerates non-machine-readable terms must not
    // thereby lose their assurance floor. Unparseable terms + onNotAttempted:proceed + wrong assurance
    // must still decline on assurance.
    const bytes = enc("not json at all");
    const log = new InMemoryOrc4Log();
    const decision = await evaluate(
      {
        ...(await proposalFor(bytes)),
        sellerAssurance: "unattested" as Assurance,
      },
      { ...basePolicy, onNotAttempted: "proceed" },
      { fetcher: fixedFetcher(bytes), now, log },
    );
    expect(decision.kind).toBe("decline");
    expect(log.entries[0]?.code).toBe("gate/assurance");
  });

  it("the escalation's hash is sha256 of the EXACT bytes handed back (LCP §12.7 display-equals-signed)", async () => {
    const bytes = enc("not json at all");
    const decision = await evaluate(
      await proposalFor(bytes),
      { ...basePolicy, onNotAttempted: "escalate" },
      { fetcher: fixedFetcher(bytes), now },
    );
    if (decision.kind !== "escalate") throw new Error("expected an escalation");
    expect(decision.bytes).toEqual(bytes);
    expect(decision.hash).toBe(await hashAtr(decision.bytes));
  });
});
