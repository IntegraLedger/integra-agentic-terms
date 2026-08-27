import type { HaltClass } from "@integraledger/lcp-binding-core";
import {
  type LegalContextJson,
  parseLegalContextJson,
} from "@integraledger/lcp-discovery";
import { hashAtr } from "@integraledger/lcp-kernel";
import type { GateDecision } from "./decision.js";
import type { TermsFetcher } from "./fetch.js";
import { recomputeAndCompare } from "./fingerprint.js";
import type { Orc4Log } from "./log.js";
import { type BuyerPolicy, evaluatePolicy } from "./policy.js";
import type { GateProposal } from "./proposal.js";

export interface GatePorts {
  readonly fetcher: TermsFetcher;
  readonly now: () => string;
  readonly log?: Orc4Log;
}

/** The gate orchestration: fetch+retain (LCP §5.4) → level floor (LCP §4.2) → fingerprint HALT (LCP §5.3) → policy on the
 *  TYPED envelope only (LCP §12.7) → coverage-gap disposition → assurance → Proceed. The signing key is NEVER
 *  touched here — this returns a decision that `transact` enforces against the guarded signer. */
export async function evaluate(
  proposal: GateProposal,
  policy: BuyerPolicy,
  ports: GatePorts,
): Promise<GateDecision> {
  const at = ports.now();
  const decline = (
    haltClass: HaltClass,
    code: string,
    detail: string,
  ): GateDecision => {
    ports.log?.append({
      timestamp: at,
      decision: "decline",
      haltClass,
      code,
      detail,
      atrHash: proposal.advertisedAtrHash,
      legalContextUrl: proposal.legalContextUrl,
    });
    return { kind: "decline", haltClass, code, detail };
  };

  // LCP §5.4: ALWAYS fetch + retain the terms as evidence, even at Level 1 (a policy decision, never a silent skip).
  //
  // The fetch is CAUGHT because a counterparty must not be able to make this function THROW. Every failure
  // the shipped fetcher raises is counterparty-reachable — a 404 or a TLS error on a URL the seller chose, a
  // body over the cap on a document the seller serves, a host the seller published that resolves to a private
  // address and trips the SSRF guard. Each has to arrive as a value the buyer can act on: the ORC-4 log
  // records the most common counterparty failure there is, the caller gets the `haltClass`/`code` pair every
  // other refusal here is a value of, and the Decline taxonomy — the seam a seller's integration is measured
  // against — names "your terms document did not serve".
  //
  // A throw would fail closed, since the signer is unreachable on any path that does not reach a Proceed. But
  // failing closed is not the same as failing WELL, and this package's own SECURITY.md names that difference
  // as a defect rather than as acceptable behaviour.
  //
  // `verification-failure`, not `policy-rejection`: no policy of the buyer's rejected anything. The terms
  // could not be obtained, so the fingerprint could not be recomputed, so the guard cannot say the document
  // is the one that was advertised — which is the same thing a mismatch says, arrived at one step earlier.
  let fetched: Awaited<ReturnType<typeof ports.fetcher.fetch>>;
  try {
    fetched = await ports.fetcher.fetch(proposal.legalContextUrl);
  } catch (cause) {
    // The fetcher's own message names the cause precisely — the status, the cap, the resolved address that
    // failed the unicast check — and it is the seller's defect, so it is carried through verbatim rather
    // than flattened into "fetch failed". A buyer that cannot see WHICH failure it was cannot report it.
    return decline(
      "verification-failure",
      "gate/terms-unfetchable",
      `could not fetch the advertised terms at ${proposal.legalContextUrl}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  // LCP §4.2: the buyer's stated trust-level floor. Level 1 is a policy decision (requiredLevel), never a default.
  if (proposal.level < policy.requiredLevel)
    return decline(
      "policy-rejection",
      "gate/below-required-level",
      `service level ${proposal.level} is below the buyer's required level ${policy.requiredLevel}`,
    );

  // Verify before sign (LCP §5.3): recompute the fingerprint over the fetched bytes vs the advertised atrHash — a mismatch HALTS before
  // any signing key. Every GateProposal carries a validated advertisedAtrHash, so verification is ALWAYS run
  // (verify-whenever-present; skipping a present, verifiable hash would be a silent fail-open).
  const fp = await recomputeAndCompare(
    fetched.bytes,
    proposal.advertisedAtrHash,
  );
  if (fp.status === "failed")
    return decline(
      "verification-failure",
      "gate/fingerprint-mismatch",
      `recomputed fingerprint ${fp.recomputed} ≠ advertised ${fp.advertised} — HALTING before sign (LCP §5.3)`,
    );

  // The seller-assurance floor (IDN-3) is a counterparty-trust dimension INDEPENDENT of the terms FORMAT —
  // it gates EVERY proceed path, so it is checked here, before the typed/coverage-gap branch. A buyer that
  // tolerates non-machine-readable terms (onNotAttempted) must NOT thereby lose their assurance floor.
  if (
    policy.requiredAssurance !== "any" &&
    proposal.sellerAssurance !== policy.requiredAssurance
  )
    return decline(
      "policy-rejection",
      "gate/assurance",
      `seller assurance ${proposal.sellerAssurance} below required ${policy.requiredAssurance}`,
    );

  // Policy on the TYPED envelope only (never the prose bytes) — LCP §12.7. parseLegalContextJson takes a PARSED
  // object and THROWS on a non-conformant record, so a non-machine-readable body is a CAUGHT coverage gap the
  // buyer's STATED onNotAttempted disposition decides — never a silent proceed.
  let typed: LegalContextJson | undefined;
  try {
    typed = parseLegalContextJson(
      JSON.parse(new TextDecoder().decode(fetched.bytes)),
    );
  } catch {
    typed = undefined;
  }
  if (typed === undefined) {
    const disp = policy.onNotAttempted; // non-machine-readable record → coverage gap; buyer's STATED disposition
    if (disp === "decline")
      return decline(
        "policy-rejection",
        "gate/unparseable-terms",
        "terms are not machine-readable legal-context JSON",
      );
    if (disp === "escalate")
      return escalate(
        fetched.bytes,
        at,
        "terms not machine-readable — escalating per policy",
        ports,
        proposal,
      );
    // disp === "proceed": a STATED election to proceed without a typed record (the policy's call, not a default).
  } else {
    const pr = evaluatePolicy(policy, typed, proposal.offer);
    // A hard ATA-2 violation is a Decline (policy-rejection); the escalate lane is for coverage gaps, not forbidden terms.
    if (!pr.ok) return decline("policy-rejection", pr.code, pr.detail);
  }

  ports.log?.append({
    timestamp: at,
    decision: "proceed",
    code: "gate/proceed",
    detail: "verified + in policy",
    atrHash: proposal.advertisedAtrHash,
    legalContextUrl: proposal.legalContextUrl,
  });
  return { kind: "proceed" };
}

/** Escalate binds a display-equals-signed hash: `hash === sha256(bytes)` and `bytes` are the EXACT displayed
 *  terms an approver signs (LCP §12.7 MUST). */
async function escalate(
  bytes: Uint8Array,
  at: string,
  reason: string,
  ports: GatePorts,
  proposal: GateProposal,
): Promise<GateDecision> {
  const hash = await hashAtr(bytes);
  ports.log?.append({
    timestamp: at,
    decision: "escalate",
    code: "gate/escalate",
    detail: reason,
    atrHash: proposal.advertisedAtrHash,
    legalContextUrl: proposal.legalContextUrl,
  });
  return { kind: "escalate", bytes, hash, reason };
}
