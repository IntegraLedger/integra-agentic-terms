/**
 * Drive the gate's whole decision on whatever runtime is executing this file.
 *
 * WHY THIS IS NOT A TEST. The suite runs under Vitest on Node, which is exactly one of the four rows in
 * `packages/agentic-terms/README.md`'s runtime table — and `AGENTS.md` says the claims in that table are
 * ENFORCED claims. They were not. The table asserted that this package works on Bun and Deno because the
 * import graph says it should: the one Node built-in that arrives, `node:crypto`, is polyfilled there. That
 * is a sound argument and it is still an argument. This file is the measurement.
 *
 * So it deliberately uses NO test framework — a framework is a dependency with its own runtime support
 * matrix, and running Vitest under Bun would measure Vitest's Bun support as much as ours. Plain ESM, plain
 * `globalThis.crypto`, one process, exit code 0 or 1. Anything that can execute an ES module can run it.
 *
 * WHAT IT ASSERTS is both halves of the guarantee, because only asserting the halt would pass on a runtime
 * where the gate is broken in the direction of refusing everything:
 *
 *   tampered terms -> halted, and the signer is NEVER reached
 *   matching terms -> signed, and the signer is reached EXACTLY once
 *
 * The signer counts its own invocations, so "never reached" is a measurement rather than an inference from
 * the returned kind.
 *
 * ⛔⛔ AND THE TAMPER MUST STAY A VALID, POLICY-CLEAN DOCUMENT, OR THIS FILE MEASURES NOTHING IT CLAIMS.
 * `M` 2026-09-14: the tamper here was `TAMPERED ${termsJson}`, which is not JSON. Driven against a build
 * whose fingerprint comparison was replaced by `return true` — verify-before-sign fully disabled — this
 * file still reported **6/6 on Node**, because the body halted at `gate/unparseable-terms` long after the
 * check that was supposed to stop it had waved it through. On the same planted build a tamper of ONE
 * TRAILING SPACE was **signed**.
 *
 * ⇒ A tamper that breaks something ELSE about the document is a tamper any number of unrelated refusals
 * can catch, and the assertion then passes without the exercise ever happening. The tamper below changes
 * the bytes and NOTHING else: same shape, same jurisdiction, same method, so the only thing in the gate
 * that can object to it is the digest.
 *
 * ⭐ AND THE HALT'S REASON IS ASSERTED, not just the halt. `decision.code` must be
 * `gate/fingerprint-mismatch`. That is what separates "the gate stopped it" from "the gate stopped it for
 * the reason this package exists" — and it is the assertion the planted build fails.
 *
 * ⚠️ The unparseable body is kept as its own case, labelled for what it actually is. It was a real
 * property being asserted under the wrong name, and deleting it would lose coverage to fix a label.
 * `planning register #205`.
 */
import { transact } from "@integraledger/agentic-terms";
import { hashAtr } from "@integraledger/lcp-kernel";

/** Whatever is running us, named for the report. Each runtime announces itself differently. */
function runtime() {
  const g = globalThis;
  if (g.Bun?.version) return `Bun ${g.Bun.version}`;
  if (g.Deno?.version?.deno) return `Deno ${g.Deno.version.deno}`;
  if (g.process?.versions?.node) return `Node ${g.process.versions.node}`;
  return "unknown runtime";
}

const enc = (s) => new TextEncoder().encode(s);
const fixedFetcher = (bytes) => ({
  async fetch() {
    return { bytes, format: "application/json", fetchedAt: "t" };
  },
});

const termsJson = JSON.stringify({
  terms: "https://s.example/body",
  disputeResolution: { jurisdiction: "US-NY", method: "arbitration" },
});
const goodBytes = enc(termsJson);

const policy = {
  requiredLevel: 2,
  acceptableJurisdictions: ["US-NY"],
  acceptableDisputeMethods: ["arbitration"],
  maxCommitment: { "base-sepolia:0xUSDC": "1000000" },
  forbiddenClauseCategories: [],
  requiredAssurance: "wallet-signature-only",
  onNotAttempted: "decline",
};

const failures = [];
// ⛔ COUNTED, NOT HARD-CODED. The pass line used to say `6/6` as a literal, so adding an assertion and
// forgetting the literal would report a smaller suite than ran — the same class of stale self-description
// this file exists to remove one layer up.
let checks = 0;
const check = (label, actual, expected) => {
  checks++;
  const ok = actual === expected;
  console.log(
    `  ${ok ? "ok  " : "FAIL"}  ${label} — got ${actual}, want ${expected}`,
  );
  if (!ok) failures.push(label);
};

const now = () => "t";
let signCalls = 0;
const signer = {
  async sign() {
    signCalls++;
    return { signature: "0xsig" };
  },
};

console.log(`runtime-smoke on ${runtime()}`);

// The fingerprint comes from the kernel, not from a constant here: a hard-coded expected hash would agree
// with itself on a runtime whose Web Crypto is broken, which is precisely what this file exists to detect.
const proposal = {
  advertisedAtrHash: await hashAtr(goodBytes),
  legalContextUrl: "https://s.example/terms",
  level: 2,
  offer: { amount: "1000", unit: "base-sepolia:0xUSDC" },
  sellerAssurance: "wallet-signature-only",
};
check(
  "the kernel produced a 32-byte fingerprint",
  /^0x[0-9a-f]{64}$/.test(proposal.advertisedAtrHash),
  true,
);

// ⛔ THE TAMPER IS A DIFFERENT, EQUALLY VALID DOCUMENT — see the docblock. Same shape, same jurisdiction,
// same method, one different URL: it parses, it satisfies every policy clause, and the only thing in the
// gate that can object to it is the digest.
const tamperedJson = JSON.stringify({
  terms: "https://s.example/body-substituted",
  disputeResolution: { jurisdiction: "US-NY", method: "arbitration" },
});
signCalls = 0;
const declined = await transact(
  proposal,
  policy,
  { fetcher: fixedFetcher(enc(tamperedJson)), now },
  signer,
);
check("tampered terms halt", declined.kind, "halted");
check("tampered terms never reach the signer", signCalls, 0);
// ⭐ THE ASSERTION THAT MAKES THE TWO ABOVE MEAN WHAT THEY SAY. Without it a halt arriving from any other
// refusal in the chain reads as a pass, which is how a build with verify-before-sign disabled scored 6/6.
check(
  "and it halts on the FINGERPRINT, not on something else about the document",
  declined.kind === "halted" ? declined.decision.code : undefined,
  "gate/fingerprint-mismatch",
);

// ⚠️ The old tamper, kept and renamed to the property it actually measures. A body that does not parse is
// refused — true, worth asserting, and NOT evidence about verify-before-sign.
signCalls = 0;
const unparseable = await transact(
  proposal,
  policy,
  { fetcher: fixedFetcher(enc(`TAMPERED ${termsJson}`)), now },
  signer,
);
check("an unparseable terms body halts", unparseable.kind, "halted");
check("an unparseable terms body never reaches the signer", signCalls, 0);

signCalls = 0;
const ok = await transact(
  proposal,
  policy,
  { fetcher: fixedFetcher(goodBytes), now },
  signer,
);
check("matching terms sign", ok.kind, "signed");
check("matching terms reach the signer exactly once", signCalls, 1);
check(
  "the signed record carries the advertised fingerprint",
  ok.kind === "signed" ? ok.atrHash : undefined,
  proposal.advertisedAtrHash,
);

if (failures.length > 0) {
  console.error(
    `\nruntime-smoke FAILED on ${runtime()}: ${failures.length} assertion(s) — ${failures.join("; ")}`,
  );
  throw new Error("runtime-smoke failed");
}
console.log(`\nruntime-smoke passed on ${runtime()} — ${checks}/${checks}`);
