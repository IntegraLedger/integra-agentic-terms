# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security report.** Public issues are visible to everyone,
including anyone who would use the finding before it is fixed.

Report privately through **[GitHub Security Advisories][advisory]** — the "Report a vulnerability" button on
this repository's Security tab. That channel is private between you and the maintainers, gives us a place to
work the fix with you, and issues a CVE when one is warranted.

[advisory]: https://github.com/IntegraLedger/integra-agentic-terms/security/advisories/new

Please include, as far as you have it: which package and version, what an attacker gains, and the smallest
input or sequence that shows it. A failing test case is the most useful thing you can send — the parsers and
the gate are test-gated and mutation-scored, so a case that reproduces the problem usually becomes the
regression test for the fix.

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment — is it a vulnerability, and how severe | within 10 business days |
| Fix or a stated plan with dates | communicated to you before any public disclosure |

We will tell you what we conclude, including when we conclude a report is **not** a vulnerability, and why.
A report that turns out to be a design decision rather than a defect still gets a written answer.

We ask for a coordinated disclosure window so a fix can reach implementers before the details are public.
We will not ask you to stay quiet indefinitely — if we cannot fix something, we will say so and you are free
to publish. Reporters who ask to be credited are credited in the advisory.

## The failure that matters most

This software exists to **halt before a signing key** when the terms a payment would settle under are not
the terms that were advertised. So the sharpest class of finding is anything that makes the guard
**proceed** when it should have declined:

- A fingerprint mismatch that is not detected, or a comparison that can be made to pass on bytes that are
  not the advertised terms.
- A path that reaches `transact`'s signer on anything other than a Proceed decision.
- A counterparty-authored document that causes `evaluate` to **throw** rather than return a decision. This
  fails closed — the signer is never reached — but it escapes the accountable log and gives the buyer
  nothing to act on, so we treat it as a defect rather than as acceptable behaviour.
- A policy check that can be skipped: a level floor, an assurance floor, a commitment cap, or a forbidden
  clause category that a crafted record slips past.

Everything this package parses is authored by the counterparty being verified — an x402 challenge, an ACP
session, an AP2 envelope, an MPP request body, and the terms document itself. Assume hostility from all of
it; we do.

## Also in scope

**The fetcher is an SSRF boundary.** It takes a counterparty-chosen URL. It is HTTPS-only, refuses
redirects, re-checks that every resolved address is public unicast on every fetch, and caps the body while
streaming. Anything that gets a request past those checks — DNS rebinding between check and connect, a
redirect that is followed, an address family that is not covered, a cap that can be exceeded — is a
vulnerability in this package even though the request is "only" a fetch.

**Prototype pollution and key-shaped injection.** Seller-controlled strings reach object keys; that is why
`Object.hasOwn` guards the commitment lookup rather than a bare index read. A path we missed is in scope.

**The MCP server's read-only claim.** Its tools declare `readOnlyHint`. A tool that mutates anything, or
that can be induced to reach the network outside the guarded fetcher, contradicts a published guarantee.

**Published guarantees generally.** The READMEs state that nothing calls home — no telemetry, no callback,
no request beyond fetching the terms the seller pointed at. Any traffic contradicting that is a defect
regardless of how benign the destination is.

## Out of scope

- **The ports you supply.** `GatePorts` is a trust boundary by design: the `fetcher` decides which bytes the
  fingerprint is recomputed over, so a deliberately wrong fetcher defeats verification. That is injection
  working as intended, not a vulnerability — it is your code. Use the `makeCachingFetcher` shipped here
  unless you have a specific reason not to. If you find a way to make the *shipped* fetcher behave that way,
  that is very much in scope.
- **What the seller actually agreed to.** This software proves that the terms a payment settled under are
  the terms that were advertised, byte for byte. It does not read them, judge them, or tell you they are
  fair. A record that is honestly bound to terrible terms is working correctly.
- **On-chain risk that is a property of the rail** — settlement finality, reorgs, fee markets. Those are
  declared per rail in the protocol's binding manifests rather than defended against here.
- **Findings in third-party services** (registries, RPC providers, chain infrastructure). Report those to
  the operator; tell us too if the exposure reaches our software.
- **Scanner output with no demonstrated impact.** A flagged dependency is welcome — say how it is reachable
  from our code, which we check ourselves before acting.

## Supported versions

The two packages are versioned independently and released from `main`. Security fixes land on the **latest
released minor of each affected package**; there are no long-term support branches. If a fix cannot be
applied to a version you depend on, we will say so rather than imply coverage we are not providing.

## Our own practice

Every push runs `pnpm verify` — build, lint, typecheck, `pnpm audit`, the full suite, and the gates that
check what ships: that every documentation snippet compiles, that the protocol line is one line, and that
the wire identities this guard reads match a sealed record of them. CodeQL runs `security-extended` on every
push and weekly, and an error-severity finding fails the run rather than only filing an alert. Mutation
scores are ratcheted per package in CI.

Two things we state so you can calibrate a report against them:

- **A green `pnpm audit` is not evidence that no advisory exists.** npm's database has lagged a published
  GHSA by a meaningful margin. If you know a version is bad, tell us even if our tooling is quiet.
- **Dependabot reports `security_update_not_possible` for transitive dependencies** it cannot patch, because
  it cannot author a pnpm `overrides:` entry. We read that as "Dependabot cannot", never as "cannot be
  done", and fix those by hand.
