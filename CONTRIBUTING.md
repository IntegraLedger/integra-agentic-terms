# Contributing

This repository is the **buyer side** of the Legal Context Protocol: a guard that fetches the terms a
counterparty advertised, recomputes their fingerprint, and halts before a signing key if they do not match —
plus an MCP server that puts the same read-only tools into any agent host.

LCP itself is co-stewarded by **Integra Ledger** and **AAA-ICDR**, and the specification is not edited here.
The protocol's open primitives live in [`integra-protocol`][protocol] and arrive as `@integraledger/lcp-*`
packages. That split decides which of two bars your change has to clear, so it is the first thing to know.

[protocol]: https://github.com/IntegraLedger/integra-protocol

## Two tiers

**Implementation improvements are welcome.** Performance, clarity, portability, better tests, a sharper
refusal message, a missing edge case in an existing rule, support for a protocol document this package
cannot parse yet — anything that leaves observable protocol behaviour unchanged. These are ordinary
engineering and are reviewed as such.

**Changes to protocol semantics or wire formats are not made here.** If a proposal alters what the wire
carries, where a reference rides, or what verification means, this repository is where a decision gets
*implemented*, never where it gets *made* — and nothing enters the standard until it is battle-tested in
production use. The useful contribution in that case is the evidence: a deployment that exercised the
behaviour, and the record of what it did.

If you are not sure which tier you are in, ask what a counterparty could observe. If your change alters a
byte on the wire, a field name, or the meaning of a verdict, it is tier two.

## What this package refuses to become

Three boundaries are load-bearing rather than stylistic, and a change that crosses one will be declined
however well it is implemented:

1. **The typed proposal cannot carry prose.** The terms body is fetched and retained as evidence and never
   reaches policy evaluation. This is the prompt-injection boundary, and it is architectural: nothing may
   widen `GateProposal` in a way that admits natural-language text.
2. **The gate has no opinion on agent operations.** Whether a quote has gone stale, which of several payment
   requirements to pay, how a negotiation reached its state — those are the agent's decisions. LCP's subject
   is that final terms are provably bound to the payment, and this gate stops at the binding. An
   offer-validity window was carried on every proposal once, read by nothing, and was removed for exactly
   this reason.
3. **Nothing calls home.** No telemetry, no callback, no request beyond fetching the terms the seller
   pointed at. This is a published guarantee in both READMEs, not a default.

## Refusal is the house style

Where two readings are possible, this code refuses rather than picking one. `parseProposalUniversal` refuses
a document that matches two protocols' discriminants. The x402 parser refuses when two carriers disagree on
a hash, because a silent choice would let a seller disown whichever reading lost. A malformed seller field
declines with a code that names *the seller's defect*, rather than declining for a reason that happens to be
true.

That last point is worth stating on its own: **failing closed is not the same as failing well.** A refusal
that misdescribes what went wrong cannot be acted on by the party who can fix it.

## Definition of done

`pnpm verify` must exit 0. It runs, in order:

```
check:versions → check:commit-messages → check:wire → check:public-boundary → check:vocab → audit
  → build → lint → typecheck → check:docs → test
```

⚠️ **One gate is deliberately outside that chain.** `pnpm check:runtime` packs the tarball, installs it
with npm as a consumer would, and drives the guard's whole decision against it — which needs the network
and does not belong in the inner loop. CI runs it as a matrix over **Node, Bun and Deno**, so it is a gate
a green `verify` does not cover: `pnpm check:runtime` exercises the Node leg locally, and the other two run
only in `ci.yml`. It exists because the runtime table in `packages/agentic-terms/README.md` is an enforced
claim and used to be an argument from the import graph instead of a measurement.

Five of those are less obvious than the rest:

- **`check:wire`** seals the protocol identities this guard reads — the discovery capability, the well-known
  path, and every placement's field, encoding and tier. A dependency bump that changes one fails here with a
  diff instead of shipping. If the change is intended, reseal with `pnpm seal:wire` and say so in the
  changeset. **The seal holds no version**, so a bump that moves no identity needs no reseal — that is what
  keeps a reseal meaningful. Whether the installed tree is the one the manifests pin is `check:versions`'
  question, answered first.
- **`check:docs`** typechecks every `ts` fence in the root README, both package READMEs, and every page of
  the documentation site under `website/content/docs`. The README fences are the code on the npmjs page and
  the only documentation inside a tarball; the site's are what an integrator lands on from a search. Both
  are copied verbatim, so both compile against the built workspace or the gate is red. A fence that is a
  deliberate fragment can be marked ` ```ts no-check `, and a fence must open at column 0 — an indented one
  is a hard error rather than a silent skip. Snippets compile at the repository root, where the
  `@integraledger/lcp-*` peers are not installed, so a fence needing a peer type should take it off the
  exported function's own signature rather than importing the peer.
- **`check:commit-messages`** refuses a commit message carrying a marker that must not be in a public
  repository — a session URL, an authorship trailer, the private repository's name. It is separate from
  `check:vocab` for one reason: a file can be fixed by editing it, and a pushed message cannot. It is
  **forward-only**, checking what a push introduces rather than auditing history, because failing until
  someone force-pushes a public repository is a decision no gate should force.
- **`check:runtime`** (CI-only, above) proves both halves of the guarantee on each runtime — tampered terms
  halt with the signer never reached, and matching terms sign with the signer reached exactly once. A
  runtime where the guard refused everything would pass a check that only looked for the halt. It uses no
  test framework on purpose: running Vitest under Bun would measure Vitest's Bun support as much as ours.
- **`check:vocab`** refuses an identifier a stranger cannot look up. Anything the published
  `@integraledger/lcp-*` packages already use resolves automatically — the allowed set is measured from the
  installed protocol line, so it moves when the pin moves — as does standards vocabulary like `SHA-256` or
  `EIP-3009`. An internal tracker id — a bare letter and digit, or a short prefix and a number — does not:
  say what it stood for instead of naming it. This repository's own prose is deliberately not a resolver,
  because mentioning an identifier is not defining it. The gate carries canaries and refuses to report
  clean if it reads nothing, so a passing run means it looked rather than that it matched nothing.

Beyond the gate:

- **Tests assert the refusal *code*, not just that something was refused.** The codes are the contract: the
  accountable log and the buyer's escalation path both key off them.
- **Mutation scores are ratcheted per package** in `stryker.config.mjs` and enforced in CI. Raise a ratchet
  when the score rises; never lower one to make a build pass. New code in a refusal path is expected to
  carry no surviving mutants — a surviving mutant on a decline branch means the suite does not constrain it.
- **Changesets for anything publishable.** A changeset body is appended verbatim into a shipping CHANGELOG,
  so write it as text a stranger will read.

## A note on the protocol dependency

`@integraledger/lcp-*` is a **peer** dependency of `agentic-terms`, deliberately, so a consumer's tree holds
one copy of it — two copies break `instanceof` across the boundary. `lcp-mcp-server` ships the same line as
ordinary `dependencies`, because it is also an executable; both are carets at the minor's zero patch, which
is what lets the two dedupe to a single copy in one tree.

The exact version CI exercises lives in `devDependencies`. `check:wire` proves the declarations are
**coherent** — one exercised line, every peer satisfied by it, no exact runtime pin, no raised floor — but
it cannot prove the range as a whole works, because a caret anchored at the dev pin satisfies those rules by
construction. What tests the rest of the range is the scheduled **`protocol-latest`** workflow: it installs
the line at `latest`, runs the full chain, and opens an issue on red. Dependabot proposes the bump itself,
so the pin stays near `latest` and the untested part of the range stays narrow.

Bumping the line is a decision about what this guard claims to interoperate with, taken with the seal in
hand.

## Security

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md) — reports go through
GitHub Security Advisories, privately.

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
