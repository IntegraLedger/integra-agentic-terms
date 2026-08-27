---
"@integraledger/agentic-terms": patch
"@integraledger/lcp-mcp-server": patch
---

Gloss the requirement ids these packages ship, and add the two gates a public npm surface was missing.

**Both packages pack `src/`, and that `src/` cited identifiers a stranger could not resolve.** `files`
includes `src`, so eleven citations across six families — `IDN-1`, `IDN-3`, `ATA-2`, `ORC-4`, `RCS-4`,
`DSC-2` — reach anyone who installs, and neither README explained them. They are not LCP clause numbers;
they come from Integra's own functional specification. `integra-protocol` settled this in August by
glossing the fourteen families in its root README and in all twenty-one of its package READMEs, and the
same table now appears here, where this tarball's reader can actually see it. The ids themselves are
unchanged — they are load-bearing in review, and a citation a reader cannot resolve is worse than prose.

**`check:dist`** refuses a build output whose source no longer exists. `tsc` never removes output for a
deleted or renamed source and `dist/` is gitignored, so an orphan is invisible to review — but it travels
in the tarball with a source map pointing at a path the tarball does not contain. Two public packages is a
smaller surface than thirty-one, not a safer one.

**`depcruise`, run through `scripts/depcruise-gate.mjs` and carrying `buyer-gate-is-chain-free`. ⛔⛔ That
rule existed before the severance and was lost in it.** While the buyer gate lived in the seller-side repository, a dep-cruiser rule forbade any file under
it — tests included — from importing viem or a rail binding. The package moved here; the rule did not
follow, so for two weeks the property held only because nobody happened to break it. This package halts
before a signing key is invoked, so a chain SDK inside it is a settlement capability in the one surface
defined by never settling — and being public, it would ship. `lcp-binding-core` stays allowed: it is the
carrier vocabulary, not a rail. ⛔ The rule matches `lcp-binding-(?!core)`, NOT `lcp-binding-<chain>-*`:
eight of the fifteen bindings the protocol publishes are single-segment (`-solana`, `-stellar`, `-xrpl`,
`-hedera`, `-cardano`, `-canton`, `-aptos`, `-sui`) and a trailing-hyphen pattern let every one of them
through. Re-planted on landing, import by import — all fifteen bindings plus `viem`, `ethers`, `xrpl` and
`@hashgraph/sdk` go red; `lcp-binding-core` stays green.

⛔ **`pnpm depcruise` runs a wrapper that asserts a module FLOOR**, because a cruise that sees nothing has
nothing to violate and reports the same colour as a real pass. Measured: `parser: "swc"` declared before
`@swc/core` was installed cruises 0 modules and exits 0. (The engine being missing is the trap — the tsc
parser does *not* cruise zero under TypeScript 7; it falls back to acorn, and all three parsers were
re-measured at an identical count.)

**A pre-publish protocol seam gate** now runs the workspace against protocol code that has not been
published yet. `protocol-latest.yml` proves the caret against what is already published and cannot see a
break until after the protocol releases — and an npm version, once used, cannot be taken back. For two
public packages that discovery belongs before the irreversible act, not after it.
