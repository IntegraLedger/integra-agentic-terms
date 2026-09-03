# @integraledger/agentic-terms

## 0.14.0

### Minor Changes

- fd79ce1: Peer the protocol at `^0.15.0` — and the two public pages that told a reader otherwise.
  
  Protocol `0.15.0` is live. On a `0.x` line a caret pins the MINOR, so `^0.14.0` means `>=0.14.0 <0.15.0`
  and **excludes the line it names**. The gap is invisible to `check:wire` by construction: that gate reads
  the declarations for coherence, and a caret anchored at the dev pin satisfies every rule it has.
  
  **Measured against the live registry, not derived** — fresh directory, no lockfile, full nested
  enumeration (`find node_modules -path '*lcp-kernel/package.json'`), npm 11.6.2 / node v25.2.1:
  
  ```
  npm i agentic-terms lcp-kernel          exit 0, ZERO warnings  one line at 0.14.0
  npm i lcp-kernel agentic-terms          exit 0, ONE warning    0.15.0 top-level, and 0.14.0 nested
                                                                 five times under authority,
                                                                 binding-core, discovery, evidence, verify
  npm i lcp-kernel@0.15.0 agentic-terms   exit 1, ERESOLVE       nothing installed
  ```
  
  Six `lcp-kernel` identities at two versions, decided by which name the caller types first — the tree
  `check:wire` exists to refuse, arriving with exit 0 and one warning that scrolls past. ⭐ Note the
  inversion: a consumer who PINS gets an honest hard failure; one who does not gets the split.
  
  29 pins move together, across all four manifest surfaces — the root's `lcp-conformance` (the root is not
  a package, and a `packages/*` sweep does not reach it), ten dev pins and nine peers in `agentic-terms`,
  and nine **runtime `dependencies`** in `lcp-mcp-server`, the field that was reported as needing no edit
  during the last repin and was wrong then. Plus the fifth surface a manifest sweep never reaches: the two
  public install pages that state the range, `quickstart.mdx` and `reference/agentic-terms.mdx`. The dated
  records that state the old range are left alone — rewriting a record to match the present falsifies it.
  
  **No source change, and that was checked rather than assumed.** `0.15.0` renames `Envelope` → `Atr`,
  `AtrFile`/`atrFile` → `AtrBytes`/`atrBytes`, `Component` → `Slot`, and `assemble/component-shape` →
  `assemble/slot-shape`. None of it lands here: every `Envelope` in this tree is the AP2 transport envelope,
  which that release deliberately keeps, and the one `assemble()` caller destructures `atrHash` alone. The
  ACP round-trip assembles a real ATR rather than pinning a digest, so the ATR's moved first member
  (`atrVersion`) is absorbed by the round-trip instead of stranding a fixture.

### Patch Changes

- e1b5b8e: Gloss the requirement ids these packages ship, and add the two gates a public npm surface was missing.
  
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

## 0.13.0

### Minor Changes

- 62cd520: Renamed from `@integraledger/agent-guard` to `@integraledger/agentic-terms`.
  
  The former name collided with at least ten concurrent products in AI-agent security, every one of them
  senior to this package's first publish on 2026-08-13 — among them AppOmni's AgentGuard (2025-11-19) and
  Jozu's Agent Guard (2026-03-12), both announced through wire services. The name identified nothing.
  
  `@integraledger/agent-guard` is deprecated and will receive no further releases. Versioning continues on
  the same line rather than restarting, so changelog history reads straight through.
  
  **Breaking:** the exported type `GuardedSigner` is now `GatedSigner`. No alias is provided. Every other
  export is unchanged — `transact`, `GatePorts`, `GateProposal`, `BuyerPolicy` and `makeCachingFetcher` keep
  their names and signatures.
  
  `@integraledger/lcp-mcp-server` is unaffected in name, in its `lcp-mcp` server identity, and in all six of
  its `lcp_*` tool names; it moves only because the two packages version in lockstep.
  
  The documentation site moves to <https://agenticterms.integraledger.com>.

## 0.12.1

### Patch Changes

- Version bump only — no change to this package.
  
  `agent-guard` and `lcp-mcp-server` are a `fixed` group in `.changeset/config.json`, so they version in
  lockstep and a release naming either moves both. The change in this release is `lcp-mcp-server`'s README
  stating the LCP capability it declares; see its CHANGELOG.
  
  Stated rather than left as a bare heading: a version that appears on the registry with nothing beside it
  tells a reader looking for the diff that something was omitted, when the honest answer is that nothing
  here moved.

## 0.12.0

### Minor Changes

- 23f0926: Peer the protocol at `^0.14.0` — and the two documents that told a reader otherwise.
  
  Protocol `0.14.0` is live: `@stellar/stellar-sdk` 16 → 17 on `binding-stellar`, viem 2.55.19 on
  `binding-evm-common`, plus `@mysten/sui` and `@aptos-labs/ts-sdk`. On a `0.x` line a caret pins the MINOR,
  so `^0.13.0` **excludes** `0.14.0` outright — a consumer holding both this package and the new protocol
  line gets two copies of `lcp-binding-core`, which breaks `instanceof CarrierError`.
  
  **Measured in a consuming workspace before this changed:** moving all 109 of its protocol declarations to
  `0.14.0` left the lockfile carrying 34 references at `0.13.0` beside 70 at `0.14.0` — thirteen
  package/version pairs held back, `lcp-binding-core` among them — because a package there consumes this one
  and this one peered `^0.13.0`. Exact pins do not decide that; a peer range does. The same shape held four
  packages at `0.12.2` through the `0.13.0` repin.
  
  ⛔ **`lcp-mcp-server` was reported as needing no edit, and that was wrong.** It declares no peers and no
  dev pins — but it carries **nine runtime `dependencies` at `^0.13.0`**, which exclude `0.14.0` exactly as
  the peers do. Moved with the rest. A scope that had trusted the report would have shipped it still pinned.
  
  ⛔ **And the ROOT manifest is not a package.** A sweep of `packages/*` left
  `@integraledger/lcp-conformance` at `0.13.0` in the root's own devDependencies, and `check:wire` caught it
  — *"the tree exercises 2 protocol lines"* — which is the trap the `0.13.0` repin wrote down and this one
  walked into anyway.
  
  ⛔⛔ **TWO PUBLIC DOCUMENTS TOLD READERS THE WRONG RANGE, AND NOTHING WAS RED.**
  `website/content/docs/quickstart.mdx` and `website/content/docs/reference/agent-guard.mdx` both stated
  `^0.13.0` — these are the published install instructions, so a reader following them pins a line the guard
  does not peer and meets it as an unmet-peer warning they did not cause. Corrected, and `check:wire` gained
  a rule that derives the expected range from `agent-guard`'s own `peerDependencies` and refuses any page
  stating a different one. Planted and red; the subject excludes dated `2026-*` records, because rewriting
  one to match today would falsify a record rather than fix a claim.
  
  ⚠️ **One follow-up after this publishes.** The root dev-depends on the PUBLISHED
  `@integraledger/lcp-mcp-server@^0.11.0` for its own runtime-consumer smoke test, and `^0.11.0` excludes
  `0.12.0` for the same caret reason. It moves to `^0.12.0` once this release is live.

## 0.11.0

### Minor Changes

- 5159d60: Version bump only — no change to this package.

  `agent-guard` and `lcp-mcp-server` are a `fixed` group in `.changeset/config.json`, so they version in
  lockstep and a changeset naming either moves both. The change in this release is
  `lcp-mcp-server` declaring the LCP capability in `capabilities.extensions`; see its CHANGELOG. The
  protocol line moved to 0.13, which this package tracks through its peer ranges.

## 0.10.1

### Patch Changes

- 5154cfb: Install one copy of the protocol packages, not two.

  `lcp-mcp-server` pinned its `@integraledger/lcp-*` dependencies to an exact version while `agent-guard`
  — which it depends on — declares the same packages as peers at a caret range. Those two declarations
  cannot be satisfied by a single copy, so installing both packages resolved the protocol line **twice**:
  once hoisted to satisfy the caret, and once nested under `lcp-mcp-server` to satisfy the exact pin. The
  two halves of one install then read different protocol code, with `instanceof` failing across the seam
  between them.

  `lcp-mcp-server` now declares those dependencies as a caret at the minor line's zero patch, matching its
  sibling. A tree holding both resolves a single copy, and `npx lcp-mcp` still installs standalone.

  Nothing about either package's API, behaviour or guarantees changes. Both were correct in isolation; only
  a tree holding both was affected.

- ccf4bb4: The runtime table is measured now, not argued.

  It used to assert that this package works on Bun and Deno because of what the import graph implies — the
  one Node built-in that arrives, `node:crypto`, is polyfilled on both. That was a sound argument and it was
  only ever an argument; nothing ran.

  Every release now drives the guard's whole decision on Node, Bun and Deno, against the packed tarball
  installed the way you would install it, with the protocol line resolved from npmjs. Both halves are
  asserted on each runtime, because a runtime where the guard refused everything would pass a check that only
  looked for the halt: tampered terms must halt with the signer never reached, and matching terms must sign
  with the signer reached exactly once.

  Measured on this release: Node 24.19.0, Bun 1.4.0, Deno 2.9.5.

  The table now separates what is measured from what is reasoned. Workers with `nodejs_compat` and the
  bundler row remain arguments from the import graph and say so, rather than sitting in the same column as
  the rows that ran.

## 0.10.0

### Minor Changes

- 06a25ac: Read the whole advertisement, and move to protocol 0.12.0.

  The peer range was `^0.10.1`, which on a `0.x` version admits only patches — so this guard declared it did
  not support the line every seller now writes, and a tree holding both resolved a second copy of the protocol
  packages to satisfy it. The peers are `^0.12.0` and the build pins 0.12.0 exactly.

  **The terms URL is no longer read by hand.** `PlacementManifest.termsUrlField` was singular and named one
  path; it is now `termsUrlFields`, plural, and a slot that rides a container the placement owns is declared on
  that container. Reading that by hand here would have been a second implementation of a manifest rule, so the
  locator now comes from the placement's own `extract`, which reconciles every declared slot and refuses two
  that disagree. The reference walk stays this package's own: "integrity carriers only" is a BUYER rule — a
  discovery link locates a standing page and attests nothing — and the placement's reader does not apply it.

  **`AdvertisedTermsUrl` loses a state, and could not keep it.** `undeclared-at-answering-carrier` existed
  because the singular member could not reach the carrier a §C.4 challenge actually used: the hash answered
  from `accepts[].extra` while the one declared path sat empty inside `extensions`, and reporting that as "no
  terms advertised" would have asserted a silence this reader could not see. With every slot declared and
  reconciled there is no such carrier, so the state is unreachable rather than merely unused, and the §C.4
  challenge now simply reads its URL. `declared-field-empty` becomes `declared-fields-empty` and carries every
  slot it looked at.

  `lcp_place_reference` takes an optional `termsUrl` — required where the protocol declares a slot and the
  reference is a digest, refused where it declares none — and `lcp_extract_reference` reports the locator
  beside the reference, with its two absences distinguished: a protocol with no slot is not a seller who left
  one empty.

  Wire identities are unchanged apart from the protocol line itself.

## 0.9.0

**First public release** — Apache-2.0, free forever, no account and no token to install.

`agent-guard` is the buyer-side verify-before-sign guard for agentic purchases. It fetches the terms a
seller advertised, recomputes their fingerprint, and halts before any signing key is invoked if the two
disagree. It works against **any** seller, whether or not that seller uses Integra software.

### The gate

`evaluate` runs the Legal Context Protocol's buyer sequence and returns a decision. It never touches a
signing key itself — `transact` enforces the decision against a guarded signer, so no caller can sign on a
refusal by mistake.

- **Fetch and retain the terms as evidence** (LCP §5.4), at every trust level, never a silent skip.
- **Verify before sign** (LCP §5.3): recompute the fingerprint over the fetched bytes and HALT on a
  mismatch, before the key.
- **Policy on the typed envelope only** (LCP §12.7). The terms body is retained as evidence and never
  reaches policy evaluation. The prompt-injection boundary is architectural rather than a filter: the
  typed proposal cannot carry prose.
- **Refuse rather than choose.** A coverage gap resolves by the buyer's stated disposition; nothing
  resolves by a silent default.

Outcomes are **twelve decline codes**, plus `gate/escalate` and `gate/proceed`. The codes are the
contract — the accountable record and a buyer's escalation path both key off them — and a refusal names
the counterparty's actual defect rather than a reason that merely happens to be true. A counterparty
cannot make the gate throw: every failure reachable from a seller-authored document arrives as a returned
decision.

### Protocols

Four commerce protocols parse into one typed `GateProposal`: **x402** and **ACP** through
`parseProposalUniversal`, which refuses a document matching two protocols' discriminants rather than
picking one; **AP2** and **MPP** by name, because their identity lives outside the body a caller holds.

### The fetcher is an SSRF boundary

It takes a counterparty-chosen URL. It is HTTPS-only, refuses redirects, re-checks that every resolved
address is public unicast on every fetch, and caps the body while streaming. IPv6-literal hosts are
supported. `GatePorts` is a documented trust boundary: the fetcher decides which bytes the fingerprint is
recomputed over.

**Nothing calls home** — no telemetry, no callback, no request beyond fetching the terms the seller
pointed at.

### Packaging

- Apache-2.0. LICENSE and NOTICE ship in the tarball; NOTICE states the trademark reservation, names
  Integra Ledger and AAA-ICDR as the Legal Context Protocol's co-stewards, and records that the
  seller-side application is separately licensed and not part of this distribution.
- The `@integraledger/lcp-*` protocol line is a **peer** dependency, so a consumer's tree holds exactly
  one copy of it — two copies break `instanceof` across the boundary.
- `files` ships `src` alongside `dist`, so published source maps resolve inside the tarball.
- Runs on Node, Deno, Bun, and Workers with `nodejs_compat`. The README's runtime table states per-target
  support exactly; the one Node-specific host lookup is lazily imported and injectable.
