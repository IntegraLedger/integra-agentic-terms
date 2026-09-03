# @integraledger/lcp-mcp-server

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
- Updated dependencies [e1b5b8e]
- Updated dependencies [fd79ce1]
  - @integraledger/agentic-terms@0.14.0

## 0.13.0

### Patch Changes

- Updated dependencies [62cd520]
  - @integraledger/agentic-terms@0.13.0

## 0.12.1

### Patch Changes

- 06de470: The npm page states the LCP capability this server has declared since 0.11.0.
  
  `lcp-mcp-server` asserts `com.integraledger/legal-context` in `capabilities.extensions`, so an MCP host can
  discover that this server verifies the legal context bound to a payment without calling a tool. The
  documentation site has described it since it shipped; the README — the only documentation inside the
  tarball, and the page npmjs renders — did not mention it at all.
  
  Documentation only: no code changed, and the declaration itself is unmoved.
  
  ⛔ **Two shipped statements said the server declares tools and nothing else**, and both were corrected
  alongside this: the `createLcpMcpServer` docblock, twenty lines above the assertion contradicting it, and
  `website/content/docs/mcp/boundary.mdx`, where the same site's MCP overview already described the
  declaration correctly. Neither moved the boundary the page is about — there are still no resources and no
  prompts, and the capability says this server speaks LCP rather than anything about a seller's terms.
- Updated dependencies
  - @integraledger/agent-guard@0.12.1

## 0.12.0

### Patch Changes

- Updated dependencies [23f0926]
  - @integraledger/agent-guard@0.12.0

## 0.11.0

### Minor Changes

- 5159d60: The server declares the LCP capability, and the protocol line moves to 0.13.

  `lcp-mcp-server` now advertises `com.integraledger/legal-context` in
  `capabilities.extensions`, so an MCP host can discover that this server verifies the legal context bound
  to a payment **without calling a tool**. The identifier and its settings value are both imported —
  `LCP_MCP_EXTENSION_ID` from `lcp-discovery`, `LCP_SPEC_VERSION` from `lcp-kernel` — because a wire
  identity spelled locally is a second home the wire seal cannot see, and a hardcoded spec version drifts
  the first time the specification moves.

  ⭐ **This is the one capability that must be asserted in the constructor, and it does not contradict the
  rule beside it.** `tools` is left to the registrations because the SDK DERIVES it, so restating it would
  duplicate a fact something else owns. Nothing derives an extension: no registration implies this server
  speaks LCP, so the constructor is the only place the declaration can come from. Measured — deleting it
  makes the extension vanish from what a client sees.

  **Graceful degradation is total, which is what makes this safe to ship.** A client that ignores the
  identifier gets a byte-identical server; there is no branch in which the extension refuses a request, and
  a test asserts the tool list is unchanged. A client must not read the declaration as a claim that any
  seller's terms are bound — it describes the server's capability, not a transaction.

  Three assertions, each driven red against a planted defect: the declaration removed (the "consistency
  fix" the docblock warns against), UCP's `com.integraledger.legal_context` substituted for MCP's
  slash-form identifier, and the spec version hardcoded rather than derived.

  ⛔ **Protocol repin: `0.13.0`.** Exact in `devDependencies`, `^0.13.0` in shipped `dependencies` and
  `peerDependencies` — the three shapes `check:wire` enforces. The line moves for a reason rather than a
  bump: `LCP_MCP_EXTENSION_ID` is new API, and it first shipped as `0.12.3`, a **patch**. That broke the
  invariant `check:wire` is built on — every patch inside a line is API-equivalent — while the gate
  requires the caret at the minor's zero patch and refuses a raised floor. With `0.12.2` resolved, squarely
  inside `^0.12.0`, the export is `undefined` and the capability key serialises as
  `{"extensions":{"undefined":{}}}`. The declaration was deliberately not shipped against that floor.
  Verified afterwards that the invariant had otherwise held: of the nine runtime protocol dependencies,
  eight added no exports anywhere across `0.12.x`.

  ⚠️ The spec is `docs/2026-08-25-lcp-mcp-extension-specification.md`. `@modelcontextprotocol/server@2.0.0`
  negotiates wire era `2025-11-25` and has no `server/discover`, so the declaration rides the `initialize`
  handshake today and carries forward unchanged when the SDK ships the modern era.

### Patch Changes

- @integraledger/agent-guard@0.11.0

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

- Updated dependencies [5154cfb]
- Updated dependencies [ccf4bb4]
  - @integraledger/agent-guard@0.10.1

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

### Patch Changes

- Updated dependencies [06a25ac]
  - @integraledger/agent-guard@0.10.0

## 0.9.0

**First public release** — Apache-2.0, free forever, no account and no token to install.

`lcp-mcp-server` exposes read-only Legal Context Protocol tools to an AI agent over the Model Context
Protocol: verify before pay, compute an atrHash, and extract or place a terms reference across the nine
commerce protocols that have a defined placement.

### Six tools, all read-only

`lcp_verify_before_pay` · `lcp_compute_atrhash` · `lcp_extract_reference` · `lcp_place_reference` ·
`lcp_generate_legal_context` · `lcp_scaffold_integration`

Every tool declares `readOnlyHint` to the host. The annotations are stated rather than omitted because
MCP documents `destructiveHint` and `openWorldHint` as defaulting to **true** — an unannotated tool reads
to a client as possibly destructive and open to an arbitrary external world, which is the most alarming
reading available and not the honest one for this surface.

The **only** network egress is the counterparty terms fetch, and it goes through the same injected,
SSRF-guarded port the guard uses: HTTPS-only, no redirects, public-unicast re-checked on every fetch, and
a streaming byte cap. Nothing calls home.

### Wiring

Stdio transport for desktop agent hosts, served so that both current and `2026-07-28` clients resolve
correctly from one registration. Built against the live MCP `ToolAnnotations` definition
(`schema/2026-07-28/schema.ts`); the specification check behind that date is recorded in this package's
README.

### Packaging

- Apache-2.0. LICENSE and NOTICE ship in the tarball; NOTICE states the trademark reservation, names
  Integra Ledger and AAA-ICDR as the Legal Context Protocol's co-stewards, and records that the
  seller-side application is separately licensed and not part of this distribution.
- Consumed as a runnable server over `npx`, so the `@integraledger/lcp-*` protocol line and
  `@integraledger/agent-guard` are ordinary exact dependencies — there is no second line for it to
  collide with.
- `files` ships `src` alongside `dist`, so published source maps resolve inside the tarball.
