# @integraledger/lcp-mcp-server

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
