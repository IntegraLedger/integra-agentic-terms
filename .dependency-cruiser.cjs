module.exports = {
  forbidden: [
    {
      name: "no-circular",
      severity: "error",
      comment:
        "A cycle between modules makes initialisation order load-bearing and defeats tree-shaking. Both published packages here are small enough that a cycle is always a design slip rather than a necessity.",
      from: {},
      to: { circular: true },
    },
    {
      name: "buyer-gate-is-chain-free",
      severity: "error",
      comment:
        "⛔⛔ THIS RULE EXISTED, WAS LOST IN A SEVERANCE, AND WAS RESTORED ON 2026-08-27. Before 2026-08-13 the buyer gate lived in the separately licensed seller-side repository behind a dep-cruiser rule that forbade any file under that package — TESTS INCLUDED — from importing viem or a rail binding. The package moved to this repository; the rule did not follow, and for two weeks the property held only because nobody happened to break it. " +
        "⭐ WHY IT MATTERS MORE HERE THAN IT DID THERE. `agentic-terms` is verify-before-sign: it fetches advertised terms, recomputes a fingerprint and HALTS BEFORE A SIGNING KEY IS INVOKED. A chain SDK inside that package is a settlement capability arriving in the one surface whose entire definition is that it never settles — and this package is PUBLIC and installed by strangers, so the dependency would ship. The live proof that drives this gate against a real chain deliberately lives in the other repository's private harness for exactly this reason: to keep this package's shipped surface chain-free while still proving it against a real settlement. " +
        "⛔ `@integraledger/lcp-binding-core` is deliberately NOT matched: every other `lcp-binding-*` package is a RAIL, while `lcp-binding-core` is the placement/carrier vocabulary — `HaltClass`, `decodeLegalContextString` — that this package is built on. Forbidding it would forbid the type system the gate reads with. " +
        "⚠️ The `to:` matches the bare SPECIFIER as well as a resolved path, on the lesson the commerce repository paid for twice: when a target is unbuilt, depcruise leaves `resolved` as the specifier and a path-only regex never matches, so the rule's correctness would otherwise depend on the build having happened first.",
      from: { path: "^packages/agentic-terms" },
      // ⛔⛔ `lcp-binding-(?!core)`, NOT `lcp-binding-[a-z0-9]+-`. The first draft required a trailing
      // hyphen on the assumption that every rail binding is `lcp-binding-<chain>-<protocol>`. **That is
      // false for eight of the fifteen the protocol publishes** — `lcp-binding-solana`, `-stellar`,
      // `-xrpl`, `-hedera`, `-cardano`, `-canton`, `-aptos` and `-sui` are single-segment, and every one
      // of them imported cleanly past the rule. Measured, import by import. `core` is the ONE exclusion
      // and it is named rather than pattern-matched, so a future `lcp-binding-<anything>` is forbidden by
      // default — the direction `entitlement-off-the-transaction-path` argues for at length.
      // ⚠️ The chain SDKs are listed rather than patterned because a bare `xrpl` or `ethers` shares no
      // prefix with anything: the set is every third-party SDK the published bindings themselves depend
      // on, plus the ones a hand-rolled settlement path would reach for first.
      to: {
        path:
          "(node_modules/(viem|ethers|xrpl|@solana|@stellar/stellar-sdk|@mysten|@aptos-labs|@hashgraph|@integraledger/lcp-binding-(?!core))" +
          "|^(viem|ethers|xrpl|@solana|@stellar/stellar-sdk|@mysten|@aptos-labs|@hashgraph)($|/)" +
          "|@integraledger/lcp-binding-(?!core))",
      },
    },
    {
      name: "no-orphan-src",
      severity: "warn",
      comment:
        "A module under src/ that nothing imports and that is not an entry point ships in the tarball — `files` packs `src` — and reads to a stranger as part of the API. A warning rather than an error because a newly-added module is legitimately orphaned for one commit.",
      from: { orphan: true, pathNot: "(^packages/[^/]+/src/index\\.ts$|\\.d\\.ts$)" },
      to: {},
    },
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    tsConfig: { fileName: "tsconfig.base.json" },
    // ⛔⛔ `parser: "swc"` REQUIRES `@swc/core` TO BE INSTALLED, AND A MISSING ENGINE CRUISES ZERO.
    // Measured 2026-08-27: with `parser: "swc"` declared and `@swc/core` absent, depcruise prints
    // `✔ no dependency violations found (0 modules, 0 dependencies cruised)` and EXITS 0 — a wholly
    // vacuous gate that is the same colour as a passing one. `depcruise-gate.mjs`'s module floor is what
    // actually catches that; this comment cannot fail a build.
    // ⚠️ An older form of this note claimed the tsc parser "cruises ZERO modules under TS 7". That is
    // NOT what happens and it was never measured: depcruise's `meta.cjs` declares `typescript
    // ">=2.0.0 <7.0.0"`, so under TS 7 `tscShouldUse()` is false and it falls back to ACORN, whose
    // loose recovery still finds the imports. Re-measured on this workspace, tsc / acorn / swc all
    // cruise the identical module count. swc is kept because it resolves one extra edge and does not
    // rely on error-recovery guesswork — a preference, not a rescue.
    parser: "swc",
    // ⛔ enhancedResolveOptions is LOAD-BEARING. Without it depcruise cannot resolve pnpm-linked
    // workspace packages (an `exports` map behind a symlink); it reports couldNotResolve, and every rule
    // whose `to:` matches a PATH then silently matches nothing — the same vacuous gate by another route.
    // `scripts/depcruise-gate.mjs`'s module floor is what fails the build on either failure.
    enhancedResolveOptions: {
      exportsFields: ["exports"],
      conditionNames: ["import", "require", "node", "default", "types"],
      mainFields: ["module", "main", "types", "typings"],
      extensions: [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".d.ts", ".json"],
    },
    exclude: { path: "(dist|node_modules|\\.runtime-consumer)" },
  },
};
