/**
 * One parametric Stryker config for every package, rather than a JSON file each.
 *
 *   pnpm mutation agentic-terms   # a single package
 *   pnpm mutation:all           # every package, sequentially
 *
 * A test COUNT says how much ran; a mutation SCORE says how much the tests constrain. That distinction
 * carries the most weight on the refusal paths — code whose whole job is to decline — because "it threw"
 * passes for the wrong reason as readily as the right one.
 *
 * THE RUN IS ROOTED AT THE REPO ROOT, not the package. Stryker's TSConfigPreprocessor calls
 * `ts.parseConfigFileTextToJson`, which TypeScript 7's native compiler API removed; rooting here sidesteps
 * it. Nothing the sandbox needs (`tsconfig.base.json`) then resolves outside the sandbox, so no path
 * rewriting is required.
 *
 * TWO BLIND SPOTS, both of which read as the opposite of what happened:
 *
 *  1. A mutant that makes an import — or a `describe` body — throw fails the whole test FILE before any
 *     test runs, and vitest reports zero FAILED tests. Stryker records that as SURVIVED. So build fixtures
 *     inside `it`, not in a describe body; and where the source itself throws at import, put the guard in
 *     its own file and `await import()` it inside the test. `pnpm verify` catches these either way — only
 *     the score is fooled.
 *  2. A skipped test kills nothing, so a suite that skips without credentials scores near zero regardless
 *     of its real quality.
 *
 * THRESHOLDS ARE RATCHETS. `break` sits just under each package's measured score. Raise it when the score
 * rises; never lower it to make a build pass. A package absent from the table has not been measured — it
 * runs at break 0 and prints its baseline.
 */

/**
 * Measured floors — both packages, each set to the integer below its measured score. These entries and
 * their histories predate this repository; the measurements
 * are the same code's.
 *
 * agentic-terms rose 94 -> 96 when the universal parser landed. The rise is the new file's own doing: at
 * 96.22 the package shows 685 killed + 2 timed out against 24 survived + 3 uncovered, and `proposal-universal`
 * contributes 312 of the kills against 5 of the survivors, so the package without it stands at 375/397 = 94.46
 * — which is the 94 this entry used to read.
 *
 * THE PACKAGE HAS 24 SURVIVORS, NOT 5, and they are not one population. Only `proposal-universal`'s five are
 * classified equivalent (below). The other 19 sat in `mechanical.ts` (6, and the file scored **64.71** —
 * far under the house floor), `fetch.ts` (4), `policy.ts` (4), `proposal.ts` (4) and `evaluate.ts` (1). All
 * 19 PREDATE the universal parser and none were classified: they are residue the 94 floor already carried, not new
 * debt, and naming them here is the point — a package-scoped "its survivors are all equivalent" would have
 * read as a clean bill for a file at 64.71 that nobody had looked at.
 *
 * **`mechanical.ts` IS CLOSED — 17/17, 100%, as of 2026-08-04 (package 96.77).** It took two changes, and
 * only one of them was here. A test pinning that a HIGHER claimed class survives the `?? "TC-2"` default
 * killed one mutant: without it nothing distinguished a default that yields to the caller's claim from an
 * expression collapsing ANY claim to TC-2, which would turn an unsupported claim into a passing verdict.
 *
 * The other five were UNKILLABLE from this repo, and that was the finding. They mutated `subject` and
 * `via` to blanks, and nothing observable changed — because `verify`'s `resolve-party` read the resolution
 * chain's array LENGTH and never its contents, so `subject: ""` and `chain: [{}]` proved attribution just
 * as a real identity did. The mutants were pointing at a protocol defect, not at test debt. Closing it
 * upstream (`@integraledger/lcp-verify`'s `resolve-party` narrowing — every party must state a non-blank
 * subject and every chain entry a non-blank `via`) killed all five at once, with no test written here to
 * chase them. Worth remembering the
 * shape: when a survivor cannot be killed without contriving an assertion, ask whether the thing it mutates
 * is observable AT ALL before classifying it equivalent.
 *
 * `proposal-universal`'s five ARE equivalent, and each is recorded because "equivalent" is a claim someone
 * has to be able to re-check: `carriesAp2Mandate`'s `return false` on a non-array `parts` (the AP2 row ANDs
 * it with `isA2aMessage`, which demands the same array, so the returned value cannot change the row's
 * answer); `carrierKey`'s `toLowerCase` vs `toUpperCase` (a key is only ever compared with another key from
 * the same fold, and both folds are idempotent); and the three on the alias `bareType` ternary — the sole
 * INTEGRITY alias declaring one is x402's `accepts.0.extra.atrHash` at `"sha256"`, which is already its
 * manifest's `carrierTypes[0]`, and the sole alias whose type differs (UCP's `"url"`) is `discovery`-class
 * and is skipped before it is read. Both arms therefore answer identically for every manifest in the
 * registry. That last one stops being equivalent the day a manifest declares an integrity bare-value alias
 * off its first carrier type, and the pin that would catch it needs a synthetic manifest this package has no
 * door for.
 *
 * `fetch.ts`'s IPv6-bracket normalisation (2026-08-13) leaves TWO Regex survivors, and both are equivalent
 * against the only input this code can receive. The expression is `/^\\[(.+)\\]$/.exec(url.hostname)`; the
 * survivors drop the `^` and the `$` respectively. Killing either needs a hostname with a bracket that is
 * not at an edge — and the WHATWG parser refuses to build one: `https://a[::1]/x`, `https://[::1]b/x`,
 * `https://a[b]c/x`, `https://[::1]]/x`, `https://[[::1]/x` and the percent-encoded `%5B::1%5D` form all
 * throw `ERR_INVALID_URL`. A `URL` cannot carry a hostname the anchors would discriminate, so no honest
 * test distinguishes the arms. Re-check by running those six through `new URL(...)`; the day one of them
 * parses, these stop being equivalent. The conjunction this replaced left THREE survivors for a worse
 * reason — it spelt a matching pair as two separately unobservable facts.
 *
 * agentic-terms's earlier entry, SUPERSEDED by the universal parser's rise to 96 (the header paragraph above): it stayed
 * at 94, measured 94.61 after the AP2/ACK buyer parsers landed (95.67 before them). The drop was real and
 * inside the ratchet — NOT a licence to lower the entry. SIX non-killed mutants arrived in the two new
 * files — five `Survived` and one `NoCoverage`, which score identically and are worth distinguishing
 * anyway — and every one is residue that still stands classified:
 *
 *   - THREE prose continuation strings on refusal messages (`proposal-ack.ts:98`, `proposal-ap2.ts:103`
 *     and `:171`). Each is the second half of a wrapped message; the half carrying the matched text is
 *     killed in every case;
 *   - the `", "` separator inside `ACK_DID_METHODS.join(", ")` at `proposal-ack.ts:116`. The mutant that
 *     blanks the WHOLE template literal at the same location is killed — only the separator survives, and
 *     killing it would mean asserting the comma-space in a joined list;
 *   - the same `method === undefined` equivalent as above (`proposal-ack.ts:112`), present for the type
 *     narrowing `includes(method)` requires;
 *   - `NoCoverage`, not `Survived`: the `?? []` on the manifest's optional `readAlso` at
 *     `proposal-ack.ts:46`. `readAlso` is optional on `PlacementManifest` and manifests legitimately omit
 *     it — `placement-acp@0.1.0` did — so `[]` is the CORRECT value for "this placement owns no alias
 *     keys", under which `siblingRefKeys` rightly reports the un-owned key as one of ACK's own. It is
 *     total handling of an optional field, not a silent fallback, and a throw there would refuse a legal
 *     manifest shape. `ACK_PLACEMENT` declares an alias today, which is why the arm is unreached.
 *
 * The NAMED declaration was pinned rather than left to a coherence check, and that is the one place a
 * literal is worth pinning: `AP2_HALT_POINT`'s `lastSafeStep` / `haltBefore` / `signingSteps` are AP2 flow
 * vocabulary an integrator reads to decide where to call the gate, so a silent rename would move the halt
 * point while every internal consistency assertion still passed.
 *
 * lcp-mcp-server measured 89.29 (325 killed, 38 survived, 1 no-coverage), RAISED 88 -> 89. The rise is
 * exactly the two verdict-enum mutants described at the end of this entry, killed by the pin that closed
 * them; `verify-before-pay.ts` moved to 89.19. Before that it measured 88.74, up from the 87.50 of its
 * first build: the manifest-read version and the
 * parsing well-known locator both landed with their refusal arms covered, so `version.ts` scores 96.15 and
 * `well-known.ts` 100. The shape of what is left is particular to what an MCP server IS: a large share of
 * its source is model-facing PROSE — the tool `description`, every schema field's `.describe()`, and the
 * wording of every refusal — because that prose is the interface an agent reads. 28 of its 41 residual
 * mutants are a string only an agent reads going empty: 22 fragments of a multi-line description, the two
 * `.join(", ")` separators that splice the supported-protocol list into two of those, and four
 * error-message template literals. What CAN be asserted about prose is asserted, and it moved the score
 * 64.04 -> 87.50: every input and output field, nested ones included, must carry a non-empty description;
 * every output schema must NAME the fields the tool returns; every tool's annotations and title are pinned;
 * and each safety-critical description must still contain its load-bearing instruction ("DO NOT PAY", "it
 * does not transmit it"). Pinning the remaining fragments word for word would encode one phrasing of
 * documentation as the standard, which is the same trap as pinning a refusal's `detail`.
 *
 * Ten of the remaining thirteen are equivalent or unreachable, each for a stated reason: five
 * `{k: undefined}` spreads that `discovery.emit` and `JSON.stringify` both drop, so the mutant's output is
 * byte-identical; three `"closed"` reach literals, where `"" !== "network"` behaves exactly as `"closed"`
 * does; the `isAtrHash` narrowing in `verify-before-pay`, whose throw arm no parsed document reaches
 * because the discovery schema is stricter than the TypeScript type it produces (that one is documented at
 * the call site); and `readFileSync(manifestUrl, "utf8")` in `version.ts`, where an unusable encoding
 * yields a Buffer that `JSON.parse` coerces to the same string. One more needs a live resolver: the
 * `makeCachingFetcher` config in `nodePorts` is a composition root whose ports only differ once a real DNS
 * lookup runs.
 *
 * TWO WERE A REAL GAP, and it is now CLOSED — the paragraph stays because the reasoning is worth keeping.
 * Both non-`verified` members of `lcp_verify_before_pay`'s `verdict` enum survived being emptied in the
 * OUTPUT SCHEMA. The tool still returned `"mismatch"` and `"unverifiable"`, so the mutant shipped a schema
 * contradicting the tool, and nothing caught it: those two verdicts only ride an `isError` result, whose
 * `structuredContent` the SDK does not validate against the schema. Every existing assertion read the
 * RUNTIME value and passed either way — verified by applying the mutant, under which all ten of the file's
 * tests stayed green.
 *
 * `verify-before-pay.test.ts` now reads the enum off the `tools/list` wire — the artifact a client actually
 * validates against — and holds it against the verdicts the tool is observed to emit, one scenario per
 * verdict, as a set equality. A member dropped from the schema and a member declared but unreachable break
 * it from opposite sides. This is the one place pinning a literal is right: the verdict vocabulary is a
 * contract with the MODEL, not documentation prose, which is why it is pinned where the descriptions
 * around it are deliberately not.
 */
const RATCHET = {
  "agentic-terms": 96,
  "lcp-mcp-server": 89,
};

const pkg = process.env.STRYKER_PKG;
if (!pkg) {
  throw new Error(
    "STRYKER_PKG is required — run `pnpm mutation <package>` (e.g. `pnpm mutation agentic-terms`).",
  );
}

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  reporters: ["html", "json", "clear-text"],
  coverageAnalysis: "perTest",
  mutate: [`packages/${pkg}/src/**/*.ts`],
  vitest: { dir: `packages/${pkg}` },
  htmlReporter: { fileName: `reports/mutation/${pkg}/index.html` },
  jsonReporter: { fileName: `reports/mutation/${pkg}/mutation.json` },
  thresholds: { high: 95, low: 90, break: RATCHET[pkg] ?? 0 },
  tempDirName: ".stryker-tmp",
  cleanTempDir: true,
  concurrency: 4,
};
