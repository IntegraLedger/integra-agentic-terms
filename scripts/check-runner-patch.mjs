#!/usr/bin/env node
/**
 * `check:runner-patch` — **the INSTALLED Stryker vitest runner must spell a full test name the way the
 * INSTALLED vitest matches it, and both must be the version the catalog asked for.**
 *
 * ⛔⛔ WHY THIS EXISTS. `@stryker-mutator/vitest-runner` builds its per-mutant test filter by joining a
 * test's suite names and its own name, turns that into a regex and hands it to vitest as
 * `testNamePattern`. vitest 5 matches that pattern against a name composed with `" > "`; the runner joins
 * with a SINGLE SPACE. The two spellings are not the same string, and vitest does not error on a pattern
 * that matches nothing — it SKIPS every test and exits 0. Stryker reads a run in which nothing failed and
 * records the mutant SURVIVED.
 *
 * ⭐⭐ THE FAILURE IS SILENT IN THE DANGEROUS DIRECTION, WHICH IS THE WHOLE ARGUMENT FOR A GATE. A package
 * whose ratchet sits below the score its STATIC mutants alone produce stays GREEN over a suite that
 * executed no tests at all. Measured in `integra-agentic-terms`, `seller-mcp`, the same 83 mutants twice:
 * patched 93.98 (78 killed), unpatched 4.82 (4 killed) — and the 4 that still die are exactly its 4 static
 * mutants. A floor anywhere below 4.82 would have passed over nothing.
 *
 * ## ⛔ WHAT pnpm ALREADY GUARDS, AND WHAT IT DOES NOT
 *
 * pnpm refuses a patch whose TARGET VERSION moved, so a runner bump cannot silently carry the patch
 * forward. That half needs no gate. What stays unguarded is the other half, and it is two-directional:
 *
 *   - the patch is DROPPED while the catalog still says vitest 5 — every filtered mutant survives;
 *   - vitest is DOWNGRADED under a patch that stayed — the mirror image, equally silent.
 *
 * ⭐⭐ AND IT IS NOT HYPOTHETICAL. `M` 2026-09-13, the shared clone `/srv/integra/repos/integra-protocol`
 * declared `vitest: "5.0.0"` AND `patchedDependencies` while its `node_modules` held vitest 4.1.11 and an
 * UNPATCHED runner. A stale install that the declared configuration hid completely, on a box where a
 * measured run is taken by hand.
 *
 * ## ⭐ THE SUBJECT IS THE INSTALL, AND THAT IS THE POINT
 *
 * Three things must agree, and reading only two of them misses a real failure:
 *
 *   1. the CATALOG's vitest major — what this repository asked for;
 *   2. the INSTALLED vitest major — what `node_modules` actually holds;
 *   3. the INSTALLED runner's join spelling — what the filter will actually emit.
 *
 * ⛔ Comparing only (2) against (3) passes the stale clone above: an unpatched runner beside vitest 4 is
 * self-consistent. It is (1) that makes it a finding. ⛔ Comparing only (1) against the `patchedDependencies`
 * block reads a declaration rather than an install, which is the failure being guarded against.
 *
 * ## ⚠️ RESOLVED, NEVER GLOBBED
 *
 * `node_modules/.pnpm/@stryker-mutator+vitest-runner@*` matches MORE THAN ONE directory after a patch is
 * added or removed — the previous copy stays in the virtual store. `M` 2026-09-13 the same grep over that
 * glob answered `1` for the orphan and `0` for the live copy in one tree. A gate reading the glob would
 * report whichever it happened to see first. ⇒ Resolve what the tree actually links, and read that.
 */
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

/** The two files that carry `collectTestName`, and must agree with each other. */
const SITES = ["stryker-setup.js", "test-helpers.js"];

/**
 * ⛔ EACH SPELLING CARRIES A SAMPLE IT MUST MATCH. A predicate that stops matching reports every file
 * clean, which looks exactly like success — this repository has been bitten by that shape before, so the
 * canaries run on every invocation rather than living in a test that can be skipped.
 */
const PATCHED = "join(' > ')";
const UNPATCHED = "join(' ')";
const CANARIES = [
  [PATCHED, "return nameParts.join(' > ').trim();", true],
  [PATCHED, "return nameParts.join(' ').trim();", false],
  [UNPATCHED, "return nameParts.join(' ').trim();", true],
  [UNPATCHED, "return nameParts.join(' > ').trim();", false],
];

/**
 * ⭐ THE CANARIES, AS A FUNCTION, because a predicate that stops matching reports every file clean and
 * looks exactly like success. Exported so the drive can assert they discriminate rather than trusting that
 * they do.
 *
 * @returns {string[]} refusals; empty when every spelling still matches what it must and nothing else.
 */
export function canaryRefusals() {
  const refusals = [];
  for (const [needle, sample, shouldMatch] of CANARIES) {
    if (sample.includes(needle) !== shouldMatch)
      refusals.push(
        `canary: \`${needle}\` ${shouldMatch ? "no longer matches" : "now matches"} \`${sample}\` — the predicate moved, and a predicate that stops discriminating passes everything`,
      );
  }
  return refusals;
}

const major = (v) => Number.parseInt(v.split(".")[0], 10);

/**
 * ⭐⭐ THE WHOLE DECISION, AS A PURE FUNCTION OF THREE FACTS. Separated from the IO so the defect can be
 * PLANTED rather than described — `check:gate-drives` requires that, and it is right to: a gate is
 * finished when the thing it names has been re-planted and it went red.
 *
 * @param {object} facts
 * @param {string} facts.catalogVersion   what `pnpm-workspace.yaml` asks for
 * @param {string} facts.installedVitest  what `node_modules` actually holds
 * @param {Record<string,string>} facts.sites  each runner `dist/src` file's contents, keyed by filename
 * @returns {{refusals: string[], want: string, seen: string[]}}
 */
export function assess({ catalogVersion, installedVitest, sites }) {
  const refusals = [];
  // (1) vs (2) — the stale-install case, which a runner/vitest comparison alone would pass.
  if (major(installedVitest) !== major(catalogVersion))
    refusals.push(
      `the catalog asks for vitest ${catalogVersion} but ${installedVitest} is INSTALLED — a stale or overridden install, and every reading taken in this tree is about a version it does not declare. Run \`pnpm install\`.`,
    );
  // (3) — what the filter will actually emit.
  const wantPatched = major(catalogVersion) >= 5;
  const want = wantPatched ? PATCHED : UNPATCHED;
  const unwanted = wantPatched ? UNPATCHED : PATCHED;
  const seen = [];
  for (const site of SITES) {
    const src = sites[site];
    if (src === undefined) {
      refusals.push(
        `${site} is not in the installed runner — the package's layout moved and this gate is reading nothing`,
      );
      continue;
    }
    const has = src.includes(want);
    const hasOther = src.includes(unwanted);
    seen.push(`${site}=${has ? want : hasOther ? unwanted : "NEITHER"}`);
    if (!has)
      refusals.push(
        `${site} does not spell \`${want}\`${hasOther ? ` — it spells \`${unwanted}\`` : " and spells neither form"}`,
      );
  }
  return { refusals, want, seen };
}

/**
 * The catalog's vitest pin, read without a YAML dependency (not every repository in this line has one).
 *
 * ⚠️ ACCEPTS BOTH SPELLINGS — `vitest: "5.0.0"` and bare `vitest: 5.0.0`. A key regex that assumes quoting
 * is a recorded failure in this corpus: one over the ratchet floors returned 48 against a true 56 because
 * eight entries were written bare. ⛔ And it requires EXACTLY ONE match: zero means the catalog moved and
 * this gate is reading nothing, which is the empty-subject-set defect and must refuse rather than pass.
 *
 * @param {string} root workspace root
 * @returns {{version?: string, error?: string}}
 */
export function catalogVitest(root) {
  const file = join(root, "pnpm-workspace.yaml");
  if (!existsSync(file)) return { error: "pnpm-workspace.yaml is not there" };
  const matches = [
    ...readFileSync(file, "utf8").matchAll(
      /^[ \t]+"?vitest"?[ \t]*:[ \t]*"?([0-9]+\.[0-9]+\.[0-9]+[^"#\s]*)"?/gm,
    ),
  ];
  if (matches.length !== 1)
    return {
      error: `expected exactly one catalog \`vitest:\` line in pnpm-workspace.yaml, found ${String(matches.length)} — refusing rather than reading an empty or ambiguous subject set`,
    };
  return { version: matches[0][1] };
}

/** ⛔ Fails CLOSED. A tool this gate cannot find is not a tool this gate may pass over. */
function resolvePkg(require_, name) {
  try {
    return dirname(require_.resolve(`${name}/package.json`));
  } catch {
    return null;
  }
}

function main() {
  const canaries = canaryRefusals();
  if (canaries.length > 0) {
    console.error(`⛔ check:runner-patch — ${canaries.join("; ")}`);
    process.exit(1);
  }

  const catalog = catalogVitest(root);
  if (catalog.error !== undefined) {
    console.error(`⛔ check:runner-patch — ${catalog.error}`);
    process.exit(1);
  }

  const require_ = createRequire(join(root, "noop.js"));
  const vitestDir = resolvePkg(require_, "vitest");
  const runnerDir = resolvePkg(require_, "@stryker-mutator/vitest-runner");
  if (vitestDir === null || runnerDir === null) {
    console.error(
      `⛔ check:runner-patch — cannot resolve ${vitestDir === null ? "vitest" : "@stryker-mutator/vitest-runner"} from ${root}.\n` +
        "   Run `pnpm install`. An unresolvable tool is refused rather than skipped: the whole point of this\n" +
        "   gate is that the INSTALL is its subject, and an absent install answers nothing.",
    );
    process.exit(1);
  }

  const installedVitest = JSON.parse(
    readFileSync(join(vitestDir, "package.json"), "utf8"),
  ).version;

  /** @type {Record<string,string>} */
  const sites = {};
  for (const site of SITES) {
    const file = join(runnerDir, "dist", "src", site);
    if (existsSync(file)) sites[site] = readFileSync(file, "utf8");
  }

  const { refusals, want, seen } = assess({
    catalogVersion: catalog.version,
    installedVitest,
    sites,
  });

  if (refusals.length > 0) {
    console.error(
      `\n⛔ check:runner-patch — the installed Stryker runner does not match the catalog's vitest major.\n\n` +
        refusals.map((r) => `   • ${r}`).join("\n") +
        `\n\n   catalog vitest ${catalog.version} · installed vitest ${installedVitest} · runner at ${runnerDir}\n\n` +
        "   ⛔⛔ THIS DOES NOT FAIL LOUDLY ON ITS OWN. vitest skips every test whose name the pattern does not\n" +
        "   match and exits 0, so Stryker records those mutants as SURVIVED and the mutation score collapses\n" +
        "   toward the static-mutants-only floor — or, where a ratchet sits below that, stays GREEN over a\n" +
        "   suite that ran nothing. Fix the install before trusting any mutation number from this tree.\n",
    );
    process.exit(1);
  }

  console.log(
    `check:runner-patch — catalog vitest ${catalog.version}, installed ${installedVitest}, runner spells \`${want}\` in both sites (${seen.join(", ")}), ${String(CANARIES.length)}/${String(CANARIES.length)} canaries.`,
  );
}

// ⭐ Importable without running: the drive loads this module to plant defects into `assess`, and a gate
// that executed on import could not be driven that way.
if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
)
  main();
