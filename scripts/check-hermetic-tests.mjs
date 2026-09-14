#!/usr/bin/env node
/**
 * `check:hermetic-tests` — a test must not reach a third party.
 *
 * ⛔⛔ **PORTED FROM `integra-protocol`, WHICH PORTED IT FROM THE SELLER-SIDE REPOSITORY, WHERE THE DEFECT
 * ACTUALLY SHIPPED.** That repository committed a plain `.test.ts` whose second case read a chain tip and
 * an account's UTXOs from **Koios** — no env gate, no skip rule — so every `pnpm verify` in every
 * environment made a live HTTP call to a third-party indexer. ⚠️ **That measurement is COMMERCE'S** and is
 * cited as history rather than restated as a local finding: carrying a number across a port is how a claim
 * nobody measured ends up in a file nobody audits.
 *
 * ⭐ **WHAT IS TRUE HERE, measured 2026-09-14 at `2334b49`:** the class is **clean today**. 25 test files
 * under `packages/` and 6 drives under `scripts/`; the hosts they name are values in fixtures, and the two
 * drives that exercise network-facing gates drive them against a LOCAL `node:http` server and a fixed
 * table. ⇒ **This gate closes no live defect. It notices the next one**, which is the whole of its value:
 * the planning register's #87 is the record that the class does not stay clean on its own, and it did not —
 * in the repository that already had the gate, one `import` outside its subject set.
 *
 * ## ⛔⛔ THIS REPOSITORY HAS NO LIVE-HARNESS CONVENTION, AND THAT IS A MEASURED ANSWER
 *
 * Commerce excludes `*.live.test.ts`. Protocol has none of those and excludes `integration*.test.ts`
 * instead — and a port that had carried commerce's spelling would have swept all 11 of its rail harnesses
 * into the subject set and reddened on the real endpoints they exist to reach. **The port's hardest part is
 * not the script; it is discovering that the local convention differs.**
 *
 * `M` 2026-09-14 at `2334b49`, this repository's answer is a THIRD one: **there is no live harness at all.**
 * 0 files match either sibling's spelling, and no package exposes a live/rail script — every package's
 * `test` is a plain `vitest run`. ⇒ **There is no exclusion, because there is nothing to exclude**, and
 * every test is in the subject set.
 *
 * ⛔ That absence is asserted rather than assumed. If a file appears under either sibling's spelling this
 * gate REFUSES and says so, instead of choosing for you. Silently excluding it would fail open — a live
 * harness nobody declared would leave the subject set on the strength of its filename. Silently sweeping it
 * in would fail closed but illegibly, reddening on endpoints the file exists to reach. **A convention this
 * repository has not adopted is a decision, not a default.**
 *
 * ## ⭐ THE SUBJECT SET IS BOTH TEST ROOTS, WHICH IS ALSO LOCAL
 *
 * Commerce's drives sit in `scripts/`, outside its gate's walk. Protocol's are `packages/rail-invariants/
 * test/`, inside it. **This repository runs BOTH** — `pnpm -r test` walks `packages/`, and `pnpm
 * test:scripts` runs 6 `scripts/*.test.mjs` drives, and both are stages of `verify`.
 *
 * ⛔ So both are walked, and `scripts/` is the half that matters most: it is where this repository's
 * network-facing code lives. `check-protocol-currency.mjs`, `reconcile-tags.mjs` and `approve-staged.mjs`
 * all `fetch`, and their drives IMPORT them — so a drive's third-party reach is exactly what a walk of
 * `packages/` alone would not see.
 *
 * ⚠️ **This gate's own drive is therefore inside its own subject set** — it is counted among the test
 * files below. Its planted host needs no exemption, because the drive composes every planted URL through a
 * template literal (`https://${PLANT}/tip`) and the authority rule above reports nothing for an
 * interpolated host. ⛔ That is a property of how the drive is written, not a licence: spelling the host
 * literally there would redden this gate, correctly, and would then have to be declared. `integra-protocol`'s
 * drive takes the other route and carries a `namedNotCalled` entry closed in both directions.
 *
 * ## ⭐ THE SUBJECT SET IS THE IMPORT GRAPH, NOT THE TEST FILE — `#87`'s widening, carried
 *
 * A host NAMED in a test and a host CALLED by one look identical to a grep, and a client that takes its
 * address from `process.env` writes no host into the file at all. So this gate reads **every test AND every
 * module a test imports**, and accounts for each third-party import as `inert`, `addressed-in-source` or
 * `endpoint-from-environment`. ⛔ A port without this widening is the empty-subject-set defect re-imported:
 * commerce's gate read the importer and never the import, and the Koios host in its own head note sat one
 * `import` outside its reach.
 *
 * ⛔ **Closed in both directions**: an undeclared host or import fails, and a declaration that matches
 * nothing in the tree fails too, because an exception that has stopped applying is one nobody notices has
 * gone stale.
 *
 * ⚠️ `*.example`, `*.test`, `*.invalid` and `example.com/org/net` are RESERVED for documentation and
 * testing (RFC 2606 / RFC 6761) and resolve nowhere, so they need no exception. Loopback needs none either:
 * a test that binds its own socket and talks to it is hermetic.
 *
 * USAGE
 *   node scripts/check-hermetic-tests.mjs
 *   INTEGRA_GATE_ROOT=<dir> node scripts/check-hermetic-tests.mjs   # a fixture (the drive uses this)
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

// ⛔ Normalised to a trailing separator. `new URL("..", import.meta.url).pathname` ends in one and a
// directory handed in by a drive does not, so a gate that builds paths by concatenation reads
// `/tmp/xyzpackages` and dies on a path that never existed.
const root_RAW =
  process.env["INTEGRA_GATE_ROOT"] ?? new URL("..", import.meta.url).pathname;
const root = root_RAW.endsWith("/") ? root_RAW : `${root_RAW}/`;

/**
 * ⛔ Held in the TREE, not in this file: a table baked into a gate makes the gate undrivable, because it
 * can only ever run against the one tree whose hosts it already lists.
 */
const DECLARATIONS_PATH = join(
  root,
  "scripts",
  "hermetic-tests.declarations.json",
);
if (!existsSync(DECLARATIONS_PATH)) {
  console.error(
    `\nRefusing to verify: check:hermetic-tests — no declarations file at ` +
      `${DECLARATIONS_PATH.slice(root.length)}.\n\n` +
      "   This gate's exception table lives in the tree. Without it the gate would refuse every host any\n" +
      "   fixture names, which is not the property it checks.\n",
  );
  process.exit(1);
}
const declarations = JSON.parse(readFileSync(DECLARATIONS_PATH, "utf8"));
const NAMED_NOT_CALLED = declarations.namedNotCalled;

const die = (message) => {
  console.error(`\nRefusing to verify: check:hermetic-tests — ${message}\n`);
  process.exit(1);
};

/** Hosts that resolve nowhere by standard, so a test naming one cannot reach anything. */
const RESERVED =
  /(^(localhost|0\.0\.0\.0)$)|(^127\.)|(^\[?::1\]?$)|(\.(example|test|invalid|localhost)$)|((^|\.)example\.(com|org|net)$)/;

/**
 * Every test file spelling this repository uses — `M` 2026-09-14: 25 `.test.ts` under `packages/` and 6
 * `.test.mjs` under `scripts/`. `.tsx` is carried from the siblings because a React suite reaches a network
 * exactly as a `.ts` one does and the extension it is written in is not a property of anything.
 */
const TEST_FILE = /\.test\.(?:ts|tsx|mjs)$/;

/**
 * ⛔⛔ THE SIBLING SPELLINGS, PRESENT ONLY TO REFUSE. See the head note: this repository has no live-harness
 * convention, so a file wearing one of these names is an undeclared decision rather than an exclusion.
 */
const SIBLING_LIVE_FILE = (name) =>
  name.endsWith(".live.test.ts") ||
  (name.startsWith("integration") && name.endsWith(".test.ts"));

const TEST_ROOT = /(?:^|\/)(?:test|tests|__tests__)\//;
const MODULE_FILE = /\.(?:ts|tsx|mts|cts|mjs|cjs|js)$/;

const files = [];
const siblingLive = [];
const supportOnDisk = [];
const walk = (dir) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "dist") continue;
      walk(path);
      continue;
    }
    if (TEST_FILE.test(entry.name)) {
      if (SIBLING_LIVE_FILE(entry.name)) siblingLive.push(path);
      files.push(path);
      continue;
    }
    const relative = path.slice(root.length);
    // ⚠️ Matched against the path RELATIVE to the root: a drive's scratch directory is free to have `test`
    // somewhere in its own absolute path, and matching that would sweep the whole tree in.
    if (MODULE_FILE.test(entry.name) && TEST_ROOT.test(relative))
      supportOnDisk.push(path);
  }
};
for (const dir of ["packages", "scripts"])
  if (existsSync(`${root}${dir}`)) walk(`${root}${dir}`);

// ⛔ The convention refusal. Before the vacuity guard, because it is a stronger statement about the tree.
if (siblingLive.length > 0)
  die(
    `${String(siblingLive.length)} file(s) are named for a live-harness convention this repository has not\n` +
      "adopted:\n\n" +
      `${siblingLive.map((f) => `     ${f.slice(root.length)}`).join("\n")}\n\n` +
      "   The seller-side repository excludes `*.live.test.ts` from hermeticity and `integra-protocol`\n" +
      "   excludes `integration*.test.ts`. This repository has neither, and every test is in the subject\n" +
      "   set. Excluding this file silently would fail OPEN — a harness would leave the subject set on the\n" +
      "   strength of its filename, with nobody having decided that it may reach a network.\n\n" +
      "   ⇒ Either rename it, or adopt a live-harness convention here deliberately: give it an env gate,\n" +
      "   name the predicate in this file, and say in the changeset which network it is allowed to reach.",
  );

// The defect this estate has produced most often: a gate whose subject set silently empties and then
// reports success over nothing. It cannot here.
if (files.length === 0)
  die(
    "NO test files were found, which means this enumeration is wrong rather than that the tree is clean.",
  );

const sources = new Map();
const sourceOf = (file) => {
  if (!sources.has(file)) sources.set(file, readFileSync(file, "utf8"));
  return sources.get(file);
};

/**
 * Every module specifier a file names, in all five forms.
 *
 * ⛔ **THREE OF THE FIVE WERE ADDED AFTER SOMETHING GOT PAST**, in the repository this came from: an
 * adversarial reviewer walked an unclassified client through twice — `import "redis";`, a side-effect
 * import with no `from`, and `export { createClient } from "redis";`, an import wearing an export's
 * clothes. Both bring the module into the process exactly as a named import does.
 */
const specifiersOf = (source) => {
  const specifiers = new Set();
  for (const match of source.matchAll(
    /(?:^|\n)\s*import[^;]*?from\s*["']([^"']+)["']|(?:^|\n)\s*import\s+["']([^"']+)["']|(?:^|\n)\s*export[^;]*?from\s*["']([^"']+)["']|\bimport\(\s*["']([^"']+)["']\s*\)|\brequire\(\s*["']([^"']+)["']\s*\)/g,
  ))
    specifiers.add(match[1] ?? match[2] ?? match[3] ?? match[4] ?? match[5]);
  return specifiers;
};

/**
 * A relative specifier, resolved to the file on disk that actually answers it.
 *
 * ⚠️ TypeScript's NodeNext resolution means the SOURCE says `./x.js` and the file is `.ts`. A walk that
 * took the specifier literally would resolve nothing, find no helpers, and go quiet — which is the same
 * silence this gate is being added for. Failing to resolve is therefore a FINDING below, not a `continue`.
 */
const resolveRelative = (from, specifier) => {
  const base = resolve(dirname(from), specifier);
  const emitted = /\.(?:js|jsx|mjs|cjs)$/.exec(base);
  const candidates = [];
  if (emitted !== null) {
    const stem = base.slice(0, -emitted[0].length);
    candidates.push(`${stem}.ts`, `${stem}.tsx`, `${stem}.mts`, `${stem}.cts`);
  }
  candidates.push(
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.mts`,
    `${base}.cts`,
    `${base}.mjs`,
    `${base}.js`,
    `${base}.json`,
    `${base}/index.ts`,
    `${base}/index.tsx`,
  );
  for (const candidate of candidates)
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  return null;
};

const unresolved = new Set();
/** `dist/` is `src/` after a build, and `src/` is another gate's subject. */
const BUILT = /(?:^|\/)dist\//;

/**
 * Every non-test module this file reaches by relative import, transitively.
 *
 * ⚠️ `src/` is NOT excluded here the way it is in `integra-protocol`. That repository excludes it because
 * `check:no-callback` polices the same hosts in production source; this repository has no such gate, so a
 * test that imports `../src/fetch.js` and reaches a host through it would otherwise be invisible. ⇒ The
 * walk follows `src/` too, and the declarations carry what it finds.
 */
const supportReachedBy = (file, record) => {
  const reached = new Set();
  const seen = new Set([file]);
  const queue = [file];
  while (queue.length > 0) {
    const current = queue.pop();
    for (const specifier of specifiersOf(sourceOf(current))) {
      if (!specifier.startsWith(".")) continue;
      if (BUILT.test(specifier)) continue;
      const resolved = resolveRelative(current, specifier);
      if (resolved === null) {
        if (record)
          unresolved.add(`${current.slice(root.length)} → ${specifier}`);
        continue;
      }
      if (seen.has(resolved)) continue;
      seen.add(resolved);
      if (TEST_FILE.test(resolved)) continue;
      reached.add(resolved);
      // A `.json` vector is data: it carries hosts to scan and no imports to follow.
      if (!resolved.endsWith(".json")) queue.push(resolved);
    }
  }
  return reached;
};

const reached = new Map();
const support = new Set(supportOnDisk);
for (const file of files) {
  const modules = supportReachedBy(file, true);
  reached.set(file, modules);
  for (const module of modules) support.add(module);
}

/** Everything the host scan reads: the tests, and the modules they can execute. */
const scanned = [...files, ...support];

/**
 * ⛔⛔ **THE HOST PATTERN SKIPS USERINFO, AND THIS PORT IS WHAT FOUND THAT.**
 *
 * The pattern this gate was born with is `https?:\/\/([A-Za-z0-9._-]+)` — and `:` and `@` are outside that
 * character class, so on a URL carrying credentials it captures the USERNAME and never the host. `M`
 * 2026-09-14, driven against `integra-protocol`'s copy at `a59607a`: a test containing
 * `fetch("https://user@api.evil-third-party.com/steal")` is reported as naming the host **`user`**.
 *
 * ⚠️ The gate still goes red, so this is not a silent pass — but the DECLARATION path is poisoned, and that
 * is the defect. A reader meeting `user` reasonably records it as a placeholder in a credential fixture,
 * and that one entry then exempts **every credentialed URL to every third party**, permanently, because the
 * scan never sees anything else. Driven, same copy: with `"user"` declared, a file fetching
 * `https://user@api.evil-third-party.com/exfiltrate` AND `https://user@another-real-host.net/also` exits
 * **0** and prints `1 third-party host(s), each enumerated as named-not-called`.
 *
 * ⇒ Optional `userinfo@` is consumed before the host is captured. The authority ends at `/`, `?` or `#`
 * (RFC 3986), so those are excluded from the userinfo run — otherwise `https://h.example?x=a@b` would eat
 * the query string and capture `b`.
 *
 * ⚠️ `integra-protocol` and the seller-side repository both carry the original line — planning register #147.
 */
const URL_AUTHORITY = /https?:\/\/([^/?#\s"'`]*)/g;

/**
 * The host an occurrence actually names, or `null` when it names none.
 *
 * ⛔ Three things the pattern this gate was ported with got wrong, each found by driving it:
 *
 * 1. **USERINFO.** `https?:\/\/([A-Za-z0-9._-]+)` stops at `:` and `@`, so on a credentialed URL it
 *    captured the USERNAME. Driven against `integra-protocol`'s copy at `a59607a`, a test containing
 *    `fetch("https://user@api.evil-third-party.com/steal")` was reported as naming the host `user`. The
 *    gate still went red, so it was never a silent pass — but the DECLARATION path was poisoned: a reader
 *    meeting `user` reasonably records it as a placeholder in a credential fixture, and that one entry
 *    then exempts **every credentialed URL to every third party**, because the scan never sees anything
 *    else. Driven on that copy: with `"user"` declared, a file fetching two real hosts behind that
 *    userinfo exits **0** and prints `1 third-party host(s), each enumerated as named-not-called`.
 * 2. **INTERPOLATION INSIDE THE AUTHORITY.** `https://u:p@${HOST}/x` names no host at all, and the
 *    trailing-`$` check cannot see it because the `$` is not at the end of the match. ⭐ This gate's own
 *    drive is what surfaced it. The authority is truncated at the first `${`, so only what is literally
 *    written counts — and `https://real.example.com${path}` still names its host, which a blanket skip
 *    would have lost.
 * 3. **IPv6 LITERALS.** `[::1]` must not be split on its own colons.
 *
 * ⚠️ `integra-protocol` and the seller-side repository both still carry the original line — planning
 * register #147.
 */
const hostOf = (authority) => {
  const literal = authority.split("${")[0];
  const at = literal.lastIndexOf("@");
  const hostPort = at === -1 ? literal : literal.slice(at + 1);
  if (hostPort === "") return null;
  // ⛔ 4. **A HOST MUST LOOK LIKE ONE.** Capturing the authority rather than the host charset lost the
  // implicit validation the original pattern got for free, and elided prose walked straight in:
  // `reconcile-tags.mjs` quotes a git error as `To https://github.com/…`, and a bare `https://…` in a
  // comment was reported as a third-party host named `…`. The leading host-shaped run is taken, so
  // `github.com/…` still yields `github.com` and `…` yields nothing.
  if (hostPort.startsWith("[")) {
    const close = hostPort.indexOf("]");
    return close === -1 ? null : hostPort.slice(0, close + 1).toLowerCase();
  }
  const host = /^[A-Za-z0-9._-]+/.exec(hostPort.split(":")[0]);
  return host === null ? null : host[0].toLowerCase();
};

const found = new Map();
for (const file of scanned) {
  const source = sourceOf(file);
  for (const match of source.matchAll(URL_AUTHORITY)) {
    // ⛔ LOWERCASED by `hostOf`. Host names are case-insensitive (RFC 4343) and `RESERVED` carries no `i`
    // flag, so `https://Seller.Example/Terms` would otherwise read as an undeclared third party despite
    // `.example` being RFC 2606 reserved — and declaring it would write a permanent exception for a host
    // that does not exist, to work around a case-sensitive regex.
    const host = hostOf(match[1]);
    if (host === null) continue;
    if (RESERVED.test(host)) continue;
    if (!found.has(host)) found.set(host, new Set());
    found.get(host).add(file.slice(root.length));
  }
}

/**
 * ⛔⛔ **A HOST SCAN CANNOT SEE A CLIENT THAT TAKES ITS ADDRESS FROM THE ENVIRONMENT.** In the repository
 * this came from, a plain `.test.ts` opened a real `pg.Pool`; it was honest — `describe.skip`ped unless
 * `POSTGRES_TEST_URL` was set — but the connection string never appeared in the file, so a host scan had
 * nothing to find.
 *
 * ⇒ A second subject set, and it is the IMPORTS rather than a roster of clients: every third-party
 * specifier is classified, and an unclassified one fails. That is what makes a NEW client of the third kind
 * a build failure the day it arrives rather than a blind spot nobody has noticed yet.
 */
const IMPORTS = declarations.imports ?? {};
const KINDS = ["inert", "addressed-in-source", "endpoint-from-environment"];

/**
 * The conditional-suite forms, with the CONDITION captured — because the condition is the whole question.
 *
 * ⛔⛔ **AN UNRELATED CONDITION IS NOT AN ENVIRONMENT GATE.** An earlier version tested only that some
 * conditional form appeared somewhere in the file, so a suite opening a real pool at module scope passed by
 * carrying `describe.skipIf(process.platform === "win32")` — a condition about the operating system.
 */
const CONDITIONAL_SUITE =
  /\b(?:describe|it|test)\.(?:skipIf|runIf)\(([^;]*?)\)\s*[(,]|([^\n;]*?)\?\s*describe\s*:\s*describe\.skip|([^\n;]*?)\?\s*describe\.skip\s*:\s*describe/g;

/** Every identifier this file — or a sibling — binds from `process.env`. The names a gate may turn on. */
const envBound = (sources) => {
  const names = new Set();
  for (const source of sources)
    for (const match of source.matchAll(
      /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*process\.env\[/g,
    ))
      names.add(match[1]);
  return names;
};

const envGated = (source, names) => {
  if (names.size === 0) return false;
  for (const match of source.matchAll(CONDITIONAL_SUITE)) {
    const condition = match[1] ?? match[2] ?? match[3] ?? "";
    if (/process\.env\[/.test(condition)) return true;
    for (const name of names)
      if (new RegExp(`\\b${name}\\b`).test(condition)) return true;
  }
  return false;
};

/**
 * Every third-party specifier this file names. Relative imports are this repository's own source and are
 * followed above; workspace `@integraledger/` packages are covered by every gate that runs over them.
 */
const importsOf = (source) =>
  new Set(
    [...specifiersOf(source)].filter(
      (specifier) =>
        !specifier.startsWith(".") && !specifier.startsWith("@integraledger/"),
    ),
  );

const problems = [];

/** The environment-bound identifiers visible to a test — its own, plus its directory's. */
const envNames = new Map();
const envNamesNear = (file) => {
  const dir = file.slice(0, file.lastIndexOf("/"));
  if (!envNames.has(dir))
    envNames.set(
      dir,
      envBound(
        readdirSync(dir, { withFileTypes: true })
          .filter((entry) => entry.isFile() && MODULE_FILE.test(entry.name))
          .map((entry) => readFileSync(`${dir}/${entry.name}`, "utf8")),
      ),
    );
  return envNames.get(dir);
};

const importsSeen = new Set();
/** What each file classifies to, so a test can be judged on what its HELPERS bring in as well. */
const fromEnvironmentIn = new Map();
// ⭐ Over `scanned`, not over `files`: a helper's client is the test's client. Classifying only the
// importer is the same mistake as host-scanning only the importer.
for (const file of scanned) {
  if (file.endsWith(".json")) continue;
  const unclassified = [];
  const fromEnvironment = [];
  for (const specifier of importsOf(sourceOf(file))) {
    importsSeen.add(specifier);
    const entry = IMPORTS[specifier];
    if (entry === undefined || !KINDS.includes(entry.kind)) {
      unclassified.push(specifier);
      continue;
    }
    if (entry.kind === "endpoint-from-environment")
      fromEnvironment.push(specifier);
  }
  fromEnvironmentIn.set(file, fromEnvironment);
  if (unclassified.length > 0)
    problems.push(
      `  ${file.slice(root.length)}\n` +
        `      imports ${unclassified.map((s) => `\`${s}\``).join(", ")}, which nothing classifies.\n` +
        `      Say in scripts/hermetic-tests.declarations.json which of ${KINDS.join(" / ")} it is, and\n` +
        "      why. A client whose address comes from the environment writes no host into the file, so the\n" +
        "      host scan cannot see it.",
    );
}

// ⚠️ The GATE is a property of the test file, never of the helper: a fixture module has no suite to skip,
// so demanding a condition of it would be demanding something it cannot express.
for (const file of files) {
  const fromEnvironment = [
    ...new Set(
      [file, ...(reached.get(file) ?? [])].flatMap(
        (module) => fromEnvironmentIn.get(module) ?? [],
      ),
    ),
  ];
  if (
    fromEnvironment.length > 0 &&
    !envGated(sourceOf(file), envNamesNear(file))
  )
    problems.push(
      `  ${file.slice(root.length)}\n` +
        `      imports ${fromEnvironment.map((s) => `\`${s}\``).join(", ")}, whose address comes from the\n` +
        "      environment, and is not gated on the variable it needs. A `pnpm verify` that dials a\n" +
        "      third party fails red for a reason that is not in the tree.",
    );
}

// ⛔ An import this walk could not resolve is a module it did not read, and a module it did not read is
// precisely the blind spot being closed. It is a finding, not a `continue`.
for (const edge of unresolved)
  problems.push(
    `  ${edge}\n      is a relative import this gate could not resolve to a file, so the module it names\n` +
      "      was never scanned. A subject set with a hole in it reports green over the hole.",
  );

// ⛔ The vacuity guard, stated as a RELATION rather than "the table is non-empty": a tree whose tests import
// nothing third-party has nothing to classify, and demanding a table for it would be this gate refusing a
// clean fixture. What is refused is imports with no classifications at all.
if (importsSeen.size > 0 && Object.keys(IMPORTS).length === 0)
  die(
    `${String(importsSeen.size)} third-party import(s) appear in tests and the declarations file classifies\n` +
      "none of them. An empty table over a non-empty tree asserts nothing while printing success.",
  );

for (const specifier of Object.keys(IMPORTS))
  if (!importsSeen.has(specifier))
    problems.push(
      `  ${specifier}\n      is classified in the declarations and no test imports it. Delete the entry:\n` +
        "      a classification that classifies nothing reads as one that does.",
    );

for (const [host, where] of found)
  if (NAMED_NOT_CALLED[host] === undefined)
    problems.push(
      `  ${host}\n      named by: ${[...where].join(", ")}\n` +
        "      A test may not reach a third party. If this host is FETCHED, drive it against a local server\n" +
        "      or a fixed table as this repository's other drives do. If it is only a value in a fixture,\n" +
        "      add it to namedNotCalled with the reason — after reading the occurrence.",
    );

for (const host of Object.keys(NAMED_NOT_CALLED))
  if (!found.has(host))
    problems.push(
      `  ${host}\n      is listed in namedNotCalled and appears in no test. Delete the entry: an exception\n` +
        "      that excludes nothing reads as one that does.",
    );

if (problems.length > 0) {
  console.error(
    "\nRefusing to verify: check:hermetic-tests\n\n" +
      `${problems.join("\n\n")}\n`,
  );
  process.exit(1);
}

// ⭐ The subject set is PRINTED, in its parts, because the whole of this gate's 2026-09-10 defect in the
// repository it came from was that nobody could see what it had enumerated.
const ts = files.filter((f) => f.endsWith(".test.ts")).length;
const mjs = files.filter((f) => f.endsWith(".test.mjs")).length;
const tsx = files.filter((f) => f.endsWith(".test.tsx")).length;
console.log(
  `check:hermetic-tests — scanned ${String(scanned.length)} file(s): ` +
    `${String(files.length)} test file(s) (${String(ts)} .test.ts + ${String(tsx)} .test.tsx + ` +
    `${String(mjs)} .test.mjs) across packages/ and scripts/, and ${String(support.size)} module(s) they ` +
    `import; ${String(found.size)} third-party host(s), each enumerated as named-not-called; ` +
    `${String(importsSeen.size)} third-party import(s), each classified, and every one whose endpoint ` +
    "comes from the environment behind a gate. No live-harness convention here, and none claimed. OK",
);
