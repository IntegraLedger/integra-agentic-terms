#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
/**
 * Seal the protocol identities this gate reads off the wire, and refuse a peer range this repository has
 * never tested against.
 *
 * WHY A GATE AND NOT A TEST. The identities here are not this package's to choose. `com.integraledger.
 * legal_context`, `/.well-known/legal-context.json`, and the field each commerce protocol carries a
 * reference in are the Legal Context Protocol's, and a seller's writer matches on exactly the same values
 * this gate's reader does. They arrive from `@integraledger/lcp-*` at whatever version is installed, so a
 * dependency bump can change what this gate looks for without changing a line of code in this repository.
 *
 * A test suite cannot catch that, and the reason is structural rather than a gap in coverage: a fixture
 * asserting a constant is written against the same installed version the code reads it from, so both sides
 * of the assertion move together and the suite stays green through the change. Sealing the values in a file
 * that does NOT move with the dependency is what makes the change visible.
 *
 * WHAT THE SEAL MEANS. Every value in `wire-identities.seal.json` is one a counterparty already has to know
 * to interoperate with this gate. A diff here is therefore a change to what a seller must write for this
 * buyer to accept it — not a refactor, and not a version bump. Resealing with `pnpm seal:wire` is a
 * deliberate line in a diff a reviewer sees.
 *
 * THE PEER CHECK. This package takes the protocol line as a `peerDependency` so the consumer owns one copy
 * of it — two copies in one tree break `instanceof` across the boundary. That shifts a burden onto this
 * repository: the range is a promise about versions we do not install, and the only version we actually
 * exercise is the exact pin in `devDependencies`. So this refuses a peer without a matching dev pin, a dev
 * pin outside its own peer range, and dev pins that are not all one version.
 *
 * ⚠️ WHAT THIS FILE CANNOT DO, STATED SO NOBODY RELIES ON IT. A caret anchored at the dev pin satisfies
 * every rule here by construction — that is what a caret IS — so this gate can never establish that the
 * range as a whole works. `^0.12.0` admits versions CI has never installed, and the promise is kept by the
 * scheduled `protocol-latest` workflow, which installs the line at `latest` and runs the full chain. This
 * gate proves the range is COHERENT; that workflow proves it is TRUE.
 *
 * ⛔ THE VERSION IS NOT SEALED HERE, AND MUST NOT BE. A `protocolLine` field once sat in the seal beside
 * the identities, read from the MANIFESTS while everything around it was read from the INSTALLED packages.
 * It therefore agreed with the manifest by construction and could not fail — a tree holding 0.10.1 under a
 * 0.12.0 manifest sealed clean — while a version bump that moved no identity at all failed loudly under
 * the words "a change to what a seller must write", making a reseal routine on every bump and hollowing
 * out the one control this file provides. Whether the tree matches its pins is `check:versions`' question
 * and is answered before this file runs.
 *
 * Regenerate deliberately with `pnpm seal:wire`, never to make a build pass.
 */
import { join } from "node:path";
import {
  isExact,
  isProtocolDep as isProtocolDepIn,
  readManifests,
  resolveEntry,
  satisfies,
  workspaceNames,
} from "./protocol-deps.mjs";

const root = new URL("..", import.meta.url).pathname;
const SEAL = join(root, "scripts", "wire-identities.seal.json");
const WRITE = process.argv.includes("--write");
/** Fixed sentinel for building a `namespaced` placement, whose field is templated on a deployment's own
 *  reverse-domain namespace. The namespace is the deployment's; the SUFFIX is the protocol's. */
const SEAL_NAMESPACE = "dev.seal";

const fail = [];

// WORKSPACE SIBLINGS ARE NOT THE PROTOCOL LINE, and the name prefix cannot tell them apart —
// `@integraledger/lcp-mcp-server` is published from this repository and matches `lcp-` exactly as
// `@integraledger/lcp-kernel` does. That distinction, and the resolution of a declared dep to what is
// actually installed, now live in `protocol-deps.mjs` so that every gate asking these questions gets the
// same answer. They were written twice before, and one copy did not know about siblings at all.
const manifestList = readManifests(root);
const manifests = manifestList.map((m) => [m.name, m.path]);
const WORKSPACE = workspaceNames(manifestList);
const isProtocolDep = (dep) => isProtocolDepIn(dep, WORKSPACE);

/* ---------- ONE: the exercised line is one line, and it satisfies every peer range ---------- */

const devLines = new Map(); // version -> [where]
const runtimeDeps = []; // { name, dep, spec } — shipped `dependencies`, checked once `line` is known
for (const [name, path] of manifests) {
  const pkg = JSON.parse(readFileSync(path, "utf8"));
  const peers = Object.entries(pkg.peerDependencies ?? {}).filter(([d]) =>
    isProtocolDep(d),
  );
  const devs = Object.fromEntries(
    Object.entries(pkg.devDependencies ?? {}).filter(([d]) => isProtocolDep(d)),
  );
  for (const [dep, spec] of Object.entries(pkg.dependencies ?? {}))
    if (isProtocolDep(dep)) runtimeDeps.push({ name, dep, spec });

  for (const [dep, exact] of Object.entries(devs)) {
    if (!isExact(exact)) {
      fail.push(
        `${name} → ${dep} is "${exact}" in devDependencies. The exercised version must be exact — it is the only one CI proves.`,
      );
      continue;
    }
    if (!devLines.has(exact)) devLines.set(exact, []);
    devLines.get(exact).push(`${name} → ${dep}`);
  }

  for (const [dep, range] of peers) {
    const exact = devs[dep];
    if (!exact) {
      fail.push(
        `${name} → ${dep} is a peer at "${range}" with no devDependency pin. Nothing installs it here, so the range is untested.`,
      );
      continue;
    }
    if (!satisfies(range, exact)) {
      fail.push(
        `${name} → ${dep}: devDependency ${exact} is outside the peer range "${range}". CI exercises a version a consumer cannot install.`,
      );
    }
    // ⛔ THE FLOOR IS THE MINOR LINE'S ZERO PATCH, AND RAISING IT IS A BREAKING CHANGE IN DISGUISE.
    // On a `0.x` version a caret pins the minor, so the patch is the only part of a peer range that moves
    // — and moving it UP stops a consumer sitting on an earlier patch of the SAME line from installing
    // this package at all. Semver already guarantees patch compatibility, so a raised floor buys nothing
    // and costs exactly those consumers. This matters because a bot proposes it: Dependabot updates
    // `peerDependencies` like any other field, so a routine-looking `^0.12.0 → ^0.12.2` arrives with no
    // author. There is deliberately no escape hatch — a genuine need for a patch floor is an argument to
    // have here, in this rule, not a range to slip through.
    if (!/^\^\d+\.\d+\.0$/.test(range)) {
      fail.push(
        `${name} → ${dep} is a peer at "${range}". A protocol peer range must be \`^X.Y.0\` — a raised floor strands consumers on earlier patches of the same line, and semver already guarantees those are compatible.`,
      );
    }
  }

  // A protocol package imported by shipped source must be a peer, or a consumer's install is incomplete.
  const srcDir = join(root, "packages", name, "src");
  if (existsSync(srcDir)) {
    // RECURSIVE. A flat `readdirSync` saw only the top level, so `src/tools/*.ts` — where one package keeps
    // every one of its tool implementations — was invisible to the peer-declaration rule below. It passed
    // because that package happens to declare all nine protocol packages directly; it would have gone on
    // passing the day one of them became a transitive-only import, which is precisely the case this rule
    // exists to catch. A checker that cannot see a directory reports it clean.
    const tsFiles = (dir) =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory()
          ? tsFiles(join(dir, e.name))
          : e.name.endsWith(".ts")
            ? [join(dir, e.name)]
            : [],
      );
    const src = tsFiles(srcDir)
      .map((f) => readFileSync(f, "utf8"))
      .join("");
    const imported = new Set(
      [...src.matchAll(/"(@integraledger\/lcp-[a-z0-9-]+)"/g)]
        .map((m) => m[1])
        .filter(isProtocolDep),
    );
    const declared = new Set(peers.map(([d]) => d));
    for (const dep of imported) {
      if (!declared.has(dep) && !(pkg.dependencies ?? {})[dep]) {
        fail.push(
          `${name} imports ${dep} from src but declares it neither as a peer nor a dependency — a consumer's install would be missing it.`,
        );
      }
    }
  }
}

if (devLines.size > 1) {
  const detail = [...devLines.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .map(([v, where]) => `    ${v}  (${where.length}) e.g. ${where[0]}`)
    .join("\n");
  fail.push(
    `the tree exercises ${devLines.size} protocol lines, and it must exercise one:\n${detail}`,
  );
}

const line = devLines.size === 1 ? [...devLines.keys()][0] : null;

// ⛔⛔ SHIPPED `dependencies` WERE NEVER IN THE LINE ACCOUNTING AT ALL, and that is not a small gap: they
// are the pins a CONSUMER actually installs. `devLines` was collected from `devDependencies` only, so nine
// runtime protocol pins sat outside every rule in this file — planting a different line in them left the
// gate printing `✓ one exercised protocol line`.
//
// The rule fits what a runtime dep IS. Not exact: an exact runtime pin is precisely what forces a SECOND
// COPY of the protocol into any tree that also holds this package's caret-peered sibling, which is the
// failure the peer design exists to prevent. Not wider than the line: a range past it is a claim nothing
// tests. So it is the caret at the exercised line, and nothing else.
//
// This also closes the escape hatch below, where declaring an exact runtime dep satisfied the
// "imported from src must be a peer" rule — after this, that declaration is refused on its own terms.
if (line) {
  // The SAME floor rule the peers get, and for the same reason: on a `0.x` line the patch is the only part
  // of a caret that moves, and raising it strands consumers on earlier patches. `pnpm up` demonstrated this
  // the first time it ran against these ranges — it rewrote `^0.12.0` to `^0.12.2` unprompted, which is
  // exactly what a Dependabot bump does. A rule that compared against the exercised version rather than its
  // minor's zero patch would have waved that straight through.
  const [major, minor] = line.split(".");
  const wanted = `^${major}.${minor}.0`;
  for (const { name, dep, spec } of runtimeDeps)
    if (spec !== wanted)
      fail.push(
        `${name} → ${dep} is "${spec}" in dependencies. A shipped protocol dependency must be \`${wanted}\` — exact forces a second copy of the protocol beside a caret-peered sibling, a raised floor strands consumers on earlier patches of the same line, and a wider range is untested.`,
      );
}

/* ---------- TWO: the wire identities are sealed ---------- */

async function identities() {
  const out = { capability: {}, placements: {} };

  const discovery = resolveEntry(manifestList, "@integraledger/lcp-discovery");
  if (!discovery)
    throw new Error("no package resolves @integraledger/lcp-discovery");
  const d = await import(discovery);
  for (const key of Object.keys(d).sort()) {
    if (/CAPABILITY_NAME|WELL_KNOWN_PATH/.test(key))
      out.capability[key] = d[key];
  }

  const placements = resolveEntry(
    manifestList,
    "@integraledger/lcp-placements",
  );
  if (!placements)
    throw new Error("no package resolves @integraledger/lcp-placements");
  const { PLACEMENTS } = await import(placements);
  for (const protocol of Object.keys(PLACEMENTS).sort()) {
    const entry = PLACEMENTS[protocol];
    const m =
      entry.kind === "namespaced"
        ? entry.build(SEAL_NAMESPACE).manifest
        : entry.adapter?.manifest;
    if (!m) {
      throw new Error(
        `placement "${protocol}" (kind=${entry.kind}) yielded no manifest — the seal would silently omit it`,
      );
    }
    out.placements[protocol] = {
      field: m.field,
      encoding: m.encoding,
      tier: m.tier,
    };
  }
  if (Object.keys(out.placements).length !== Object.keys(PLACEMENTS).length) {
    throw new Error("sealed fewer placements than the registry declares");
  }
  return out;
}

if (line) {
  const actual = await identities();

  if (WRITE) {
    writeFileSync(SEAL, `${JSON.stringify(actual, null, 2)}\n`);
    console.log(
      `sealed ${Object.keys(actual.placements).length} placements at protocol ${line}`,
    );
    process.exit(0);
  }

  if (!existsSync(SEAL)) {
    fail.push(
      "no seal at scripts/wire-identities.seal.json — run `pnpm seal:wire`",
    );
  } else {
    const a = JSON.stringify(actual, null, 2);
    const b = JSON.stringify(JSON.parse(readFileSync(SEAL, "utf8")), null, 2);
    if (a !== b) {
      const al = a.split("\n");
      const bl = b.split("\n");
      const delta = [];
      for (let i = 0; i < Math.max(al.length, bl.length); i++) {
        if (al[i] !== bl[i]) {
          if (bl[i] !== undefined) delta.push(`    - sealed  ${bl[i].trim()}`);
          if (al[i] !== undefined) delta.push(`    + actual  ${al[i].trim()}`);
        }
      }
      fail.push(
        "the wire identities changed. Every value here is one a counterparty must already know to\n" +
          "  interoperate with this gate, so this is a change to what a seller must write — not a refactor:\n" +
          delta.slice(0, 40).join("\n") +
          "\n\n  If the change is intended, reseal with `pnpm seal:wire` and say so in the changeset.",
      );
    }
  }
} else if (WRITE) {
  fail.push(
    "cannot seal while the tree exercises more than one protocol line — fix that first",
  );
}

/* ---------- THREE: the range the DOCS state is the range the gate declares ---------- */

/**
 * ⛔⛔ **A PUBLISHED DOC STATING A PEER RANGE GOES STALE SILENTLY, AND TWO OF THEM HAD.** Measured the day
 * this rule landed: `website/content/docs/quickstart.mdx` and `docs/reference/agentic-terms.mdx` both told a
 * reader the gate peers `^0.13.0` while `package.json` declared `^0.14.0`. Nothing was red. These are the
 * PUBLIC install instructions — a reader following them pins a line the gate no longer peers, and
 * discovers it as an unmet-peer warning they did not cause.
 *
 * ⭐ **Derived from the manifest, never written here.** The expected range is read off `agentic-terms`'s own
 * `peerDependencies`, so this cannot drift into a third statement of the same fact. Every doc that states
 * a range must state THAT one; a doc that stops stating it is fine — the rule is about being WRONG, not
 * about being silent, because these pages are prose and not an inventory.
 *
 * ⚠️ The subject is every `.md`/`.mdx` under `docs/` and `website/content/`, excluding dated records:
 * `docs/2026-*.md` are point-in-time documents, and rewriting one to match today would falsify a record
 * rather than fix a claim.
 */
if (line) {
  const guard = JSON.parse(
    readFileSync(
      join(root, "packages", "agentic-terms", "package.json"),
      "utf8",
    ),
  );
  const declared = new Set(
    Object.entries(guard.peerDependencies ?? {})
      .filter(([dep]) => /^@integraledger\/lcp-/.test(dep))
      .map(([, range]) => range),
  );
  if (declared.size !== 1)
    fail.push(
      `agentic-terms declares ${declared.size} distinct protocol peer range(s) (${[...declared].join(", ")}); ` +
        "this rule compares the documents against ONE, and with several there is no single answer to state.",
    );
  else {
    const expected = [...declared][0];
    const pages = [];
    const walk = (dir) => {
      if (!existsSync(dir)) return;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === "node_modules") continue;
          walk(path);
        } else if (
          /\.mdx?$/.test(entry.name) &&
          !/^2026-\d\d-\d\d/.test(entry.name)
        )
          pages.push(path);
      }
    };
    walk(join(root, "docs"));
    walk(join(root, "website", "content"));
    if (pages.length === 0)
      fail.push(
        "no .md/.mdx pages under docs/ or website/content — this rule read nothing and would report a pass",
      );
    for (const page of pages) {
      const text = readFileSync(page, "utf8");
      for (const m of text.matchAll(
        /protocol line (?:as|at) `(\^?\d+\.\d+\.\d+)`/g,
      ))
        if (m[1] !== expected)
          fail.push(
            `${page.slice(root.length)} states the protocol peer range as \`${m[1]}\`; agentic-terms declares ` +
              `\`${expected}\`.\n      These are install instructions: a reader following them pins a line the ` +
              "gate does not peer.",
          );
    }
  }
}

/* ---------- FOUR: a workspace sibling is declared `workspace:*`, never a published range ---------- */

/**
 * ⛔⛔ **A SIBLING DECLARED BY VERSION RANGE BREAKS EVERY RELEASE, AND IT BROKE THE LAST ONE.** The root
 * dev-depended on the PUBLISHED `@integraledger/lcp-mcp-server` at `^0.11.0` while `agentic-terms` — needed
 * by the same gate, for the same reason — was `workspace:*` beside it. `changeset version` rewrites an
 * internal reference to the version the release is CREATING, so the tree then refuses to install:
 *
 *     ERR_PNPM_NO_MATCHING_VERSION  No matching version found for @integraledger/lcp-mcp-server@^0.12.0
 *
 * The remedy applied at the time was to pin it back by hand and move it forward again after publish —
 * twice per release, forever, remembered by a person. That is not a policy; it is a defect with a rota.
 *
 * ⭐ **AND THE RANGE MEASURED THE WRONG ARTIFACT.** `check:docs` compiles every documentation fence at
 * this root, and three of them import `@integraledger/lcp-mcp-server` — two site pages and the package's
 * own README. Against a published range those fences were checked against the PREVIOUS release: a fence
 * using an API added in this tree fails though it is correct, and a fence using an API DELETED in this
 * tree passes though it is broken. `workspace:*` checks them against the code being shipped.
 *
 * The subject is `dependencies` and `devDependencies`. Peers are excluded deliberately — a published
 * package peering a sibling must state a range a consumer can satisfy, and no such peer exists here.
 */
for (const { name, pkg } of manifestList) {
  for (const field of ["dependencies", "devDependencies"]) {
    for (const [dep, spec] of Object.entries(pkg[field] ?? {})) {
      if (!WORKSPACE.has(dep) || spec.startsWith("workspace:")) continue;
      fail.push(
        `${name} → ${dep} is "${spec}" in ${field}, but ${dep} is a package in THIS workspace.\n      ` +
          "A sibling declared by published range makes `changeset version` rewrite it to the version the " +
          "release is creating, which cannot install — and it points every consumer of it at the PREVIOUS " +
          "release rather than the tree. Declare it `workspace:*`.",
      );
    }
  }
}

if (fail.length) {
  console.error("\n✕ wire-identity check failed\n");
  for (const f of fail) console.error(`  • ${f}\n`);
  process.exit(1);
}

console.log(
  `✓ one exercised protocol line (${line}), every peer range satisfied, wire identities match the seal`,
);
