/**
 * The drive for `check:published-dist-parity`.
 *
 * ⛔⛔ THE MOTIVATING FAILURE CANNOT BE PLANTED AGAINST THE LIVE REGISTRY, and that is a property of the
 * subject rather than a weakness of the drive: a published version is immutable, so there is no way to make
 * npm serve a stale `dist` beside a correct `src`. Every case that needs a defective artifact injects one.
 * ⭐ The live registry is still driven, once, as a control — see the last case — because a suite of
 * injected fixtures proves only that the gate agrees with fixtures.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  compare,
  DIST_FLOOR,
  distParityReport,
  hashTree,
  publishedDist,
  publishedSrc,
  verdict,
} from "./check-published-dist-parity.mjs";
import { NetworkRegistry } from "./check-published-parity.mjs";

const ROOT = new URL("../packages", import.meta.url).pathname;
const manifests = () =>
  readdirSync(ROOT).map((d) => ({
    dir: join(ROOT, d),
    pkg: JSON.parse(readFileSync(join(ROOT, d, "package.json"), "utf8")),
  }));

/** A registry that serves exactly the entries it is given, keyed `name@version`. */
const stubRegistry = (byPkg) => ({
  async metadata(name) {
    const versions = {};
    for (const key of Object.keys(byPkg))
      if (key.startsWith(`${name}@`))
        versions[key.slice(name.length + 1)] = {
          dist: { tarball: `https://example.invalid/${key}.tgz` },
        };
    return { versions };
  },
  async contents(name, version) {
    const e = byPkg[`${name}@${version}`];
    if (e === undefined) throw new Error(`no fixture for ${name}@${version}`);
    return e;
  },
});

/** Entries that agree with the tree: src hashed from disk, dist hashed from a build already on disk. */
const faithful = () => {
  const out = {};
  for (const { dir, pkg } of manifests()) {
    if (pkg.private === true) continue;
    const e = new Map();
    for (const [p, h] of hashTree(join(dir, "src"))) e.set(`src/${p}`, h);
    for (const [p, h] of hashTree(join(dir, "dist"))) e.set(`dist/${p}`, h);
    out[`${pkg.name}@${pkg.version}`] = e;
  }
  return out;
};

const noBuild = () => {};

test("⭐ THE CONTROL — entries that agree with the tree are parity, and the floor is met", async () => {
  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(faithful()),
    build: noBuild,
  });
  assert.deepEqual(r.drift, []);
  assert.deepEqual(r.faults, []);
  // Every publishable package in the tree has a faithful fixture here, so a healthy run compares all of
  // them and `ahead` is zero — which is what makes this the control for the live case further down.
  assert.equal(r.compared, DIST_FLOOR);
  assert.equal(r.ahead, 0);
  assert.equal(verdict(r).kind, "parity");
});

test("⛔⛔ THE MOTIVATING FAILURE — a STALE published dist beside a CORRECT src is DRIFT", async () => {
  // The whole reason this gate exists: `check:published-parity` compares src and is green, `check:runtime`
  // rebuilds dist from the tree and is green, and the artifact a consumer loads is old.
  const fx = faithful();
  const key = Object.keys(fx).find((k) =>
    k.startsWith("@integraledger/agentic-terms@"),
  );
  const e = new Map(fx[key]);
  const victim = [...e.keys()].find(
    (k) => k.startsWith("dist/") && k.endsWith(".js"),
  );
  e.set(victim, "0".repeat(64)); // the byte-level shape a filename check cannot see
  fx[key] = e;

  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(fx),
    build: noBuild,
  });
  assert.equal(verdict(r).kind, "drift");
  assert.ok(
    r.drift.some(
      (d) =>
        d.includes("DIFFER in content") &&
        d.includes(victim.slice("dist/".length)),
    ),
    `the differing file was not named: ${JSON.stringify(r.drift)}`,
  );
});

test("⛔ DRIFT, ABSENT — a dist file the source emits and the tarball lacks is named", async () => {
  const fx = faithful();
  const key = Object.keys(fx).find((k) =>
    k.startsWith("@integraledger/agentic-terms@"),
  );
  const e = new Map(fx[key]);
  const victim = [...e.keys()].find(
    (k) => k.startsWith("dist/") && k.endsWith(".js"),
  );
  e.delete(victim);
  fx[key] = e;

  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(fx),
    build: noBuild,
  });
  assert.equal(verdict(r).kind, "drift");
  assert.ok(
    r.drift.some((d) => d.includes("MISSING")),
    JSON.stringify(r.drift),
  );
});

test("⛔ DRIFT, EXTRA — a published dist file this source does not emit is named", async () => {
  const fx = faithful();
  const key = Object.keys(fx).find((k) =>
    k.startsWith("@integraledger/agentic-terms@"),
  );
  const e = new Map(fx[key]);
  e.set("dist/nobody-wrote-this.js", "1".repeat(64));
  fx[key] = e;

  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(fx),
    build: noBuild,
  });
  assert.equal(verdict(r).kind, "drift");
  assert.ok(
    r.drift.some((d) => d.includes("does not emit")),
    JSON.stringify(r.drift),
  );
});

test("⛔⛔ A DIFFERING src is SKIPPED and named for the OTHER gate — never reported as dist drift", async () => {
  // Without this the gate would rebuild the wrong source and report the difference as a dist finding,
  // which is a true red with a false diagnosis — the shape this estate keeps paying for.
  const fx = faithful();
  const key = Object.keys(fx).find((k) =>
    k.startsWith("@integraledger/agentic-terms@"),
  );
  const e = new Map(fx[key]);
  const victim = [...e.keys()].find((k) => k.startsWith("src/"));
  e.set(victim, "2".repeat(64));
  fx[key] = e;

  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(fx),
    build: noBuild,
  });
  assert.deepEqual(
    r.drift,
    [],
    "a src difference must not surface as dist drift",
  );
  assert.ok(r.skipped.includes("@integraledger/agentic-terms"));
  assert.ok(
    r.notes.some((n) => n.includes("check:published-parity")),
    JSON.stringify(r.notes),
  );
});

test("⛔⛔ ZERO COMPARED IS UNMEASURED, and never a tick", async () => {
  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry({}), // nothing published at these versions
    build: noBuild,
  });
  assert.equal(r.compared, 0);
  assert.equal(verdict(r).kind, "unmeasured");
  assert.notEqual(verdict(r).code, 0);
});

test("⛔ A tarball with NO dist/ entries is a FAULT, not parity over nothing", async () => {
  const fx = faithful();
  const key = Object.keys(fx).find((k) =>
    k.startsWith("@integraledger/agentic-terms@"),
  );
  fx[key] = new Map([...fx[key]].filter(([k]) => !k.startsWith("dist/")));

  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(fx),
    build: noBuild,
  });
  assert.equal(verdict(r).kind, "fault");
  assert.ok(
    r.faults.some((f) => f.includes("published NO dist/")),
    JSON.stringify(r.faults),
  );
});

test("⛔ AN UNREACHABLE REGISTRY IS A FAULT — not drift and never parity", async () => {
  const dead = {
    async metadata() {
      throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
    },
    async contents() {
      throw new Error("unreachable");
    },
  };
  const r = await distParityReport({
    manifests: manifests(),
    registry: dead,
    build: noBuild,
  });
  assert.equal(verdict(r).kind, "fault");
  assert.deepEqual(r.drift, []);
});

test("⛔ A FAILED REBUILD IS A FAULT — the instrument, not the product", async () => {
  const r = await distParityReport({
    manifests: manifests(),
    registry: stubRegistry(faithful()),
    build: () => {
      throw new Error("tsc exploded");
    },
  });
  assert.equal(verdict(r).kind, "fault");
  assert.ok(r.faults.some((f) => f.includes("rebuild failed")));
});

test("⛔ THE FLOOR — a package leaving the comparable set must not leave a green behind", () => {
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], compared: 4 }).kind,
    "parity",
  );
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], compared: 3 }).kind,
    "stale-floor",
  );
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], compared: 5 }).kind,
    "stale-floor",
    "held EQUAL to the floor, so a package JOINING also refuses until the number is raised",
  );
});

test("⛔⛔ `ahead` IS NOT `skipped` — a release in flight is parity, a package that LEFT is not", () => {
  // ⭐⭐ THE DEFECT THIS PINS WAS LIVE UNTIL 2026-09-16, and the LIVE control below is what found it — no
  // fixture in this file could. Both states used to land in `skipped`, which cleared the equality arm and
  // was then refused by `compared < floor`. So every release window, from `changeset version` landing
  // until the publish, exited 2 — while the run's own note for that state said this gate "gives no
  // opinion on it". The note and the verdict disagreed, and the workflow reads the verdict.
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], ahead: 1, compared: 3 }).kind,
    "parity",
    "a declared package that is not on the registry yet — every new package, until its first publish",
  );
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], ahead: 2, compared: 2 }).kind,
    "parity",
    "an ordinary release in flight: the fixed group moves two packages at once",
  );
  // ⛔ AND THE ALLOWANCE MUST NOT SWALLOW THE THING THE FLOOR IS FOR. A package that LEFT the set does not
  // increment `ahead`, so it still refuses — which is the whole point of holding the floor EQUAL.
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], ahead: 0, compared: 3 }).kind,
    "stale-floor",
    "one package simply absent is a stale declaration, not a release",
  );
  // ⛔ AND `skipped` IS NOT `ahead` EITHER, WHICH IS THE HALF THAT IS EASY TO GET WRONG IN THE OTHER
  // DIRECTION. ⭐ Written here as `parity` and driven; the gate answered `unmeasured` and the gate is
  // right. A package whose PUBLISHED src disagrees with the tree is a subject genuinely lost — the
  // sibling gate reds on it as drift — so this gate must not print a tick over what remains. Only
  // "not on the registry yet" is a subject that has honestly left for the length of one publish.
  assert.equal(
    verdict({
      drift: [],
      faults: [],
      skipped: ["src-differs"],
      ahead: 1,
      compared: 2,
    }).kind,
    "unmeasured",
    "the third accounting is NOT an allowance: it is the sibling gate's finding, and it loses coverage",
  );
  // ⛔ ZERO COMPARED IS STILL UNMEASURED, HOWEVER WELL ACCOUNTED FOR — `- ahead` must not reach this.
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], ahead: 4, compared: 0 }).kind,
    "unmeasured",
    "a whole release in flight opens no tarball, and a tick there is the empty-subject-set defect",
  );
});

test("⛔⛔ compare() names each side BY THE SIDE IT IS ON — the inversion that shipped once", () => {
  const pub = new Map([
    ["a", "1"],
    ["b", "2"],
    ["c", "3"],
  ]);
  const reb = new Map([
    ["a", "1"],
    ["b", "9"],
    ["d", "4"],
  ]);
  assert.deepEqual(compare(pub, reb), {
    onlyPublished: ["c"],
    onlyRebuilt: ["d"],
    different: ["b"],
  });
});

test("⛔ publishedDist and publishedSrc split one entry map and neither claims the other's files", () => {
  const e = new Map([
    ["dist/i.js", "1"],
    ["src/i.ts", "2"],
    ["README.md", "3"],
  ]);
  assert.deepEqual([...publishedDist(e).keys()], ["i.js"]);
  assert.deepEqual([...publishedSrc(e).keys()], ["i.ts"]);
});

test("⭐⭐ THE LIVE CONTROL — the REAL registry, the REAL tarballs, a REAL rebuild, and it is PARITY", async () => {
  // ⛔ Without this the suite proves only that the gate agrees with its own fixtures. This is the case that
  // fetches three tarballs from npmjs and runs `pnpm build` three times.
  const r = await distParityReport({
    manifests: manifests(),
    registry: NetworkRegistry({}),
  });
  assert.deepEqual(
    r.faults,
    [],
    `the live run faulted: ${JSON.stringify(r.faults)}`,
  );
  assert.deepEqual(
    r.drift,
    [],
    `the live run found drift: ${JSON.stringify(r.drift)}`,
  );
  // ⛔⛔ A FLOOR PLUS AN ACCOUNTING, NOT A BARE EQUALITY — and this pairing is what caught the `ahead`
  // defect. `compared` legitimately moves the day a newly declared package first publishes; `compared +
  // ahead + skipped` does not. A bare `assert.equal(r.compared, 3)` went red the moment a fourth package
  // was DECLARED, which is a true fact about the registry stated as a failure of the tree — and the fix
  // for it, under deadline, is to edit the number rather than read the verdict. That is how a live
  // control becomes a fixture.
  assert.ok(
    r.compared >= 3,
    `the live run compared ${r.compared} package(s) — it must open real tarballs to mean anything`,
  );
  assert.equal(
    r.compared + r.ahead + r.skipped.length,
    DIST_FLOOR,
    "every declared package accounted for, against the real registry",
  );
  assert.equal(verdict(r).kind, "parity");
});

test("⛔⛔ A SYMLINK UNDER THE TREE IS SKIPPED, NOT FOLLOWED — the guard that never fired", async () => {
  // ⚠️ This case exists because the first implementation used `statSync`, which FOLLOWS symlinks, so its
  // `isSymbolicLink()` guard could never be true. The guard read as present and did nothing: a link out of
  // the tree was hashed as a file this artifact does not ship, and a link into it hashed one file twice
  // under two names. ⛔ The whole drive was green before and after the fix, which is what makes this case
  // worth more than the twelve above it — none of them could see the defect.
  const { mkdtempSync, writeFileSync, symlinkSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "dist-parity-symlink-"));
  writeFileSync(join(dir, "real.js"), "export const a = 1;\n");
  const outside = mkdtempSync(join(tmpdir(), "dist-parity-outside-"));
  writeFileSync(join(outside, "stranger.js"), "export const b = 2;\n");
  symlinkSync(join(outside, "stranger.js"), join(dir, "linked.js"));
  symlinkSync(join(dir, "real.js"), join(dir, "alias.js"));

  const hashed = hashTree(dir);
  assert.deepEqual(
    [...hashed.keys()].sort(),
    ["real.js"],
    "only the regular file may be hashed: `linked.js` points outside the tree and `alias.js` would hash one file twice",
  );
});
