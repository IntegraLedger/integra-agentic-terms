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
  assert.equal(r.compared, 3);
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
    verdict({ drift: [], faults: [], skipped: [], compared: 3 }).kind,
    "parity",
  );
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], compared: 2 }).kind,
    "stale-floor",
  );
  assert.equal(
    verdict({ drift: [], faults: [], skipped: [], compared: 4 }).kind,
    "stale-floor",
    "held EQUAL to the floor, so a package JOINING also refuses until the number is raised",
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
  assert.equal(r.compared, 3);
  assert.equal(verdict(r).kind, "parity");
});
