/**
 * The drive for `check:hermetic-tests`.
 *
 * ⛔⛔ **A GATE THAT HAS NEVER BEEN RED HAS NEVER BEEN SHOWN TO BE A GATE.** Every case below plants a
 * defect into a temporary tree and asserts the refusal NAMES it — and the first case is the null plant,
 * over the same fixture shape, because a red that a clean tree also produces is measuring the fixture
 * rather than the plant.
 *
 * ⭐ The fixtures are `mkdtemp` trees handed to the gate through `INTEGRA_GATE_ROOT`. Nothing in them is
 * executed: the gate READS files. So a host planted here is never dialled.
 *
 * ⚠️ **This file is inside the subject set of the gate it drives** — `check:hermetic-tests` walks
 * `scripts/`, and this is a `.test.mjs`. It needs no `namedNotCalled` entry all the same, because every
 * planted URL is composed through a template literal and the gate reports no host for an interpolated
 * authority. ⛔ Not a loophole and not a licence: writing `PLANT` literally into a URL here would redden
 * the gate, correctly, and would then have to be declared. Measured — with the plant composed, the gate
 * reports 11 hosts over this tree, the same 11 as before this drive existed.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const GATE = fileURLToPath(
  new URL("./check-hermetic-tests.mjs", import.meta.url),
);

/**
 * ⭐ THE PLANTED HOST, and the only one. It is a real registrable name rather than a reserved one on
 * purpose: `RESERVED` skips `*.example`/`*.invalid`, so a plant spelled that way would prove nothing —
 * the gate would pass it for the right reason and the case would read as a pass for the wrong one.
 * `integra-protocol`'s drive plants the same name, so the two repositories' drives read alike.
 */
const PLANT = "api.blockcypher.com";

/** The `$` of a `${` a FIXTURE must contain, built here so no plain string in this file holds one. */
const DOLLAR = "$";

const DECLARATIONS = {
  namedNotCalled: {},
  imports: { vitest: { kind: "inert", why: "the runner" } },
};

/** A fixture tree: one package, one test, plus whatever this case adds. */
const tree = ({ files = {}, declarations = DECLARATIONS } = {}) => {
  const root = mkdtempSync(join(tmpdir(), "hermetic-drive-"));
  mkdirSync(join(root, "scripts"), { recursive: true });
  mkdirSync(join(root, "packages", "p", "test"), { recursive: true });
  writeFileSync(
    join(root, "scripts", "hermetic-tests.declarations.json"),
    JSON.stringify(declarations),
  );
  const all = {
    "packages/p/test/clean.test.ts":
      'import { it } from "vitest";\nit("x", () => {});\n',
    ...files,
  };
  for (const [path, body] of Object.entries(all)) {
    const full = join(root, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return root;
};

const run = (root) => {
  const r = spawnSync(process.execPath, [GATE], {
    env: { ...process.env, INTEGRA_GATE_ROOT: root },
    encoding: "utf8",
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
};

/**
 * Does the refusal list this host as a FINDING, on its own line?
 *
 * ⭐ Line EQUALITY, not `out.includes(host)`. Two reasons, and only the first is CodeQL's:
 *
 * 1. A bare `.includes()` over a hostname-shaped constant is the `url.includes("example.com")`
 *    antipattern, and `js/incomplete-url-substring-sanitization` flags it — correctly in general, even
 *    though nothing here is validating a URL.
 * 2. ⛔ And it is the weaker assertion anyway: `includes` would also pass on the host appearing inside a
 *    `named by:` path, inside the remedy sentence, or as a SUFFIX of some longer host. The gate prints a
 *    finding's host alone on its line, so that is what is asserted.
 */
const namesHost = (out, host) =>
  out.split("\n").some((line) => line.trim() === host);

const drive = (name, options, expect) =>
  test(name, () => {
    const root = tree(options);
    try {
      expect(run(root));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

// ⭐⭐ THE NULL PLANT, FIRST. Every case below differs from this one by exactly the planted defect, so a
// red below is caused by the plant. Without this the suite could be measuring a malformed fixture.
drive(
  "⭐ the null plant — a clean fixture is GREEN, so every red below is the plant",
  {},
  (r) => {
    assert.equal(r.status, 0, `a clean fixture must pass, got:\n${r.out}`);
    assert.match(r.out, /1 test file\(s\)/);
  },
);

drive(
  "⛔ a third-party host in a TEST file is refused, naming the file",
  {
    files: {
      "packages/p/test/bad.test.ts": `import { it } from "vitest";\nit("x", async () => { await fetch("https://${PLANT}/tip"); });\n`,
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.ok(
      namesHost(r.out, PLANT),
      `the refusal must name ${PLANT} as a finding:\n${r.out}`,
    );
    assert.match(r.out, /packages\/p\/test\/bad\.test\.ts/);
  },
);

// ⭐ `#87`'s widening, DRIVEN rather than assumed: the host sits one `import` away from the test, which is
// exactly where the Koios host sat while commerce's gate reported green.
drive(
  "⛔⛔ a third-party host in a HELPER A TEST IMPORTS is refused, naming the HELPER",
  {
    files: {
      "packages/p/test/uses.test.ts":
        'import { it } from "vitest";\nimport { tip } from "./helper.js";\nit("x", async () => { await tip(); });\n',
      "packages/p/test/helper.ts": `export const tip = async () => fetch("https://${PLANT}/tip");\n`,
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.match(r.out, /packages\/p\/test\/helper\.ts/);
  },
);

// ⭐⭐ THE USERINFO FIX, and the case that found it. Against the pattern this gate was ported with, the
// refusal named `user` and never the host — so a reader would declare `user` as a fixture placeholder and
// thereby exempt EVERY credentialed URL to EVERY third party. Driven both ways: the real host is named,
// and declaring the userinfo does not buy an exemption.
drive(
  "⛔⛔ a host behind USERINFO is named as the HOST, not as the username",
  {
    files: {
      "packages/p/test/creds.test.ts": `import { it } from "vitest";\nit("x", async () => { await fetch("https://user:pw@${PLANT}/steal"); });\n`,
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.ok(
      namesHost(r.out, PLANT),
      `the refusal must name ${PLANT} as a finding:\n${r.out}`,
    );
    assert.doesNotMatch(
      r.out,
      /^ {2}user$/m,
      "the refusal named the userinfo instead of the host",
    );
  },
);

drive(
  "⛔ declaring the USERINFO does not exempt the host behind it",
  {
    declarations: {
      namedNotCalled: { user: "a placeholder" },
      imports: { vitest: { kind: "inert", why: "r" } },
    },
    files: {
      "packages/p/test/creds.test.ts": `import { it } from "vitest";\nit("x", async () => { await fetch("https://user@${PLANT}/steal"); });\n`,
    },
  },
  (r) => {
    assert.equal(
      r.status,
      1,
      `a declared userinfo must not exempt the host:\n${r.out}`,
    );
    assert.ok(
      namesHost(r.out, PLANT),
      `the refusal must name ${PLANT} as a finding:\n${r.out}`,
    );
  },
);

// ⛔ This repository has no live-harness convention. A file wearing a sibling's live name is an undeclared
// decision, and the gate refuses rather than choosing — see the gate's head note.
for (const name of ["rail.live.test.ts", "integration.rail.test.ts"])
  drive(
    `⛔ a file named for a SIBLING's live convention (${name}) is refused, not silently excluded`,
    {
      files: {
        [`packages/p/test/${name}`]: `import { it } from "vitest";\nit("x", async () => { await fetch("https://${PLANT}/tip"); });\n`,
      },
    },
    (r) => {
      assert.equal(r.status, 1);
      assert.match(
        r.out,
        /live-harness convention this repository has not\s*\n?\s*adopted/,
      );
      assert.ok(
        r.out.includes(name),
        `the refusal must name ${name}:\n${r.out}`,
      );
    },
  );

drive(
  "⛔ an UNCLASSIFIED third-party import is refused",
  {
    files: {
      "packages/p/test/imp.test.ts":
        'import { it } from "vitest";\nimport pg from "pg";\nit("x", () => { void pg; });\n',
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.match(r.out, /`pg`, which nothing classifies/);
  },
);

// ⛔ An `endpoint-from-environment` client writes no host into the file, so the host scan cannot see it.
// What must then be true is that the suite is gated on the variable it needs.
drive(
  "⛔ an endpoint-from-environment import in an UNGATED suite is refused",
  {
    declarations: {
      namedNotCalled: {},
      imports: {
        vitest: { kind: "inert", why: "r" },
        pg: { kind: "endpoint-from-environment", why: "a pool" },
      },
    },
    files: {
      "packages/p/test/db.test.ts":
        'import { describe, it } from "vitest";\nimport pg from "pg";\ndescribe("d", () => { it("x", () => { void pg; }); });\n',
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.match(r.out, /whose address comes from the/);
  },
);

drive(
  "⭐ …and the SAME import is accepted once the suite is gated on the variable it needs",
  {
    declarations: {
      namedNotCalled: {},
      imports: {
        vitest: { kind: "inert", why: "r" },
        pg: { kind: "endpoint-from-environment", why: "a pool" },
      },
    },
    files: {
      "packages/p/test/db.test.ts":
        'import { describe, it } from "vitest";\nimport pg from "pg";\nconst URL_ = process.env["POSTGRES_TEST_URL"];\ndescribe.skipIf(!URL_)("d", () => { it("x", () => { void pg; }); });\n',
    },
  },
  (r) => assert.equal(r.status, 0, `a gated suite must pass:\n${r.out}`),
);

// ⛔ Closed in the OTHER direction: an exception that excludes nothing reads as one that does.
drive(
  "⛔ a declared host that appears NOWHERE is refused",
  {
    declarations: {
      namedNotCalled: { "gone.example.org": "stale" },
      imports: { vitest: { kind: "inert", why: "r" } },
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.match(r.out, /appears in no test/);
  },
);

drive(
  "⛔ a classification nothing imports is refused",
  {
    declarations: {
      namedNotCalled: {},
      imports: {
        vitest: { kind: "inert", why: "r" },
        redis: { kind: "inert", why: "stale" },
      },
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.match(r.out, /no test imports it/);
  },
);

// ⛔ The defect this estate produces most often: a green over nothing examined.
test("⛔⛔ an EMPTY subject set is refused, never reported as clean", () => {
  const root = mkdtempSync(join(tmpdir(), "hermetic-drive-"));
  try {
    mkdirSync(join(root, "scripts"), { recursive: true });
    mkdirSync(join(root, "packages"), { recursive: true });
    writeFileSync(
      join(root, "scripts", "hermetic-tests.declarations.json"),
      JSON.stringify(DECLARATIONS),
    );
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.out, /NO test files were found/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ⛔ An import the walk cannot resolve is a module it did not read — a hole in the subject set.
drive(
  "⛔ an UNRESOLVABLE relative import is a finding, not a skip",
  {
    files: {
      "packages/p/test/miss.test.ts":
        'import { it } from "vitest";\nimport { x } from "./nope.js";\nit("x", () => { void x; });\n',
    },
  },
  (r) => {
    assert.equal(r.status, 1);
    assert.match(r.out, /could not resolve to a file/);
  },
);

// ⚠️ Host names are case-insensitive (RFC 4343) and RESERVED carries no `i` flag. Declaring a mixed-case
// reserved host would write a permanent exception for a host that does not exist.
drive(
  "⭐ a RESERVED host in mixed case needs no exception",
  {
    files: {
      "packages/p/test/mixed.test.ts":
        'import { it } from "vitest";\nit("x", () => { const u = "https://Seller.Example/Terms/AbC.md"; void u; });\n',
    },
  },
  (r) =>
    assert.equal(
      r.status,
      0,
      `a reserved host must not be reported:\n${r.out}`,
    ),
);

// ⛔⛔ The shape that disproved truncating an interpolated authority to its literal prefix. It is the
// seller-side repository's, carried here because the two gates must answer the same question the same way.
drive(
  "⛔⛔ an interpolation INSIDE the host names nothing — not even a fragment",
  {
    files: {
      "packages/p/test/interp.test.ts": `import { it } from "vitest";\nconst h = "https://seam${DOLLAR}{i}.example";\nconst g = "https://u:p@${DOLLAR}{h}/x";\nit("x", () => [h, g]);\n`,
    },
  },
  (r) => {
    assert.equal(
      r.status,
      0,
      `an interpolated authority names no host:\n${r.out}`,
    );
    assert.ok(
      !r.out.includes("seam"),
      `reported a fragment of an interpolated host:\n${r.out}`,
    );
  },
);

// ⛔ The declarations file is the gate's subject table; without it the gate would refuse every host.
test("⛔ a missing declarations file is refused, not defaulted to an empty table", () => {
  const root = mkdtempSync(join(tmpdir(), "hermetic-drive-"));
  try {
    mkdirSync(join(root, "packages", "p", "test"), { recursive: true });
    writeFileSync(
      join(root, "packages", "p", "test", "a.test.ts"),
      'import { it } from "vitest";\nit("x", () => {});\n',
    );
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.out, /no declarations file/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
