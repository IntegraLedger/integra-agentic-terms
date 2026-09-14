#!/usr/bin/env node
/**
 * The drive for `check:published-parity` — every verdict PLANTED, with the gate going red for the right
 * reason and green only when it could have gone red.
 *
 * ⛔⛔ WHAT AN EARLIER EDITION OF THIS FILE DID NOT MEASURE, found by killing mutants rather than by reading:
 *
 *   · replacing the WHOLE of `NetworkRegistry` with stubs broke no test — the 404 mapping, both `!res.ok`
 *     throws and the tarball parse were asserted by nothing, and the fixtures encoding "what a tarball looks
 *     like" were the author's assumption checked against itself;
 *   · changing `main()`'s `exit(1)` and `exit(2)` to `exit(0)` broke no test — `verdict()` was proved to
 *     RETURN codes while the workflow reads the PROCESS's, and nothing spanned the join. That is this
 *     estate's piped-exit defect one layer up;
 *   · deleting the empty-source-set refusal broke no test, because no fixture ever produced one.
 *
 * ⇒ The three sections below exist for those three gaps: fakes for the verdict logic, a REAL HTTP registry
 * serving a REAL tarball for the seam, and spawned PROCESSES for the exit codes.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  COMPARABLE_FLOOR,
  declaredSourceFiles,
  hashTarEntries,
  NetworkRegistry,
  parityReport,
  publishableManifests,
  verdict,
} from "./check-published-parity.mjs";

const GATE = fileURLToPath(
  new URL("check-published-parity.mjs", import.meta.url),
);
const NAME = "@integraledger/agentic-terms";
const VERSION = "0.17.0";
const SRC = {
  "index.ts": "export * from './evaluate.js';\n",
  "evaluate.ts": "export const evaluate = () => true;\n",
  "x402-envelope.ts": "export const x402PaymentHeader = () => '';\n",
};

/** A throwaway package tree. `extra` adds further packages so the floor can be exercised. */
function fixture({
  files = ["dist", "src"],
  version = VERSION,
  extra = [],
} = {}) {
  const root = mkdtempSync(join(tmpdir(), "parity-fixture-"));
  // `readManifests` starts at the workspace root manifest; private, so it is not in the subject set.
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ name: "root", private: true }),
  );
  const mk = (dirName, pkg, src) => {
    const dir = join(root, "packages", dirName);
    mkdirSync(join(dir, "src"), { recursive: true });
    for (const [f, body] of Object.entries(src))
      writeFileSync(join(dir, "src", f), body);
    const path = join(dir, "package.json");
    writeFileSync(path, JSON.stringify(pkg, null, 2));
    return { name: dirName, path, pkg };
  };
  const manifests = [
    mk(
      "agentic-terms",
      { name: NAME, version, files, publishConfig: { access: "public" } },
      SRC,
    ),
    ...extra.map((e) => mk(e.dir, e.pkg, e.src ?? SRC)),
  ];
  return { root, manifests };
}

/** A registry that answers from literals, recording what it was asked for. */
function FakeRegistry({
  versions = { [VERSION]: { dist: { tarball: "http://x/t.tgz" } } },
  contents,
  throws,
} = {}) {
  const asked = [];
  const fetched = [];
  return {
    asked,
    fetched,
    async metadata(name) {
      asked.push(name);
      if (throws === "metadata")
        throw new Error("ENOTFOUND registry.npmjs.org");
      return { versions };
    },
    async contents(name, version) {
      // ⭐ Recorded rather than ignored: a fake that discards its arguments cannot catch a gate asking for
      // the WRONG package or version, which would compare two unrelated artifacts and report parity.
      fetched.push(`${name}@${version}`);
      if (throws === "contents") throw new Error("tarball answered 503");
      return contents ?? new Map();
    },
  };
}

const sha = (s) =>
  execFileSync(
    "node",
    [
      "-e",
      `const c=require('node:crypto');process.stdout.write(c.createHash('sha256').update(process.argv[1]).digest('hex'))`,
      s,
    ],
    { encoding: "utf8" },
  );

/** The tarball a correct publish of the fixture would produce. */
const parityContents = () =>
  new Map(Object.entries(SRC).map(([f, body]) => [`src/${f}`, sha(body)]));

/* ================================================================ 1 · the verdict logic, on fakes */

test("a tarball whose bytes match every declared source file is parity", async () => {
  const { root, manifests } = fixture();
  try {
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ contents: parityContents() }),
    });
    assert.deepEqual(r.drift, []);
    assert.deepEqual(r.faults, []);
    assert.equal(r.checked, 1);
    assert.equal(verdict({ ...r, floor: 1 }).code, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("⛔⛔ DRIFT, ABSENT — a declared file missing from the tarball is named", async () => {
  const { root, manifests } = fixture();
  try {
    const c = parityContents();
    c.delete("src/x402-envelope.ts");
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ contents: c }),
    });
    assert.equal(r.drift.length, 1);
    assert.match(r.drift[0], /ABSENT {4}src\/x402-envelope\.ts/);
    assert.match(
      r.drift[0],
      /1 file\(s\) absent, 0 present with different bytes/,
    );
    assert.match(
      r.drift[0],
      /Control: 2 file\(s\) were read from that tarball and 3 from this tree/,
    );
    assert.equal(verdict({ ...r, floor: 1 }).code, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("⛔⛔ DRIFT, DIFFERENT BYTES — the shape a filename check cannot see", async () => {
  const { root, manifests } = fixture();
  try {
    const c = parityContents();
    c.set("src/index.ts", sha("export * from './something-else.js';\n"));
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ contents: c }),
    });
    assert.equal(r.drift.length, 1);
    assert.match(r.drift[0], /DIFFERENT src\/index\.ts/);
    assert.match(
      r.drift[0],
      /0 file\(s\) absent, 1 present with different bytes/,
    );
    assert.equal(verdict({ ...r, floor: 1 }).code, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/* ================================================================ 2 · the states that are not drift */

test("⛔ THE FLOOR — a package leaving the comparable set must not leave a green behind", async () => {
  // agentic-terms drops `src` (an ordinary "stop shipping source" edit); a second package still compares.
  const { root, manifests } = fixture({
    files: ["dist"],
    extra: [
      {
        dir: "other",
        pkg: {
          name: "@x/other",
          version: VERSION,
          files: ["src"],
          publishConfig: { access: "public" },
        },
      },
    ],
  });
  try {
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ contents: parityContents() }),
    });
    assert.equal(r.checked, 1, "only the second package was comparable");
    assert.deepEqual(r.drift, []);
    assert.match(r.notes[0], /NOT COMPARABLE/);
    assert.equal(
      verdict({ ...r, floor: 2 }).code,
      2,
      "⛔ without the floor this is exit 0 and the workflow CLOSES the drift issue",
    );
    assert.match(
      verdict({ ...r, floor: 2 }).message,
      /LEAVES the comparable set/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a version not yet on the registry is a note, and leaves the run unmeasured rather than green", async () => {
  const { root, manifests } = fixture({ version: "0.18.0" });
  try {
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ contents: parityContents() }),
    });
    assert.deepEqual(r.drift, []);
    assert.deepEqual(r.faults, []);
    assert.match(r.notes[0], /not on the registry yet/);
    assert.equal(verdict({ ...r, floor: 1 }).code, 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a package that has never published says so, and names the 404 ambiguity the floor exists for", async () => {
  const { root, manifests } = fixture();
  try {
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ versions: {} }),
    });
    assert.equal(r.checked, 0);
    assert.match(r.notes[0], /never published/);
    assert.match(r.notes[0], /404 reads the same way/);
    assert.deepEqual(r.drift, []);
    assert.equal(verdict({ ...r, floor: 1 }).code, 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/* ================================================================ 3 · faults are not drift */

test("⛔⛔ AN UNREACHABLE REGISTRY IS A FAULT, not drift and never parity", async () => {
  const { root, manifests } = fixture();
  try {
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ throws: "metadata" }),
    });
    assert.deepEqual(
      r.drift,
      [],
      "the instrument failing is NOT a product finding",
    );
    assert.equal(r.faults.length, 1);
    assert.match(r.faults[0], /An unreachable registry is NOT parity/);
    assert.equal(verdict({ ...r, floor: 1 }).code, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("⛔ an unfetchable tarball and an empty one are both faults", async () => {
  for (const [opts, re] of [
    [{ throws: "contents" }, /could not be read/],
    [{ contents: new Map() }, /yielded no files/],
  ]) {
    const { root, manifests } = fixture();
    try {
      const r = await parityReport({ manifests, registry: FakeRegistry(opts) });
      assert.deepEqual(r.drift, []);
      assert.match(r.faults[0], re);
      assert.equal(verdict({ ...r, floor: 1 }).code, 3);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("⛔ AN EMPTY SUBJECT SET IS A FAULT, not a clean run", async () => {
  const r = await parityReport({ manifests: [], registry: FakeRegistry() });
  assert.match(r.faults[0], /subject set of zero, not a clean run/);
  assert.equal(verdict(r).code, 3);
});

test("⛔ a declared source directory that is EMPTY on disk is a fault — it would pass over nothing", async () => {
  const root = mkdtempSync(join(tmpdir(), "parity-empty-"));
  try {
    writeFileSync(
      join(root, "package.json"),
      JSON.stringify({ name: "root", private: true }),
    );
    const dir = join(root, "packages", "empty");
    mkdirSync(join(dir, "src"), { recursive: true });
    const path = join(dir, "package.json");
    const pkg = {
      name: "@x/empty",
      version: VERSION,
      files: ["src"],
      publishConfig: { access: "public" },
    };
    writeFileSync(path, JSON.stringify(pkg));
    const r = await parityReport({
      manifests: [{ name: "empty", path, pkg }],
      registry: FakeRegistry({ contents: parityContents() }),
    });
    assert.match(r.faults[0], /holds no files in this tree/);
    assert.equal(verdict(r).code, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("⛔ a symlink under src is a NAMED fault, and does not empty its own directory", async () => {
  const { root, manifests } = fixture();
  try {
    symlinkSync(
      join(root, "nowhere.ts"),
      join(root, "packages", "agentic-terms", "src", "broken.ts"),
    );
    const r = await parityReport({
      manifests,
      registry: FakeRegistry({ contents: parityContents() }),
    });
    assert.equal(r.faults.length, 1);
    assert.match(r.faults[0], /broken\.ts/);
    assert.match(r.faults[0], /symbolic link/);
    assert.doesNotMatch(
      r.faults[0],
      /holds no files/,
      "a first draft abandoned the whole directory and then misdiagnosed it as empty",
    );
    assert.equal(verdict(r).code, 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/* ================================================================ 4 · the predicate and the path shapes */

test("the publishable predicate is the one a PUBLISH uses, and it discriminates", () => {
  const mk = (pkg) => ({ name: "x", path: "/x/package.json", pkg });
  const subjects = publishableManifests([
    mk({ name: "a", version: "1.0.0", publishConfig: { access: "public" } }),
    mk({
      name: "b",
      version: "1.0.0",
      private: true,
      publishConfig: { access: "public" },
    }),
    mk({ name: "c", version: "1.0.0" }),
    mk({
      name: "d",
      version: "1.0.0",
      publishConfig: { access: "restricted" },
    }),
  ]);
  assert.deepEqual(
    subjects.map((s) => s.pkg.name),
    ["a"],
  );
});

test("⛔ all three legal spellings of one directory read the same — `src`, `src/`, `./src`", () => {
  const { root, manifests } = fixture();
  try {
    const dir = join(manifests[0].path, "..");
    const expected = Object.keys(SRC)
      .map((f) => `src/${f}`)
      .sort();
    for (const spelling of ["src", "src/", "./src"]) {
      const got = declaredSourceFiles(dir, ["dist", spelling]);
      assert.equal(
        got.comparable,
        true,
        `${spelling} must stay in the subject set`,
      );
      assert.deepEqual(
        [...got.files.keys()].sort(),
        expected,
        `${spelling} must not produce a doubled separator or drop out`,
      );
    }
    assert.equal(declaredSourceFiles(dir, ["dist"]).comparable, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the gate asks the registry for the package and version it is comparing", async () => {
  const { root, manifests } = fixture();
  try {
    const registry = FakeRegistry({ contents: parityContents() });
    await parityReport({ manifests, registry });
    assert.deepEqual(registry.asked, [NAME]);
    assert.deepEqual(registry.fetched, [`${NAME}@${VERSION}`]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the four verdicts are distinguishable, and drift outranks a fault", () => {
  assert.equal(
    verdict({ drift: [], faults: [], checked: 2, floor: 2 }).code,
    0,
  );
  assert.equal(
    verdict({ drift: ["d"], faults: [], checked: 2, floor: 2 }).code,
    1,
  );
  assert.equal(
    verdict({ drift: [], faults: [], checked: 1, floor: 2 }).code,
    2,
  );
  assert.equal(
    verdict({ drift: [], faults: ["f"], checked: 2, floor: 2 }).code,
    3,
  );
  assert.equal(
    verdict({ drift: ["d"], faults: ["f"], checked: 2, floor: 2 }).code,
    1,
    "a confirmed product defect outranks an incomplete instrument",
  );
  assert.equal(COMPARABLE_FLOOR, 2);
});

/* ================================================================ 5 · the REAL seam, against a real server */

/** Serve npm-shaped metadata plus a real gzipped tarball, so the parse is measured rather than assumed. */
function startRegistry({
  srcFiles,
  name = NAME,
  version = VERSION,
  status = 200,
}) {
  const dir = mkdtempSync(join(tmpdir(), "parity-reg-"));
  const pkgDir = join(dir, "package", "src");
  mkdirSync(pkgDir, { recursive: true });
  for (const [f, body] of Object.entries(srcFiles))
    writeFileSync(join(pkgDir, f), body);
  writeFileSync(
    join(dir, "package", "package.json"),
    JSON.stringify({ name, version }),
  );
  execFileSync("tar", ["czf", join(dir, "t.tgz"), "-C", dir, "package"]);
  const tgz = readFileSyncSafe(join(dir, "t.tgz"));

  const server = createServer((req, res) => {
    if (status !== 200) {
      res.writeHead(status);
      res.end("nope");
      return;
    }
    if (req.url.endsWith("/t.tgz")) {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(tgz);
      return;
    }
    const origin = `http://127.0.0.1:${server.address().port}`;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        versions: { [version]: { dist: { tarball: `${origin}/t.tgz` } } },
      }),
    );
  });
  return new Promise((ok) =>
    server.listen(0, "127.0.0.1", () =>
      ok({
        origin: `http://127.0.0.1:${server.address().port}`,
        stop: () => {
          server.close();
          rmSync(dir, { recursive: true, force: true });
        },
      }),
    ),
  );
}

function readFileSyncSafe(p) {
  return execFileSync("cat", [p], {
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
  });
}

test("⭐⭐ THE REAL NetworkRegistry parses a REAL tarball — the half a stub once replaced unnoticed", async () => {
  const reg = await startRegistry({ srcFiles: SRC });
  try {
    const r = NetworkRegistry({ origin: reg.origin });
    const meta = await r.metadata(NAME);
    assert.ok(meta.versions[VERSION].dist.tarball.endsWith("/t.tgz"));
    const contents = await r.contents(
      NAME,
      VERSION,
      meta.versions[VERSION].dist.tarball,
    );
    assert.deepEqual(
      [...contents.keys()].sort(),
      ["package.json", ...Object.keys(SRC).map((f) => `src/${f}`)].sort(),
      "the package/ prefix must be stripped and nested paths kept",
    );
    assert.equal(
      contents.get("src/index.ts"),
      sha(SRC["index.ts"]),
      "hashed, not merely listed",
    );
  } finally {
    reg.stop();
  }
});

test("⛔ the real registry maps 404 to `never published` and throws on any other non-OK", async () => {
  const gone = await startRegistry({ srcFiles: SRC, status: 404 });
  try {
    assert.deepEqual(
      await NetworkRegistry({ origin: gone.origin }).metadata(NAME),
      { versions: {} },
    );
  } finally {
    gone.stop();
  }
  const broken = await startRegistry({ srcFiles: SRC, status: 503 });
  try {
    await assert.rejects(
      () => NetworkRegistry({ origin: broken.origin }).metadata(NAME),
      /answered 503/,
    );
  } finally {
    broken.stop();
  }
});

test("⛔ a version whose metadata carries no dist.tarball is a fault, not a crash", async () => {
  const r = NetworkRegistry({ origin: "http://127.0.0.1:1" });
  await assert.rejects(
    () => r.contents(NAME, VERSION, undefined),
    /carries no dist\.tarball/,
  );
});

/* ================================================================ 6 · the PROCESS exit codes */

/**
 * Run the gate as the workflow runs it: a process, whose exit code is the only thing read.
 *
 * ⛔ ASYNC `spawn`, NEVER `spawnSync`. The fixture registry is an HTTP server in THIS process, and
 * `spawnSync` blocks this event loop until the child exits — so the child's fetch could never be answered
 * and both sides waited for each other forever. A synchronous helper and an in-process server cannot both
 * be right; the drive deadlocked for sixty seconds before this was `spawn`.
 */
function runGate({ root, origin }) {
  return new Promise((resolve) => {
    const child = spawn("node", [GATE], {
      env: {
        ...process.env,
        INTEGRA_PARITY_ROOT: root,
        INTEGRA_PARITY_ORIGIN: origin,
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("⛔⛔ THE PROCESS EXITS THE CODE — proved end to end, because the workflow reads the code and not the return value", async () => {
  // parity -> 0
  const { root, manifests } = fixture({ extra: [] });
  const reg = await startRegistry({ srcFiles: SRC });
  try {
    const floorOne = await runGate({ root, origin: reg.origin });
    // One comparable package against a floor of 2 is UNMEASURED, which is itself the floor's exit.
    assert.equal(
      floorOne.status,
      2,
      `expected 2, got ${floorOne.status}: ${floorOne.stderr}`,
    );
    assert.match(floorOne.stderr, /below the floor of 2/);
  } finally {
    reg.stop();
    rmSync(root, { recursive: true, force: true });
  }

  // drift -> 1
  const d = fixture();
  const short = { ...SRC };
  delete short["x402-envelope.ts"];
  const driftReg = await startRegistry({ srcFiles: short });
  try {
    const out = await runGate({ root: d.root, origin: driftReg.origin });
    assert.equal(out.status, 1, `expected 1, got ${out.status}: ${out.stderr}`);
    assert.match(out.stderr, /IS PUBLISHED AND IS BEHIND ITS OWN SOURCE/);
  } finally {
    driftReg.stop();
    rmSync(d.root, { recursive: true, force: true });
  }

  // fault -> 3 (nothing listening on that port)
  const f = fixture();
  try {
    const out = await runGate({ root: f.root, origin: "http://127.0.0.1:1" });
    assert.equal(out.status, 3, `expected 3, got ${out.status}: ${out.stderr}`);
    assert.match(out.stderr, /THE INSTRUMENT FAILED/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

/* ================================================================ 7 · the archive is never extracted */

/** Build one POSIX ustar entry by hand, so hostile shapes can be planted exactly. */
function tarEntry(name, body, type = "0") {
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0, "utf8");
  header.write("000644 \0", 100);
  header.write("0000000 \0", 108);
  header.write("0000000 \0", 116);
  header.write(`${body.length.toString(8).padStart(11, "0")} `, 124);
  header.write("00000000000 ", 136);
  header.write(type, 156);
  header.write("ustar\0" + "00", 257);
  header.fill(" ", 148, 156); // checksum field is spaces while summing
  let sum = 0;
  for (const b of header) sum += b;
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
  const content = Buffer.alloc(Math.ceil(body.length / 512) * 512);
  Buffer.from(body).copy(content);
  return Buffer.concat([header, content]);
}

test("⛔⛔ A HOSTILE ENTRY NAME IS INERT — traversal and absolute paths become Map keys, never files", () => {
  const canaryRel = join(tmpdir(), "parity-traversal-canary.txt");
  rmSync(canaryRel, { force: true });

  const tar = Buffer.concat([
    tarEntry("package/src/ok.ts", "export const ok = 1;\n"),
    tarEntry(
      "../../../../../../../../tmp/parity-traversal-canary.txt",
      "OWNED\n",
    ),
    tarEntry("/tmp/parity-traversal-canary.txt", "OWNED\n"),
    Buffer.alloc(1024),
  ]);

  const out = hashTarEntries(tar);

  assert.ok(out.has("package/src/ok.ts"), "the legitimate entry is still read");
  assert.ok(
    out.has("../../../../../../../../tmp/parity-traversal-canary.txt"),
    "the hostile name is DATA — a key in a Map, which is the whole point",
  );
  assert.equal(
    existsSync(canaryRel),
    false,
    "⛔ nothing may be written to the filesystem: this is why the tar is walked in memory rather than extracted",
  );
});

test("⛔ symlink and directory entries are skipped — a link cannot be followed if it is never created", () => {
  const tar = Buffer.concat([
    tarEntry("package/src/real.ts", "export const a = 1;\n"),
    tarEntry("package/src/link.ts", "", "2"), // symlink
    tarEntry("package/src/nested/", "", "5"), // directory
    Buffer.alloc(1024),
  ]);
  const out = hashTarEntries(tar);
  assert.deepEqual([...out.keys()], ["package/src/real.ts"]);
});

test("⭐ the hand-rolled reader agrees with real `tar` output, entry for entry", async () => {
  // startRegistry builds its fixture with the real `tar czf`, so this compares the parser against the tool.
  const reg = await startRegistry({ srcFiles: SRC });
  try {
    const r = NetworkRegistry({ origin: reg.origin });
    const meta = await r.metadata(NAME);
    const contents = await r.contents(
      NAME,
      VERSION,
      meta.versions[VERSION].dist.tarball,
    );
    assert.deepEqual(
      [...contents.keys()].sort(),
      ["package.json", ...Object.keys(SRC).map((f) => `src/${f}`)].sort(),
      "a real gzipped tar, parsed in memory, with the package/ prefix stripped",
    );
    assert.equal(contents.get("src/index.ts"), sha(SRC["index.ts"]));
  } finally {
    reg.stop();
  }
});

test("⛔ an unreadable size field is refused rather than silently truncating the archive", () => {
  const bad = tarEntry("package/x.ts", "hi");
  bad.write("XXXXXXXXXXX ", 124); // not octal
  assert.throws(
    () => hashTarEntries(Buffer.concat([bad, Buffer.alloc(1024)])),
    /unreadable size field/,
  );
});
