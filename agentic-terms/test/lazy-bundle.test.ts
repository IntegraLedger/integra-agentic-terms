// Each public entry point in package.json's `exports`, built, bundled by esbuild into one ES module behind an entry that
// imports it lazily with `import()`, as a Worker's bundler bundles it. One build takes every entry point and writes
// each one's bundle to a temporary folder. One Node process then imports each bundle in turn, awaits its lazy import,
// and gives the names Node's own loader gives for the built file; it prints each entry point's line as soon as it has
// one. A lazy import that never settles leaves that process nothing to wait for, so it exits with code 13 (an unsettled
// top-level await): the entry point it is loading when it stops did not settle, and a new process loads the ones after
// it. No clock bounds the build or the loads. The names each entry point gives are the package's public functions.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../", import.meta.url));

const EXPORTS: Record<string, { default: string }> = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).exports;
const ENTRIES: [string, string][] = Object.entries(EXPORTS).map(([key, target]) => [key, join(ROOT, target.default)]);
/** The public functions of each entry point. */
const PUBLIC: Record<string, string[]> = {
  ".": ["agree", "check", "confirm", "finish", "openChannel", "recordCharge", "transact", "within"],
};

const dir = mkdtempSync(join(tmpdir(), "terms-lazy-bundle-"));
/** The bundle of the `i`th entry point. */
const bundleOf = (i: number) => join(dir, "out", `${i}.mjs`);

type Loaded = { lazy: string[]; built: string[] } | { threw: string } | "did not settle";
/** Per entry point: the export names its lazy import gives and those of its built file, or why there are none. */
const loaded = new Map<string, Loaded>();

// Node's own loader: argv[1] is a JSON list of [entry point, bundle, built file]. For each in turn it awaits the
// bundle's lazy import and prints one JSON line of the names it and the built file give, sorted.
const LOAD = `
import { pathToFileURL } from "node:url";
const names = (m) => Object.keys(m).sort();
for (const [key, bundle, built] of JSON.parse(process.argv[1])) {
  let line;
  try {
    const { load } = await import(pathToFileURL(bundle).href);
    line = { key, lazy: names(await load()), built: names(await import(pathToFileURL(built).href)) };
  } catch (e) {
    line = { key, threw: String(e) };
  }
  process.stdout.write(JSON.stringify(line) + "\\n");
}
`;

beforeAll(async () => {
  for (const [, entry] of ENTRIES) {
    expect(existsSync(entry), `${entry} is missing: build the package first`).toBe(true);
  }
  // One module per entry point that imports it lazily, all bundled by one build.
  const entryPoints = ENTRIES.map(([, entry], i) => {
    const file = join(dir, `${i}.mjs`);
    writeFileSync(file, `export const load = () => import(${JSON.stringify(entry)});\n`);
    return file;
  });
  await build({
    entryPoints,
    outdir: join(dir, "out"),
    outExtension: { ".js": ".mjs" },
    bundle: true,
    format: "esm",
    platform: "node",
    logLevel: "silent",
  });
}, 0);
// Loading is its own hook. Neither hook has a time bound (0): the build returns or throws, and each loading process
// exits by itself, so how long either takes depends only on the machine.
beforeAll(() => {
  let jobs = ENTRIES.map(([key, entry], i) => [key, bundleOf(i), entry]);
  while (jobs.length > 0) {
    let out: string;
    let stopped: Loaded = { threw: "exit 0 without a line" };
    try {
      const args = ["--input-type=module", "-e", LOAD, JSON.stringify(jobs)];
      out = execFileSync(process.execPath, args, { encoding: "utf8" });
    } catch (e) {
      const { stdout, status, stderr } = e as { stdout?: string; status?: number | null; stderr?: string };
      out = String(stdout ?? "");
      // Node exits with code 13 when a top-level await never settles; any other exit is what it says.
      stopped = status === 13 ? "did not settle" : { threw: `exit ${status}: ${String(stderr ?? "").trim()}` };
    }
    for (const line of out.split("\n").filter((l) => l !== "")) {
      const { key, ...names } = JSON.parse(line) as { key: string } & Exclude<Loaded, string>;
      loaded.set(key, names);
    }
    // The process stopped at the first entry point without a line; the next process starts after it.
    const at = jobs.findIndex(([key]) => !loaded.has(key!));
    if (at === -1) break;
    loaded.set(jobs[at]![0]!, stopped);
    jobs = jobs.slice(at + 1);
  }
}, 0);
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("each public entry point in one bundle behind a lazy import()", () => {
  it.each(ENTRIES)("%s loads", (key) => {
    const m = loaded.get(key);
    expect(m).not.toBe("did not settle");
    expect(m).toHaveProperty("lazy");
    const { lazy, built } = m as { lazy: string[]; built: string[] };
    expect(built).toEqual(PUBLIC[key]);
    expect(lazy).toEqual(built);
  });
});
