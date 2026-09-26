// The built entry point bundled by esbuild, as a Worker's bundler bundles it, behind an entry that imports the package
// lazily with `import()`. The bundle is written to a temporary folder and imported, and the lazy import is awaited under a
// bounded deadline, so an import that never settles fails the test instead of stalling it. The same bundle behind a
// static import is the control. The expected exports are the package's public functions.
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";
import { afterAll, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const ENTRY = join(ROOT, "dist", "index.js");
const DEADLINE_MS = 20_000;
const EXPORTS = ["agree", "check", "confirm", "finish", "openChannel", "recordCharge", "transact", "within"];

const dir = mkdtempSync(join(tmpdir(), "terms-lazy-bundle-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** Bundles `contents`, which imports the built entry point, into one ES module file and returns its path. */
async function bundle(name: string, contents: string): Promise<string> {
  expect(existsSync(ENTRY), "dist/index.js is missing: build the package first").toBe(true);
  const out = await build({
    stdin: { contents, resolveDir: ROOT, loader: "js" },
    bundle: true,
    write: false,
    format: "esm",
    platform: "node",
    logLevel: "silent",
  });
  const file = join(dir, `${name}.mjs`);
  writeFileSync(file, out.outputFiles[0]!.text);
  return file;
}

/** `p`, or the string "did not settle" when `p` has not settled within the deadline. */
async function within<T>(p: Promise<T>): Promise<T | "did not settle"> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<"did not settle">((resolve) => {
    timer = setTimeout(() => resolve("did not settle"), DEADLINE_MS);
  });
  try {
    return await Promise.race([p, late]);
  } finally {
    clearTimeout(timer);
  }
}

describe("the built entry point in one bundle", () => {
  it("loads through a static import", async () => {
    const file = await bundle("static", `export * from ${JSON.stringify(ENTRY)};`);
    const m = await within(import(pathToFileURL(file).href) as Promise<Record<string, unknown>>);
    expect(m).not.toBe("did not settle");
    expect(Object.keys(m).sort()).toEqual(EXPORTS);
  }, DEADLINE_MS * 3);

  it("loads through a lazy import()", async () => {
    const file = await bundle("lazy", `export const load = () => import(${JSON.stringify(ENTRY)});`);
    const { load } = (await import(pathToFileURL(file).href)) as { load: () => Promise<Record<string, unknown>> };
    const m = await within(load());
    expect(m).not.toBe("did not settle");
    expect(Object.keys(m).sort()).toEqual(EXPORTS);
  }, DEADLINE_MS * 3);
});
