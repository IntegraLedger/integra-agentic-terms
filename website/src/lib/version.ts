import "server-only";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The version of the packages these pages document, read from the workspace at build time.
 *
 * The two packages are a `fixed` changeset group and version in lockstep, so one number
 * describes both. Read from the manifest rather than restated here: a version typed into
 * the site would be a second statement of a fact the release process owns, and it would
 * drift the first time a release shipped without someone remembering this file.
 *
 * `server-only` makes a client import a build error naming this file, rather than a
 * bundler complaint about `node:fs`.
 */
export const packageVersion: string = (() => {
  // Resolved from the working directory: `next build` runs in website/, and
  // `import.meta.dirname` is undefined inside Next's server bundle.
  const manifest = join(
    process.cwd(),
    "..",
    "packages",
    "agentic-terms",
    "package.json",
  );
  const { version } = JSON.parse(readFileSync(manifest, "utf8")) as {
    version: string;
  };
  if (typeof version !== "string" || version.length === 0) {
    throw new Error(`${manifest} carries no version`);
  }
  return version;
})();
