import "server-only";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** The version of the packages these pages document, read from @integraledger/terms's manifest at build time. */
export const packageVersion: string = (() => {
  // `next build` runs in website/, one level below the packages.
  const manifest = join(process.cwd(), "..", "agentic-terms", "package.json");
  const { version } = JSON.parse(readFileSync(manifest, "utf8")) as { version?: unknown };
  if (typeof version !== "string" || version.length === 0) throw new Error(`${manifest} carries no version`);
  return version;
})();
