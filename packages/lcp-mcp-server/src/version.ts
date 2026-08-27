import { readFileSync } from "node:fs";

/**
 * A package manifest's `version`, or a named failure.
 *
 * Takes the manifest URL rather than closing over one so that every refusal arm is REACHABLE from a test.
 * A manifest with no `version`, a non-string one, an empty one, or JSON that is not an object at all each
 * has to produce an error naming the file — never a server that declares `undefined` as its version to
 * every connected client.
 */
export function readManifestVersion(manifestUrl: URL): string {
  const manifest: unknown = JSON.parse(readFileSync(manifestUrl, "utf8"));
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    !("version" in manifest) ||
    typeof manifest.version !== "string" ||
    manifest.version.length === 0
  )
    throw new Error(
      `${manifestUrl.href} states no non-empty string "version" — the server cannot declare an identity it cannot read`,
    );
  return manifest.version;
}

/**
 * This package's own version, READ from its manifest — never restated in source.
 *
 * A FUNCTION, and a `const` only for the name beside it, because the two facts have different owners. The
 * server name is ours to declare and changing it is a deliberate act. The version is the MANIFEST's to
 * declare, and `changeset version` rewrites it without touching a line of TypeScript. A hardcoded constant
 * would keep announcing the previous version over the wire to every MCP client, and nothing in a release
 * would catch it: the manifest and the constant would both be internally consistent while disagreeing with
 * each other. Reading the manifest makes that drift impossible rather than merely detectable.
 *
 * `../package.json` resolves to the package root from `src/` and from `dist/` alike, and npm includes the
 * manifest in every tarball regardless of `files`, so the read is as valid installed as it is in the
 * workspace.
 */
export function serverVersion(): string {
  return readManifestVersion(new URL("../package.json", import.meta.url));
}
