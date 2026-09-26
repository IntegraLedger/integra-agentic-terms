#!/usr/bin/env node
// Writes src/version.ts: the package's version from package.json, so the built package reads no file when it loads.
import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const { version } = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));
if (typeof version !== "string" || version === "") throw new Error("package.json has no version");
writeFileSync(
  new URL("src/version.ts", root),
  `// Written by scripts/version.mjs from package.json.\nexport const VERSION: string = ${JSON.stringify(version)};\n`,
);
