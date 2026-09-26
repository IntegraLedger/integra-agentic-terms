import { resolve } from "node:path";
import { createMDX } from "fumadocs-mdx/next";
import type { NextConfig } from "next";

const withMDX = createMDX();

/** The repository root: the site reads its pages from ../docs, so the bundler's root is one level up. */
const root = resolve(import.meta.dirname, "..");

const config: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  outputFileTracingRoot: root,
  turbopack: { root },
};

export default withMDX(config);
