import { createMDX } from "fumadocs-mdx/next";
import type { NextConfig } from "next";

const withMDX = createMDX();

const config: NextConfig = {
  output: "export",
  images: {
    unoptimized: true,
  },
  // This app has its own lockfile inside a pnpm workspace that has another.
  // Without this, Next infers the workspace root and warns on every build.
  outputFileTracingRoot: import.meta.dirname,
};

export default withMDX(config);
