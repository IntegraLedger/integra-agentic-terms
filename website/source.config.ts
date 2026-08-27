import { defineConfig, defineDocs } from "fumadocs-mdx/config";
import lastModified from "fumadocs-mdx/plugins/last-modified";

export const docs = defineDocs({
  dir: "content/docs",
  docs: {
    postprocess: {
      // Exposes each page as processed Markdown (`getText("processed")`), which is what
      // `/llms-full.txt` serves — the same source the HTML is rendered from, never a copy.
      // Heading IDs are an HTML-anchor concern; in plain Markdown they are noise.
      includeProcessedMarkdown: { headingIds: false },
    },
  },
});

export default defineConfig({
  // Each page's last-modified time comes from git, so `<lastmod>` in the sitemap and the
  // "last updated" line on the page state the commit that actually changed the file rather
  // than the build clock.
  plugins: [lastModified({ versionControl: "git" })],
});
