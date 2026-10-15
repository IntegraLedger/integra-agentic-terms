import { dirname, relative, resolve } from "node:path";
import type { Definition, Link, Root } from "mdast";
import { replaceSource } from "fumadocs-core/mdx-plugins/stringifier";

type SourceFile = Parameters<typeof replaceSource>[0];

/**
 * Rewrites a relative link to another page of `docs/` (`../reference/pairings.md#ethereum`) into the page's URL on
 * the site (`/reference/pairings#ethereum`), so the same Markdown links correctly on GitHub and here. Links that leave
 * `docs/`, and absolute links, are left as written. The page's Markdown copy, which fumadocs writes from the authored
 * source, carries each rewritten link too (`replaceSource`).
 */
export function remarkDocLinks(options: { root: string }) {
  return (tree: Root, file: { path?: string }): void => {
    const from = file.path === undefined ? undefined : dirname(file.path);
    if (from === undefined) return;
    const visit = (node: Root | Root["children"][number]): void => {
      if (node.type === "link" || node.type === "definition") {
        const url = rewrite(node.url, from, options.root);
        if (url !== undefined) {
          replaceSource(file as SourceFile, node, (s) => markdownOf(node, url, s.inner(node)));
          node.url = url;
        }
      }
      if ("children" in node) for (const child of node.children) visit(child);
    };
    visit(tree);
  };
}

/** The site URL a relative link to a page of `docs/` names, or undefined for any other link. */
function rewrite(url: string, from: string, root: string): string | undefined {
  const m = /^(?!\w+:|\/|#)([^#?]+\.md)(#.*)?$/.exec(url);
  if (m === null) return undefined;
  const target = relative(root, resolve(from, m[1]!));
  if (target.startsWith("..")) return undefined;
  const slug = target.replace(/\\/g, "/").replace(/\.md$/, "").replace(/(^|\/)index$/, "");
  return `/${slug}${m[2] ?? ""}`;
}

/** The link or definition as Markdown, with its new URL. */
function markdownOf(node: Link | Definition, url: string, inner: string): string {
  const title = node.title ? ` "${node.title.replace(/["\\]/g, "\\$&")}"` : "";
  return node.type === "link" ? `[${inner}](${url}${title})` : `[${node.label ?? node.identifier}]: ${url}${title}`;
}
