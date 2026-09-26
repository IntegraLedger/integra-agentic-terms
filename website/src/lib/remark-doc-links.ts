import { dirname, relative, resolve } from "node:path";
import type { Link, Root } from "mdast";

/**
 * Rewrites a relative link to another page of `docs/` (`../reference/pairings.md#ethereum`) into the page's URL on
 * the site (`/reference/pairings#ethereum`), so the same Markdown links correctly on GitHub and here. Links that leave
 * `docs/`, and absolute links, are left as written.
 */
export function remarkDocLinks(options: { root: string }) {
  return (tree: Root, file: { path?: string }): void => {
    const from = file.path === undefined ? undefined : dirname(file.path);
    if (from === undefined) return;
    const visit = (node: Root | Root["children"][number]): void => {
      if (node.type === "link") rewrite(node as Link, from, options.root);
      if ("children" in node) for (const child of node.children) visit(child);
    };
    visit(tree);
  };
}

function rewrite(link: Link, from: string, root: string): void {
  const m = /^(?!\w+:|\/|#)([^#?]+\.md)(#.*)?$/.exec(link.url);
  if (m === null) return;
  const target = relative(root, resolve(from, m[1]!));
  if (target.startsWith("..")) return;
  const slug = target.replace(/\\/g, "/").replace(/\.md$/, "").replace(/(^|\/)index$/, "");
  link.url = `/${slug}${m[2] ?? ""}`;
}
