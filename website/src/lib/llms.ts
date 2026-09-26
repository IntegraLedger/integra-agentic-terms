import type { Folder, Node, Root } from "fumadocs-core/page-tree";
import { siteConfig } from "@/lib/site";
import { type Page, source } from "@/lib/source";

export interface OrderedPage {
  /** The sidebar section the page sits under, from its nearest separator. */
  section: string | undefined;
  page: Page;
}

function label(name: unknown): string | undefined {
  return typeof name === "string" && name.length > 0 ? name : undefined;
}

/** Every page, in the order the sidebar shows it, with its section. Pages the sidebar does not list come last. */
export function orderedPages(): OrderedPage[] {
  const byUrl = new Map(source.getPages().map((page) => [page.url, page]));
  const out: OrderedPage[] = [];
  const seen = new Set<string>();
  const push = (url: string, section: string | undefined) => {
    const page = byUrl.get(url);
    if (page === undefined || seen.has(url)) return;
    seen.add(url);
    out.push({ section, page });
  };
  const walk = (nodes: Node[], section: string | undefined) => {
    let current = section;
    for (const node of nodes) {
      if (node.type === "separator") {
        current = label(node.name) ?? current;
      } else if (node.type === "folder") {
        const folder: Folder = node;
        const name = label(folder.name) ?? current;
        if (folder.index) push(folder.index.url, name);
        walk(folder.children, name);
      } else if (!node.external) {
        push(node.url, current);
      }
    }
  };
  const root: Root = source.pageTree;
  walk(root.children, undefined);
  for (const page of source.getPages()) push(page.url, undefined);
  return out;
}

/** Where a page's Markdown copy is served: `/md/<path>.md`, and `/md/index.md` for the home page. */
export function markdownPath(url: string): string {
  return url === "/" ? "/md/index.md" : `/md${url}.md`;
}

/** A `<Mermaid chart="…" />` element of the processed Markdown, back as the `mermaid` block it was written as. */
const MERMAID = /<Mermaid\s+chart="((?:[^"\\]|\\.)*)"\s*\/>/g;

/**
 * A page as Markdown a reader outside the site can use: the processed Markdown the page is rendered from, with
 * diagrams back as `mermaid` blocks, numeric entities decoded and root-relative links made absolute.
 */
export async function pageMarkdown(page: Page): Promise<string> {
  const processed = await page.data.getText("processed");
  return `${processed
    .replace(MERMAID, (_: string, chart: string) => `\`\`\`mermaid\n${chart.replace(/\\(.)/g, "$1")}\n\`\`\``)
    .replace(/&#x([0-9A-Fa-f]+);/g, (_: string, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/\]\(\/(?=[^)]*\))/g, `](${siteConfig.url}/`)
    .trim()}\n`;
}
