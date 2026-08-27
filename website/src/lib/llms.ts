import type { Folder, Node, Root } from "fumadocs-core/page-tree";
import { siteConfig } from "@/lib/site";
import { source } from "@/lib/source";

type DocPage = ReturnType<typeof source.getPages>[number];

export interface OrderedPage {
  /** The sidebar section the page sits under, from its nearest separator. */
  section: string | undefined;
  page: DocPage;
}

/** Sidebar labels are plain strings from `meta.json`; anything else is not a label. */
function label(name: unknown): string | undefined {
  return typeof name === "string" && name.length > 0 ? name : undefined;
}

/**
 * Every documentation page in the order the sidebar presents it, with the section it
 * belongs to — so the machine-readable exports read in the order a person is meant to.
 * `getPages()` alone is alphabetical, which puts the agent skill before the introduction.
 */
export function orderedPages(): OrderedPage[] {
  const byUrl = new Map(source.getPages().map((page) => [page.url, page]));
  const out: OrderedPage[] = [];
  const seen = new Set<string>();

  const push = (url: string, section: string | undefined) => {
    const page = byUrl.get(url);
    if (!page || seen.has(url)) return;
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
        if (folder.index) push(folder.index.url, current);
        walk(folder.children, current);
      } else if (!node.external) {
        push(node.url, current);
      }
    }
  };

  const root: Root = source.pageTree;
  walk(root.children, undefined);

  // A page absent from every meta.json still exists; the tree is an ordering, not a filter.
  for (const page of source.getPages()) push(page.url, undefined);

  return out;
}

/** Where a page's plain-Markdown twin is served: `/md/<path>.md` (`/mcp` → `/md/mcp.md`). */
export function markdownPath(url: string): string {
  return `/md${url}.md`;
}

/**
 * A page as plain Markdown a reader outside this site can use.
 *
 * `getText("processed")` is the MDX after the remark pipeline, which is faithful but not
 * yet portable: the stringifier escapes a few characters as numeric entities, the
 * site's own components (`<Callout>`, `<Steps>`) survive as JSX, and links are
 * root-relative. Each is rewritten here rather than in the pipeline, because the HTML
 * build wants exactly what the pipeline emits.
 */
export async function pageMarkdown(page: DocPage): Promise<string> {
  const processed = await page.data.getText("processed");
  const out: string[] = [];
  let quoting = false;
  let steps = 0;
  for (const raw of processed.split("\n")) {
    // Inside <Steps>, every line is indented by the containers; four spaces would read
    // as a code block once the containers are gone.
    const line = (steps > 0 ? raw.replace(/^ {1,4}/, "") : raw)
      .replace(/&#x([0-9A-Fa-f]+);/g, (_: string, hex: string) =>
        String.fromCodePoint(Number.parseInt(hex, 16)),
      )
      .replace(/\]\(\/(?=[^)]*\))/g, `](${siteConfig.url}/`);

    const callout = /^\s*<Callout(?:\s+type="(\w+)")?>\s*$/.exec(line);
    if (callout) {
      quoting = true;
      const kind = callout[1] === "warn" ? "Warning" : "Note";
      out.push(`> **${kind}**`);
      continue;
    }
    if (/^\s*<\/Callout>\s*$/.test(line)) {
      quoting = false;
      continue;
    }
    if (/^\s*<Steps>\s*$/.test(line)) {
      steps += 1;
      continue;
    }
    if (/^\s*<\/Steps>\s*$/.test(line)) {
      steps -= 1;
      continue;
    }
    if (/^\s*<\/?Step>\s*$/.test(line)) continue;

    out.push(quoting ? (line.length > 0 ? `> ${line}` : ">") : line);
  }
  return `${out.join("\n").trim()}\n`;
}
