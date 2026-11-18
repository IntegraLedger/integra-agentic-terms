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

/**
 * Every page, in the order the sidebar shows it, with its section: the separator above it. A folder takes the
 * separator it sits under (each API package is a folder under "API"); only a folder before any separator names a
 * section of its own. Pages the sidebar does not list come last.
 */
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
        const name = current ?? label(folder.name);
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

/** The heading `/llms.txt` gives a section: the pages before the first separator are where to start. */
export function sectionHeading(section: string | undefined): string {
  if (section === undefined) return "Start here";
  return section === "API" ? "API reference" : section;
}

/**
 * The sections whose pages are also served as one file, at `<path>/llms-full.txt`, each by its route under
 * src/app/<path>/llms-full.txt/. Every page of a section sits under its path; the build stops when one does not.
 */
export const SECTION_FILES: ReadonlyArray<{ section: string; path: string }> = [
  { section: "Guides", path: "/guides" },
  { section: "Reference", path: "/reference" },
  { section: "API", path: "/api" },
];

/** The pages of the section served at `<path>/llms-full.txt`, in sidebar order. */
export function sectionPages(path: string): Page[] {
  const file = SECTION_FILES.find((f) => f.path === path);
  if (file === undefined) throw new Error(`no section is served at ${path}/llms-full.txt`);
  const pages = orderedPages()
    .filter(({ section }) => section === file.section)
    .map(({ page }) => page);
  if (pages.length === 0) throw new Error(`the section ${file.section} has no page`);
  for (const page of pages) {
    if (page.url !== path && !page.url.startsWith(`${path}/`)) {
      throw new Error(`${page.url}, in the section ${file.section}, is not under ${path}: move SECTION_FILES with it`);
    }
  }
  return pages;
}

/** Where the build writes a page's Markdown copy: `/md/<path>.md`, and `/md/index.md` for the home page. */
export function markdownPath(url: string): string {
  return url === "/" ? "/md/index.md" : `/md${url}.md`;
}

/**
 * Where a reader asks for a page as Markdown: the page's address with `.md` appended (https://llmstxt.org), and
 * `/index.md` for the home page. The site's Worker (`worker.js`) answers it with the page's Markdown copy.
 */
export function markdownUrl(url: string): string {
  return url === "/" ? "/index.md" : `${url}.md`;
}

/** Where a page's social card is written: `/og/<slugs>/image.png`, and `/og/image.png` for the home page. */
export function ogImagePath(slugs: string[]): string {
  return `/og/${[...slugs, "image.png"].join("/")}`;
}

/** The protocol package's repository and documentation site, whose profiles and vectors that site serves. */
const PROTOCOL = { github: "https://github.com/IntegraLedger/integra-protocol", site: siteConfig.lcpUrl };

/**
 * The repository files a page may link on GitHub that a site serves as they are: this site's profile, vectors and
 * skill, and the protocol site's profiles and vectors. A link to one names the site's copy, from the commit that site
 * is built from; a link to a folder names its index where it has one.
 */
const COPIES: ReadonlyArray<{ github: string; site: string; file: RegExp; index?: string }> = [
  { github: `${siteConfig.githubUrl}/blob/main/agentic-terms/profiles/`, site: `${siteConfig.url}/profiles/`, file: /^[\w.-]+\.md$/ },
  { github: `${siteConfig.githubUrl}/blob/main/agentic-terms/vectors/`, site: `${siteConfig.url}/vectors/`, file: /^[\w.-]+\.json$/ },
  {
    github: `${siteConfig.githubUrl}/blob/main/agentic-terms-mcp/skills/`,
    site: `${siteConfig.url}/.well-known/agent-skills/`,
    file: /^[\w-]+\/SKILL\.md$/,
  },
  { github: `${PROTOCOL.github}/blob/main/lcp/profiles/`, site: `${PROTOCOL.site}/profiles/`, file: /^[\w.-]+\.md$/ },
  { github: `${PROTOCOL.github}/blob/main/lcp/vectors/`, site: `${PROTOCOL.site}/vectors/`, file: /^[\w.-]+\.json$/ },
  { github: `${PROTOCOL.github}/tree/main/lcp/profiles`, site: `${PROTOCOL.site}/profiles/llms.txt`, file: /^\/?$/, index: "" },
  { github: `${PROTOCOL.github}/tree/main/lcp/vectors`, site: `${PROTOCOL.site}/vectors/llms.txt`, file: /^\/?$/, index: "" },
];

/**
 * Links that keep an agent in Markdown: a link to a page of this site names the page's Markdown address, and a link
 * to a profile, vector file or skill on GitHub names the copy a site serves (`COPIES`). Only link targets change: the
 * text of the page, its code and its other links are left as written.
 */
function agentLinks(text: string): string {
  const pages = new Set(source.getPages().map((p) => p.url));
  const target = (url: string): string => {
    const at = url.indexOf("#");
    const address = at === -1 ? url : url.slice(0, at);
    const hash = at === -1 ? "" : url.slice(at);
    if (address === siteConfig.url || address.startsWith(`${siteConfig.url}/`)) {
      const path = address.slice(siteConfig.url.length) || "/";
      return pages.has(path) ? `${siteConfig.url}${markdownUrl(path)}${hash}` : url;
    }
    for (const copy of COPIES) {
      if (!address.startsWith(copy.github)) continue;
      const rest = address.slice(copy.github.length);
      if (copy.file.test(rest)) return `${copy.site}${copy.index ?? rest}${hash}`;
    }
    return url;
  };
  return text
    .replace(/\]\((<?)(https:\/\/[^)\s>]+)(>?)(?=[)\s])/g, (_, open: string, url: string, close: string) => `](${open}${target(url)}${close}`)
    .replace(/^(\[[^\]]+\]:\s*)(https:\/\/\S+)/gm, (_, lead: string, url: string) => `${lead}${target(url)}`);
}

/**
 * A page as Markdown a reader outside the site can use: the page's authored Markdown with the edits the remark plugins
 * make through `replaceSource()` (links to other pages rewritten to their site URLs), numeric character references
 * decoded, root-relative links made absolute, and links kept in Markdown (`agentLinks`). A diagram stays the `mermaid`
 * block it is written as.
 */
export async function pageMarkdown(page: Page): Promise<string> {
  const processed = await page.data.getText("processed");
  const text = processed
    .replace(/&#x([0-9A-Fa-f]+);/g, (_: string, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/\]\(\/(?=[^)]*\))/g, `](${siteConfig.url}/`)
    .replace(/^(\[[^\]]+\]:\s*)\/(?=\S)/gm, `$1${siteConfig.url}/`);
  return `${agentLinks(text).trim()}\n`;
}

/** The facts a reader needs beside a page: what it documents. */
export interface PageFacts {
  /** The packages and versions the pages document, as one phrase. */
  versions: string;
}

/** The date a page last changed, where git gives one: the generated API pages have none. */
export function lastModifiedOf(page: Page): Date | undefined {
  const date = "lastModified" in page.data ? page.data.lastModified : undefined;
  return date instanceof Date ? date : undefined;
}

/**
 * A page as a standalone Markdown document: title, description, canonical URL, the date the page last changed and the
 * versions it documents, the index of every page, then the body. In a file of many pages (`inFile`), the index line is
 * left to the file's header, and each link to a fragment of the page names the page, so that a fragment two pages
 * share points at one.
 */
export async function pageDocument(page: Page, facts: PageFacts, { inFile = false } = {}): Promise<string> {
  let body = await pageMarkdown(page);
  const markdown = `${siteConfig.url}${markdownUrl(page.url)}`;
  if (inFile) {
    body = body
      .replace(/\]\(#([^)\s]+)\)/g, `](${markdown}#$1)`)
      .replace(/^(\[[^\]]+\]:\s*)#(\S+)/gm, `$1${markdown}#$2`);
  }
  const date = lastModifiedOf(page);
  const updated = date === undefined ? "" : `Updated ${date.toISOString().slice(0, 10)}. `;
  return [
    `# ${page.data.title}`,
    "",
    ...(page.data.description ? [`> ${page.data.description}`, ""] : []),
    `Source: ${new URL(page.url, siteConfig.url).toString()}`,
    "",
    `${updated}Documents ${facts.versions}.${inFile ? "" : ` Every page of this site is listed in ${siteConfig.url}/llms.txt.`}`,
    "",
    body,
  ].join("\n");
}

/** Pages as one Markdown file: a header, then each page, in the order given. */
export async function pagesFile(header: string[], pages: Page[], facts: PageFacts): Promise<string> {
  const documents = await Promise.all(pages.map((page) => pageDocument(page, facts, { inFile: true })));
  return `${header.join("\n")}\n\n${documents.map((d) => d.trim()).join("\n\n---\n\n")}\n`;
}

/**
 * A file's size an agent can plan by: its bytes, and its tokens estimated at 4 bytes a token, rounded ("341 KB, about
 * 85,000 tokens").
 */
export function sizeOf(text: string): string {
  const bytes = new TextEncoder().encode(text).length;
  const size = bytes >= 1e6 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1e3))} KB`;
  const step = bytes >= 40_000 ? 1000 : 100;
  const tokens = Math.max(step, Math.round(bytes / 4 / step) * step);
  return `${size}, about ${tokens.toLocaleString("en-US")} tokens`;
}

/** A description cut to at most `max` characters, at a word, for a line of an index. */
export function brief(text: string, max = 300): string {
  const flat = text.replace(/\s+/g, " ").trim();
  if (flat.length <= max) return flat;
  const cut = flat.lastIndexOf(" ", max - 1);
  return `${flat.slice(0, cut > 0 ? cut : max - 1).replace(/[\s,;:]+$/, "")}…`;
}
