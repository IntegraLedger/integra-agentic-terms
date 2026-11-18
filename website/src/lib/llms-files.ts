import "server-only";
import {
  brief,
  lastModifiedOf,
  markdownUrl,
  orderedPages,
  type PageFacts,
  pagesFile,
  SECTION_FILES,
  sectionHeading,
  sectionPages,
  sizeOf,
} from "@/lib/llms";
import { absoluteUrl, siteConfig } from "@/lib/site";
import { profiles, skills, vectorFiles } from "@/lib/terms-files";
import { documents, lcpRange, mcpNodeRange, mcpVersion, nodeRange, packageVersion, python } from "@/lib/version";

// The text of the site's files for language models (https://llmstxt.org), each served by a route of its own. Server
// only: the versions and the packages' files are read from the filesystem at build time.

/** The facts every Markdown copy states: the versions the pages document. */
export const pageFacts: PageFacts = { versions: documents };

/** `/llms-full.txt`: every page, in sidebar order. */
export async function fullFile(): Promise<string> {
  return pagesFile(
    [
      `# ${siteConfig.name}: the full documentation`,
      "",
      `> ${siteConfig.llmsSummary}`,
      "",
      `Every page of ${siteConfig.url}, in the order of its index, ${siteConfig.url}/llms.txt. They document ${documents}.`,
    ],
    orderedPages().map(({ page }) => page),
    pageFacts,
  );
}

/** `<path>/llms-full.txt`: the pages of one section of `/llms.txt`. */
export async function sectionFile(path: string): Promise<string> {
  const file = SECTION_FILES.find((f) => f.path === path);
  const pages = sectionPages(path);
  return pagesFile(
    [
      `# ${siteConfig.name}: ${sectionHeading(file?.section)}`,
      "",
      `> The ${pages.length} pages of the section ${sectionHeading(file?.section)} of ${siteConfig.url}/llms.txt, in its order. ` +
        `They document ${documents}.`,
    ],
    pages,
    pageFacts,
  );
}

/**
 * `/.well-known/agent-skills/index.json`: the MCP server's skills, each with the SHA-256 of its file, in the form
 * the agent skills discovery index takes (schema 0.2.0).
 */
export function skillsIndex(): string {
  const index = {
    $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
    skills: skills().map((s) => ({
      name: s.name,
      type: "skill-md",
      description: s.when,
      url: absoluteUrl(s.path),
      digest: `sha256:${s.sha256}`,
    })),
  };
  return `${JSON.stringify(index, null, 2)}\n`;
}

/**
 * `/llms.txt`: what the pages document, where the protocol is documented, the rules an agent must not miss, then every
 * page in sidebar order as Markdown, each section led by the file of all its pages with its size, the gate's profile,
 * vectors and skill, and, under Optional, the whole site in one file and the project's links.
 */
export async function llmsIndex(): Promise<string> {
  const pages = orderedPages();
  const updated = pages
    .map(({ page }) => lastModifiedOf(page)?.toISOString().slice(0, 10))
    .filter((d) => d !== undefined)
    .sort()
    .at(-1);
  const node = nodeRange === mcpNodeRange ? `on Node.js ${nodeRange}` : `on Node.js ${nodeRange} and ${mcpNodeRange}`;
  const [terms, mcp, py] = siteConfig.packages;
  const lines: string[] = [
    `# ${siteConfig.name}`,
    "",
    `> ${siteConfig.llmsSummary}`,
    "",
    `These pages document ${terms.name} ${packageVersion} (peer @integraledger/lcp ${lcpRange}) and ${mcp.name} ` +
      `${mcpVersion} ${node}, and ${py.name} ${python.version} on Python ${python.requires}.` +
      `${updated === undefined ? "" : ` Pages last updated ${updated}.`} Under 0.x a minor release may change the API: ` +
      `these pages hold for these versions (\`npm install ${terms.name}@${packageVersion}\`, ` +
      `\`pip install ${py.name}==${python.version}\`).`,
    "",
    "The gate implements the Legal Context Protocol (LCP) and takes each pairing's binding from @integraledger/lcp. " +
      `That package and the protocol are documented at ${siteConfig.lcpUrl}/llms.txt; its pairing registry, with each ` +
      `pairing's export, is ${siteConfig.lcpUrl}/reference/pairings.md.`,
    "",
    "Before you write code with these packages:",
    "- The gate holds no keys and judges none of the record's terms: what the record says is for you and your " +
      "principal to judge.",
    "- A decline is a value, never an exception: `{ decline: { code, detail } }` in TypeScript, " +
      "`Declined(code, detail, moved)` in Python (Declines, below). A decline that carries `moved` means the signer already moved the payment: keep what it " +
      "holds, the payment as signed, the ATR's bytes and their hash, to present again.",
    "- With @integraledger/terms-mcp, install its skill confirming-the-atr-hash-before-paying with the server " +
      "(MCP server, below; the skill is listed under Profile, vectors and skill).",
    "",
    "Each page link below is the page as Markdown; the same address without `.md` is the HTML page, and a request " +
      "there whose Accept header ranks `text/markdown` at least as high as `text/html` gets the Markdown. A section's " +
      "first link is all of its pages in one file. Sizes in tokens are estimates, at 4 bytes a token.",
  ];

  let section: string | undefined | null = null;
  for (const { section: s, page } of pages) {
    if (s !== section) {
      section = s;
      lines.push("", `## ${sectionHeading(section)}`, "");
      const file = SECTION_FILES.find((f) => f.section === section);
      if (file !== undefined) {
        const count = sectionPages(file.path).length;
        const what = section === "API" ? "Generated from the source of each package; " : "";
        lines.push(
          `- [The ${count} ${sectionHeading(section)} pages in one file](${siteConfig.url}${file.path}/llms-full.txt): ` +
            `${what}${sizeOf(await sectionFile(file.path))}.`,
        );
      }
    }
    const description = page.data.description ? `: ${brief(page.data.description)}` : "";
    lines.push(`- [${page.data.title}](${absoluteUrl(markdownUrl(page.url))})${description}`);
  }

  lines.push(
    "",
    "## Profile, vectors and skill",
    "",
    ...profiles().map(
      (f) => `- [Profile ${f.name}](${siteConfig.url}${f.path}): ${f.description}; the rules both gates implement.`,
    ),
    ...vectorFiles().map((f) => `- [Vectors ${f.name}](${siteConfig.url}${f.path}): ${f.description}`),
    ...skills().map((s) => `- [Skill ${s.name}](${siteConfig.url}${s.path}): ${s.description}`),
    `- [Agent skills index](${siteConfig.url}/.well-known/agent-skills/index.json): The skills above, each with the ` +
      "SHA-256 of its file, for an agent that discovers skills by that index.",
    "",
    "## Optional",
    "",
    `- [Every page in one file](${siteConfig.url}/llms-full.txt): ${sizeOf(await fullFile())}.`,
    `- [Source](${siteConfig.githubUrl}): The repository.`,
    ...siteConfig.packages.map((p) => `- [${p.name} on ${p.url.includes("pypi.org") ? "PyPI" : "npm"}](${p.url})`),
    `- [Security policy](${siteConfig.githubUrl}/blob/main/SECURITY.md)`,
    `- [License, Apache-2.0](${siteConfig.githubUrl}/blob/main/LICENSE)`,
  );
  return `${lines.join("\n")}\n`;
}

/** A route's answer: `text` as plain text, or as the type given. */
export function textResponse(text: string | Buffer, type = "text/plain; charset=utf-8"): Response {
  return new Response(typeof text === "string" ? text : new Uint8Array(text), { headers: { "content-type": type } });
}
