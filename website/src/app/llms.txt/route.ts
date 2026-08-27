import { orderedPages } from "@/lib/llms";
import { absoluteUrl, siteConfig } from "@/lib/site";

// Required for route handlers under `output: export`.
export const dynamic = "force-static";

/**
 * `/llms.txt` — the index an AI crawler reads first (https://llmstxt.org). Generated from
 * the live page tree, in sidebar order, with absolute URLs, so it cannot list a page that
 * does not exist or omit one that does. The bodies are at `/llms-full.txt`.
 */
export function GET() {
  const lines: string[] = [
    `# ${siteConfig.name}`,
    "",
    `> ${siteConfig.description}`,
    "",
    `Two Apache-2.0 packages — \`${siteConfig.packages.terms.name}\` and \`${siteConfig.packages.mcp.name}\` — implementing the buyer side of the ${siteConfig.standard.name} (${siteConfig.standard.short}): ${siteConfig.standard.specUrl}`,
    "",
    `- Full documentation as one Markdown file: ${siteConfig.url}/llms-full.txt`,
    `- Source: ${siteConfig.githubUrl}`,
    `- npm: ${siteConfig.packages.terms.npm} · ${siteConfig.packages.mcp.npm}`,
  ];

  let section: string | undefined;
  for (const { section: s, page } of orderedPages()) {
    if (s !== section) {
      section = s;
      lines.push("", `## ${section ?? "Other"}`, "");
    }
    const description = page.data.description
      ? `: ${page.data.description}`
      : "";
    lines.push(
      `- [${page.data.title}](${absoluteUrl(page.url)})${description}`,
    );
  }

  return new Response(`${lines.join("\n")}\n`, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
