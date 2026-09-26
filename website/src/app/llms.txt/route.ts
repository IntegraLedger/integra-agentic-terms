import { orderedPages } from "@/lib/llms";
import { absoluteUrl, siteConfig } from "@/lib/site";

export const dynamic = "force-static";

/** `/llms.txt` (https://llmstxt.org): the index of every page, in sidebar order, with absolute URLs. */
export function GET() {
  const lines: string[] = [
    `# ${siteConfig.name}`,
    "",
    `> ${siteConfig.description}`,
    "",
    `Packages: ${siteConfig.packages.map((p) => `${p.name} (${p.url})`).join(", ")}. Source: ${siteConfig.githubUrl}.`,
    "",
    `- Every page as one Markdown file: ${siteConfig.url}/llms-full.txt`,
    `- Each page as Markdown: ${siteConfig.url}/md/<page>.md`,
  ];
  let section: string | undefined | null = null;
  for (const { section: s, page } of orderedPages()) {
    if (s !== section) {
      section = s;
      lines.push("", `## ${section ?? "Documentation"}`, "");
    }
    const description = page.data.description ? `: ${page.data.description}` : "";
    lines.push(`- [${page.data.title}](${absoluteUrl(page.url)})${description}`);
  }
  return new Response(`${lines.join("\n")}\n`, { headers: { "content-type": "text/plain; charset=utf-8" } });
}
