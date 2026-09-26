import { orderedPages, pageMarkdown } from "@/lib/llms";
import { absoluteUrl, siteConfig } from "@/lib/site";

export const dynamic = "force-static";

/** `/llms-full.txt`: every page as Markdown, in sidebar order, from the same source the HTML is rendered from. */
export async function GET() {
  const sections = await Promise.all(
    orderedPages().map(async ({ page }) =>
      [
        `# ${page.data.title}`,
        "",
        ...(page.data.description ? [`> ${page.data.description}`, ""] : []),
        `Source: ${absoluteUrl(page.url)}`,
        "",
        (await pageMarkdown(page)).trim(),
      ].join("\n"),
    ),
  );
  const header = [
    `# ${siteConfig.name}: the full documentation`,
    "",
    `> ${siteConfig.description}`,
    "",
    `Site: ${siteConfig.url}. Index: ${siteConfig.url}/llms.txt.`,
    "",
  ].join("\n");
  return new Response(`${header}\n${sections.join("\n\n---\n\n")}\n`, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
