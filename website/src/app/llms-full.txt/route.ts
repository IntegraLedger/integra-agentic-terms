import { orderedPages, pageMarkdown } from "@/lib/llms";
import { absoluteUrl, siteConfig } from "@/lib/site";

// Required for route handlers under `output: export`.
export const dynamic = "force-static";

/**
 * `/llms-full.txt` — every documentation page as processed Markdown, in sidebar order.
 * The text is the same MDX the HTML is rendered from, stringified after the remark
 * pipeline ran and made portable by `pageMarkdown`, so an agent reading this and a person
 * reading the site read one document.
 */
export async function GET() {
  const sections = await Promise.all(
    orderedPages().map(async ({ page }) => {
      const body = await pageMarkdown(page);
      return [
        `# ${page.data.title}`,
        "",
        ...(page.data.description ? [`> ${page.data.description}`, ""] : []),
        `Source: ${absoluteUrl(page.url)}`,
        "",
        body.trim(),
      ].join("\n");
    }),
  );

  const header = [
    `# ${siteConfig.name} — full documentation`,
    "",
    `> ${siteConfig.description}`,
    "",
    `Canonical site: ${siteConfig.url} · Index: ${siteConfig.url}/llms.txt`,
    "",
  ].join("\n");

  return new Response(`${header}\n${sections.join("\n\n---\n\n")}\n`, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
