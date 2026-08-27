import { pageMarkdown } from "@/lib/llms";
import { absoluteUrl } from "@/lib/site";
import { source } from "@/lib/source";

// Required for route handlers under `output: export`.
export const dynamic = "force-static";

/**
 * `/md/<page>.md` — one documentation page as plain Markdown, the file the page's
 * "copy Markdown" and "open in …" actions point at. Same renderer as `/llms-full.txt`.
 */
export async function generateStaticParams() {
  return source.getPages().map((page) => {
    const slug = page.url.split("/").filter(Boolean);
    const last = slug.at(-1);
    if (last === undefined) throw new Error(`page with no slug: ${page.url}`);
    return { slug: [...slug.slice(0, -1), `${last}.md`] };
  });
}

export async function GET(
  _request: Request,
  context: { params: Promise<{ slug: string[] }> },
) {
  const { slug } = await context.params;
  const last = slug.at(-1);
  if (last === undefined || !last.endsWith(".md")) {
    return new Response("not found", { status: 404 });
  }
  const page = source.getPage([...slug.slice(0, -1), last.slice(0, -3)]);
  if (!page) return new Response("not found", { status: 404 });

  const body = await pageMarkdown(page);
  const text = [
    `# ${page.data.title}`,
    "",
    ...(page.data.description ? [`> ${page.data.description}`, ""] : []),
    `Source: ${absoluteUrl(page.url)}`,
    "",
    body,
  ].join("\n");
  return new Response(text, {
    headers: { "content-type": "text/markdown; charset=utf-8" },
  });
}
