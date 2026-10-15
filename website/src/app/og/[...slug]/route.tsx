import { generateOGImage } from "fumadocs-ui/og";
import { cardFont, notInCardFont } from "@/lib/card-font";
import { ogImagePath } from "@/lib/llms";
import { siteConfig } from "@/lib/site";
import { source } from "@/lib/source";

export const dynamic = "force-static";
export const dynamicParams = false;

/** `/og/<page>/image.png`: a page's social card, 1200×630, written at build time. The home page's is `/og/image.png`. */
export function generateStaticParams() {
  return source.getPages().map((page) => ({ slug: ogImagePath(page.slugs).split("/").slice(2) }));
}

/**
 * The card's description: the page's, cut after the last whole word within 150 characters and marked with an ellipsis
 * when it is longer, so the template draws it in at most four lines, above its footer.
 */
function cardDescription(text: string | undefined): string | undefined {
  if (text === undefined || text.length <= 150) return text;
  const head = text.slice(0, 149);
  return `${head.slice(0, head.lastIndexOf(" ")).replace(/[,;:]$/, "")}…`;
}

export async function GET(_request: Request, context: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await context.params;
  const page = source.getPage(slug.slice(0, -1));
  if (!page) return new Response("not found", { status: 404 });
  const description = cardDescription(page.data.description);
  // The card is drawn in its one font, and only when the font draws every character of its text (src/lib/card-font.ts).
  const missing = notInCardFont([page.data.title, description ?? "", siteConfig.name].join("\n"));
  if (missing.length > 0) {
    const named = missing.join(", ");
    throw new Error(`the social card of ${page.url} has characters its font, Geist, does not draw: ${named}`);
  }
  return generateOGImage({
    title: page.data.title,
    description,
    site: siteConfig.name,
    fonts: [cardFont()],
    // The site's icon (src/app/icon.svg), drawn inline: the card is rendered at build time with no network.
    icon: (
      <svg viewBox="0 0 48 48" width="48" height="48" aria-hidden="true">
        <rect x="3" y="3" width="42" height="42" rx="9" fill="#2563d9" />
        <path
          d="M 3 24 h 10.5 v -5.5 h 10.5 v 11 h 10.5 v -5.5 H 45"
          fill="none"
          stroke="#ffffff"
          strokeWidth="4.5"
          strokeLinejoin="round"
        />
      </svg>
    ),
    primaryColor: "hsla(220, 70%, 46%, 0.3)",
    primaryTextColor: "hsl(220, 70%, 66%)",
  });
}
