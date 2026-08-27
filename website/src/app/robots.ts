import type { MetadataRoute } from "next";
import { siteConfig } from "@/lib/site";

// Required for metadata route handlers under `output: export`.
export const dynamic = "force-static";

/**
 * Generated robots. These packages exist to be found by agents and by the people
 * building them, so AI crawlers are named explicitly rather than left to the
 * wildcard. Sitemap and host come from siteConfig, so they cannot drift to a
 * stale origin.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      { userAgent: "*", allow: "/" },
      {
        userAgent: [
          "GPTBot",
          "ChatGPT-User",
          "OAI-SearchBot",
          "ClaudeBot",
          "Claude-Web",
          "anthropic-ai",
          "Claude-SearchBot",
          "Google-Extended",
          "PerplexityBot",
          "Perplexity-User",
          "CCBot",
          "Bytespider",
          "Amazonbot",
          "Applebot-Extended",
          "Meta-ExternalAgent",
          "cohere-ai",
          "DuckAssistBot",
        ],
        allow: "/",
      },
    ],
    sitemap: `${siteConfig.url}/sitemap.xml`,
    host: new URL(siteConfig.url).hostname,
  };
}
