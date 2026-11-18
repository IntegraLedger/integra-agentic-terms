import type { MetadataRoute } from "next";
import { siteConfig } from "@/lib/site";

export const dynamic = "force-static";

/**
 * Every crawler may read every page; the sitemap is named. The Content-Signal line (https://contentsignals.org) states
 * that the content may be used for search, as input to an AI answer, and to train AI models, so that agents learn how to
 * pay through the gate.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/", other: { "Content-Signal": "search=yes, ai-input=yes, ai-train=yes" } }],
    sitemap: `${siteConfig.url}/sitemap.xml`,
  };
}
