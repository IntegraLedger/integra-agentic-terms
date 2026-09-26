import type { MetadataRoute } from "next";
import { absoluteUrl } from "@/lib/site";
import { source } from "@/lib/source";

export const dynamic = "force-static";

/** Every page, dated by the commit that last changed its source where Git knows it. */
export default function sitemap(): MetadataRoute.Sitemap {
  return source.getPages().map((page) => {
    const lastModified = "lastModified" in page.data ? page.data.lastModified : undefined;
    return {
      url: absoluteUrl(page.url),
      ...(lastModified instanceof Date ? { lastModified } : {}),
      priority: page.url === "/" ? 1 : 0.7,
    };
  });
}
