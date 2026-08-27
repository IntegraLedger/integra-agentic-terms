/**
 * Single source of truth for site-wide identity, canonical URL, and SEO/LLM
 * metadata. Every absolute URL, canonical tag, sitemap entry, robots directive,
 * and JSON-LD block derives from here — never hardcode the domain elsewhere.
 *
 * Imported by client components too, so nothing here may touch Node APIs; the
 * package version, which needs the filesystem, lives in `version.ts`.
 */

export const siteConfig = {
  /** Canonical production origin. Apex-subdomain, no `www`, no trailing slash. */
  url: "https://agenticterms.integraledger.com",
  name: "Integra Agentic Terms",
  shortName: "Agentic Terms",
  /** ~60 chars: brand front-loaded, no word repetition, keyword-rich. */
  title: "Integra Agentic Terms — Verify Before Sign for Paying Agents",
  titleTemplate: "%s | Integra Agentic Terms",
  /** ≤155 chars so search results show the whole claim; leads with the value proposition. */
  description:
    "Open-source buyer-side guard for agentic commerce: recomputes the seller's advertised LCP fingerprint over the terms as served and halts before your key.",
  keywords: [
    "Integra Agentic Terms",
    "agentic-terms",
    "verify before sign",
    "verify before pay",
    "agentic commerce",
    "AI agent payments",
    "x402",
    "ACP",
    "AP2",
    "MPP",
    "Model Context Protocol",
    "MCP server",
    "Legal Context Protocol",
    "atrHash",
    "buyer policy",
    "prompt injection boundary",
  ],
  github: {
    owner: "IntegraLedger",
    repo: "integra-agentic-terms",
  },
  githubUrl: "https://github.com/IntegraLedger/integra-agentic-terms",
  /** The two published package names, in the order the docs introduce them. */
  packages: {
    guard: {
      name: "@integraledger/agentic-terms",
      npm: "https://www.npmjs.com/package/@integraledger/agentic-terms",
    },
    mcp: {
      name: "@integraledger/lcp-mcp-server",
      npm: "https://www.npmjs.com/package/@integraledger/lcp-mcp-server",
    },
  },
  /**
   * The standard these packages implement the buyer side of.
   *
   * `LCP` is an acronym almost no reader arrives knowing, and this site leans on it constantly — for
   * section references, trust levels, and the `atrHash` the whole guard is built around. So the expansion
   * and the link live here and are rendered in the persistent chrome (sidebar banner, nav, footer) rather
   * than being spelled out once in prose and assumed thereafter.
   */
  standard: {
    name: "Legal Context Protocol",
    short: "LCP",
    url: "https://legalcontextprotocol.org",
    specUrl: "https://legalcontextprotocol.org/standard",
  },
  // Next's app/opengraph-image.tsx file convention emits this extensionless
  // route (referenced from JSON-LD and from every docs page's own metadata).
  ogImage: "/opengraph-image",
  ogImageAlt: "Integra Agentic Terms — verify before sign for paying agents",
  locale: "en_US",
  publisher: {
    name: "Integra Ledger",
    url: "https://www.integraledger.com",
  },
} as const;

/** Build an absolute URL on the canonical origin from a root-relative path. */
export function absoluteUrl(path: string): string {
  return new URL(path, siteConfig.url).toString();
}

/** A file in the repository, on `main`, as a browsable GitHub URL. */
export function repoFile(path: string): string {
  return `${siteConfig.githubUrl}/blob/main/${path}`;
}

/** Repository path of a documentation page, given its path within the content directory. */
export function docSourcePath(contentPath: string): string {
  return `website/content/docs/${contentPath}`;
}

/** Organization JSON-LD — resolves "who publishes Agentic Terms". */
export function organizationJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "Organization",
    "@id": `${siteConfig.url}/#organization`,
    name: siteConfig.publisher.name,
    url: siteConfig.publisher.url,
    logo: absoluteUrl("/icon.svg"),
    description:
      "Integra Ledger builds the record infrastructure for agentic commerce and co-stewards the Legal Context Protocol.",
    sameAs: [siteConfig.githubUrl],
  };
}

/** WebSite JSON-LD — establishes the canonical site entity. */
export function webSiteJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "@id": `${siteConfig.url}/#website`,
    name: siteConfig.name,
    alternateName: siteConfig.shortName,
    url: siteConfig.url,
    description: siteConfig.description,
    inLanguage: "en",
    publisher: { "@id": `${siteConfig.url}/#organization` },
    license: "https://www.apache.org/licenses/LICENSE-2.0",
  };
}

/**
 * SoftwareSourceCode JSON-LD for the two published packages. Emitted site-wide
 * because "what do I install" is the question this site exists to answer.
 */
export function softwareJsonLd(version: string) {
  return [siteConfig.packages.guard, siteConfig.packages.mcp].map((pkg) => ({
    "@context": "https://schema.org",
    "@type": "SoftwareSourceCode",
    "@id": `${siteConfig.url}/#${pkg.name}`,
    name: pkg.name,
    version,
    codeRepository: siteConfig.githubUrl,
    programmingLanguage: "TypeScript",
    runtimePlatform: "Node.js",
    license: "https://www.apache.org/licenses/LICENSE-2.0",
    isPartOf: { "@id": `${siteConfig.url}/#website` },
    publisher: { "@id": `${siteConfig.url}/#organization` },
  }));
}

/** BreadcrumbList JSON-LD for a docs page given its labeled path segments. */
export function breadcrumbJsonLd(
  crumbs: Array<{ name: string; path: string }>,
) {
  return {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: crumbs.map((c, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: c.name,
      item: absoluteUrl(c.path),
    })),
  };
}
