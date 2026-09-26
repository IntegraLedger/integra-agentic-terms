/**
 * The site's identity, canonical origin and metadata. Every absolute URL, canonical tag, sitemap entry and JSON-LD block
 * is built from here. Client components import it too, so it touches no Node API.
 */
export const siteConfig = {
  /** The canonical origin: no trailing slash. */
  url: "https://agenticterms.integraledger.com",
  name: "Integra Agentic Terms",
  title: "Integra Agentic Terms: the buyer gate for agents that pay",
  titleTemplate: "%s | Integra Agentic Terms",
  description:
    "Before an agent's wallet signs, the buyer gate confirms that the record a seller serves hashes to the value the payment will carry. TypeScript, Python and MCP.",
  keywords: [
    "Legal Context Protocol",
    "LCP",
    "Agentic Transaction Record",
    "ATR",
    "buyer gate",
    "agentic commerce",
    "AI agent payments",
    "x402",
    "MPP",
    "Model Context Protocol",
  ],
  github: { owner: "IntegraLedger", repo: "integra-agentic-terms" },
  githubUrl: "https://github.com/IntegraLedger/integra-agentic-terms",
  packages: [
    { name: "@integraledger/terms", url: "https://www.npmjs.com/package/@integraledger/terms", language: "TypeScript" },
    { name: "@integraledger/terms-mcp", url: "https://www.npmjs.com/package/@integraledger/terms-mcp", language: "TypeScript" },
    { name: "integraledger-terms", url: "https://pypi.org/project/integraledger-terms/", language: "Python" },
  ],
  locale: "en_US",
  publisher: { name: "Integra Ledger", url: "https://www.integraledger.com" },
} as const;

/** An absolute URL on the canonical origin, from a root-relative path. */
export function absoluteUrl(path: string): string {
  return new URL(path, siteConfig.url).toString();
}

/** A file of the repository on `main`, as a GitHub URL. */
export function repoFile(path: string): string {
  return `${siteConfig.githubUrl}/blob/main/${path}`;
}

/** The repository path of a page, from its path in its collection. API pages are generated and have none. */
export function docSourcePath(collection: "docs" | "api", contentPath: string): string | undefined {
  return collection === "docs" ? `docs/${contentPath}` : undefined;
}

export function organizationJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "Organization",
    "@id": `${siteConfig.url}/#organization`,
    name: siteConfig.publisher.name,
    url: siteConfig.publisher.url,
    logo: absoluteUrl("/icon.svg"),
    sameAs: [siteConfig.githubUrl],
  };
}

export function webSiteJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "@id": `${siteConfig.url}/#website`,
    name: siteConfig.name,
    url: siteConfig.url,
    description: siteConfig.description,
    inLanguage: "en",
    publisher: { "@id": `${siteConfig.url}/#organization` },
    license: "https://www.apache.org/licenses/LICENSE-2.0",
  };
}

/** One SoftwareSourceCode block per published package. */
export function softwareJsonLd(version: string) {
  return siteConfig.packages.map((pkg) => ({
    "@context": "https://schema.org",
    "@type": "SoftwareSourceCode",
    "@id": `${siteConfig.url}/#${pkg.name}`,
    name: pkg.name,
    version,
    codeRepository: siteConfig.githubUrl,
    programmingLanguage: pkg.language,
    license: "https://www.apache.org/licenses/LICENSE-2.0",
    isPartOf: { "@id": `${siteConfig.url}/#website` },
    publisher: { "@id": `${siteConfig.url}/#organization` },
  }));
}

export function breadcrumbJsonLd(crumbs: Array<{ name: string; path: string }>) {
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
