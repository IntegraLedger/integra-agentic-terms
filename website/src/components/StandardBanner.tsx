import { siteConfig } from "@/lib/site";

/**
 * What LCP is, on every documentation page.
 *
 * These docs use "LCP" constantly — section references, trust levels, the `atrHash` the guard is built
 * around — and a reader who arrives on a deep page from a search has no reason to know the acronym.
 * Expanding it once in the introduction is not enough when most entrances are not the introduction.
 */
export function StandardBanner() {
  return (
    <div className="rounded-lg border border-fd-border bg-fd-card p-3 text-sm">
      <p className="mb-1 font-medium text-fd-foreground">
        Built on {siteConfig.standard.name}
      </p>
      <p className="text-fd-muted-foreground">
        <strong>{siteConfig.standard.short}</strong> is the open standard for
        legal context in agentic commerce, co-stewarded by Integra Ledger and
        AAA-ICDR.{" "}
        <a
          href={siteConfig.standard.url}
          className="text-fd-primary hover:underline"
          target="_blank"
          rel="noopener noreferrer"
        >
          Read the standard &rarr;
        </a>
      </p>
    </div>
  );
}
