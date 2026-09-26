import { repoFile, siteConfig } from "@/lib/site";
import { packageVersion } from "@/lib/version";

export function Footer() {
  return (
    <footer className="border-t border-fd-border px-6 py-8">
      <div className="mx-auto flex max-w-5xl flex-col items-center gap-4 text-sm text-fd-muted-foreground md:flex-row md:justify-between">
        <span>
          <span className="font-mono text-xs">v{packageVersion}</span> &middot; Apache-2.0
        </span>
        <nav aria-label="Footer" className="flex flex-wrap justify-center gap-4">
          <a href="/getting-started" className="hover:text-fd-foreground">
            Getting started
          </a>
          <a href="/reference/pairings" className="hover:text-fd-foreground">
            Pairings
          </a>
          <a href="/llms.txt" className="hover:text-fd-foreground">
            llms.txt
          </a>
          <a href={siteConfig.githubUrl} className="hover:text-fd-foreground" target="_blank" rel="noopener noreferrer">
            GitHub
          </a>
          <a href={repoFile("CONTRIBUTING.md")} className="hover:text-fd-foreground" target="_blank" rel="noopener noreferrer">
            Contributing
          </a>
          <a href={repoFile("SECURITY.md")} className="hover:text-fd-foreground" target="_blank" rel="noopener noreferrer">
            Security
          </a>
        </nav>
      </div>
    </footer>
  );
}
