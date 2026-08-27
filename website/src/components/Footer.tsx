import Link from "next/link";
import { repoFile, siteConfig } from "@/lib/site";
import { packageVersion } from "@/lib/version";

export function Footer() {
  return (
    <footer className="border-t border-fd-border px-6 py-8">
      <div className="mx-auto flex max-w-5xl flex-col items-center gap-4 text-sm text-fd-muted-foreground md:flex-row md:justify-between">
        <span className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
          <a
            href={repoFile("packages/agentic-terms/CHANGELOG.md")}
            className="rounded-full border border-fd-border px-2.5 py-0.5 font-mono text-xs hover:text-fd-foreground"
            target="_blank"
            rel="noopener noreferrer"
            title="Changelog"
          >
            v{packageVersion}
          </a>
          <span>
            Apache-2.0 &middot; free forever &middot; no account, no key, no
            telemetry
          </span>
        </span>
        <nav
          aria-label="Footer"
          className="flex flex-wrap justify-center gap-4"
        >
          <Link href="/quickstart" className="hover:text-fd-foreground">
            Quickstart
          </Link>
          <Link href="/protocols" className="hover:text-fd-foreground">
            Protocols
          </Link>
          <Link href="/mcp" className="hover:text-fd-foreground">
            MCP Server
          </Link>
          <Link href="/security" className="hover:text-fd-foreground">
            Security
          </Link>
          <a
            href={siteConfig.standard.url}
            className="hover:text-fd-foreground"
            target="_blank"
            rel="noopener noreferrer"
          >
            {siteConfig.standard.name}
          </a>
          <a
            href={siteConfig.githubUrl}
            className="hover:text-fd-foreground"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub
          </a>
          <a
            href={repoFile("CONTRIBUTING.md")}
            className="hover:text-fd-foreground"
            target="_blank"
            rel="noopener noreferrer"
          >
            Contributing
          </a>
          <a
            href={repoFile("SECURITY.md")}
            className="hover:text-fd-foreground"
            target="_blank"
            rel="noopener noreferrer"
          >
            Report a vulnerability
          </a>
        </nav>
      </div>
    </footer>
  );
}
