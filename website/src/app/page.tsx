import { ServerCodeBlock } from "fumadocs-ui/components/codeblock.rsc";
import type { Metadata } from "next";
import Link from "next/link";
import { Footer } from "@/components/Footer";
import { JsonLd } from "@/components/JsonLd";
import { LandingNav } from "@/components/LandingNav";
import { MarkIcon } from "@/components/MarkIcon";
import { absoluteUrl, siteConfig } from "@/lib/site";

export const metadata: Metadata = {
  // Homepage owns the brand-default title; no template suffix.
  title: { absolute: siteConfig.title },
  description: siteConfig.description,
  alternates: { canonical: "/" },
};

const techArticleJsonLd = {
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "@id": `${siteConfig.url}/#techarticle`,
  headline: siteConfig.title,
  name: siteConfig.name,
  description: siteConfig.description,
  url: siteConfig.url,
  image: absoluteUrl(siteConfig.ogImage),
  inLanguage: "en",
  isPartOf: { "@id": `${siteConfig.url}/#website` },
  publisher: { "@id": `${siteConfig.url}/#organization` },
  keywords: siteConfig.keywords.join(", "),
  license: "https://www.apache.org/licenses/LICENSE-2.0",
};

const EXAMPLE = `import {
  makeCachingFetcher,
  nodeDnsLookup,
  parseProposalFromChallenge,
  transact,
} from "@integraledger/agentic-terms";

const now = () => new Date().toISOString();
const fetcher = makeCachingFetcher({ httpFetch: fetch, now, lookup: nodeDnsLookup });

// \`challenge\` is the 402 body the seller returned.
const proposal = parseProposalFromChallenge(challenge, {
  level: 3,
  sellerAssurance: "domain-controlled",
});

const result = await transact(proposal, policy, { fetcher, now }, signer);
// result.kind === "signed" only on Proceed.
// On Decline or Escalate the signer is never called.`;

const INSTALL = `npm install ${siteConfig.packages.terms.name}`;

const MCP_CONFIG = JSON.stringify(
  {
    mcpServers: {
      lcp: { command: "npx", args: ["-y", siteConfig.packages.mcp.name] },
    },
  },
  null,
  2,
);

export default function HomePage() {
  return (
    <div className="min-h-screen bg-fd-background text-fd-foreground">
      <JsonLd data={techArticleJsonLd} />
      <LandingNav />
      <main id="main">
        {/* Hero */}
        <section className="px-6 py-20 text-center md:py-28">
          <div className="mx-auto max-w-4xl">
            <div className="mb-8 flex justify-center">
              <MarkIcon size={112} className="text-fd-primary" />
            </div>
            <h1 className="mb-6 text-5xl font-extrabold leading-tight tracking-tight md:text-6xl">
              Verify before sign.
            </h1>
            <p className="mb-5 text-2xl text-fd-primary md:text-3xl">
              As a type, and as a runtime guarantee.
            </p>
            <p className="mx-auto mb-10 max-w-2xl text-lg leading-relaxed text-fd-muted-foreground [text-wrap:balance]">
              None of the agentic commerce protocols carries a fingerprint of
              the terms it is settling. The{" "}
              <a
                href={siteConfig.standard.url}
                className="text-fd-primary hover:underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                Legal Context Protocol
              </a>{" "}
              (LCP) defines one. Agentic Terms is the buyer-side check: it
              fetches the terms the seller advertised, recomputes that
              fingerprint over the bytes actually served, and refuses to reach
              your signing key if the two disagree.
            </p>
            <div className="mx-auto mb-8 max-w-xl text-left">
              <ServerCodeBlock lang="bash" code={INSTALL} />
            </div>
            <div className="mb-6 flex flex-wrap items-center justify-center gap-4">
              <Link
                href="/quickstart"
                className="inline-flex items-center rounded-lg bg-fd-primary px-7 py-3.5 text-base font-semibold text-fd-primary-foreground transition-colors hover:bg-fd-primary/90"
              >
                Quickstart
              </Link>
              <Link
                href="/verify-before-sign"
                className="inline-flex items-center rounded-lg border border-fd-muted-foreground px-7 py-3.5 text-base font-semibold transition-colors hover:bg-fd-accent"
              >
                How it works
              </Link>
              <a
                href={siteConfig.githubUrl}
                className="inline-flex items-center rounded-lg border border-fd-muted-foreground px-7 py-3.5 text-base font-semibold transition-colors hover:bg-fd-accent"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub
              </a>
            </div>
            <div className="inline-block rounded-full border border-fd-border px-4 py-1.5 text-sm font-medium text-fd-muted-foreground">
              Apache-2.0 &middot; free forever &middot; no account, no key, no
              token
            </div>
          </div>
        </section>

        {/* The failure it prevents */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-5xl">
            <h2 className="mb-4 text-center text-3xl font-bold">
              The failure is not the one people expect
            </h2>
            <p className="mx-auto mb-10 max-w-2xl text-center text-lg text-fd-muted-foreground [text-wrap:balance]">
              Told that a fingerprint disagrees, agents already halt — reliably
              and unprompted. That is not the gap. The gap is that nothing tells
              them: a seller who advertised{" "}
              <strong className="text-fd-foreground">no</strong> fingerprint
              reads as nothing to check.
            </p>
            <div className="grid gap-6 md:grid-cols-3">
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  Reading is not verifying
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  Fetching a terms document tells you what was served to you.
                  Only a fingerprint the <em>seller</em> advertised binds the
                  seller to it.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  Your own hash proves nothing
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  Hashing the bytes you were handed records what you saw. It is
                  not a commitment, because the seller never made one — in a
                  dispute it proves only that you hashed something.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  Gaps resolve by policy
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  Paying at Level 1 can be correct. What must not happen is
                  paying while believing the terms were verified — so a gap is
                  your stated disposition, never a silent default.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* The code */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-5xl">
            <h2 className="mb-4 text-center text-3xl font-bold">
              The whole integration
            </h2>
            <p className="mx-auto mb-10 max-w-2xl text-center text-lg text-fd-muted-foreground [text-wrap:balance]">
              Parse the challenge into a typed proposal, hand it to{" "}
              <code className="text-base">transact</code> with your policy and
              your signer. The key is reachable on one path only.
            </p>
            <div className="mx-auto max-w-3xl text-left">
              <ServerCodeBlock
                lang="ts"
                code={EXAMPLE}
                codeblock={{ title: "gate.ts" }}
              />
            </div>
            <div className="mt-8 text-center">
              <Link
                href="/quickstart"
                className="text-base font-medium text-fd-primary hover:underline"
              >
                Read the quickstart &rarr;
              </Link>
            </div>
          </div>
        </section>

        {/* What halts */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-5xl">
            <h2 className="mb-4 text-center text-3xl font-bold">
              Three outcomes, and only one reaches the key
            </h2>
            <p className="mb-10 text-center text-lg text-fd-muted-foreground [text-wrap:balance]">
              A step&rsquo;s four-valued status maps <em>totally</em> onto a
              disposition. A failure always declines; gaps are resolved by the
              buyer&rsquo;s stated policy.
            </p>
            <div className="grid gap-6 md:grid-cols-3">
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent-mint">
                  Proceed
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  The terms served hash to the fingerprint the seller
                  advertised, and the typed record satisfies your policy. The
                  signer is called exactly once.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-fd-muted-foreground">
                  Decline
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  A fingerprint mismatch, an unfetchable document, a level below
                  your floor, a forbidden clause, an offer over your cap.
                  Carries a halt class, a code, and a detail you can report to
                  the seller.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-fd-muted-foreground">
                  Escalate
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  Hands back the exact bytes and their hash, so what a human
                  approves is what a key would sign. Reached only when your
                  policy elects it.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Protocol coverage */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-5xl">
            <h2 className="mb-4 text-center text-3xl font-bold">
              Works on the protocol you are already on
            </h2>
            <p className="mb-10 text-center text-lg text-fd-muted-foreground [text-wrap:balance]">
              Reading the advertised reference is universal. Parsing a full
              proposal is not — and the difference is a fact about the
              protocols, not a gap in the library.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-base">
                <thead>
                  <tr className="border-b border-fd-border text-fd-muted-foreground">
                    <th className="px-4 py-3 font-medium">Capability</th>
                    <th className="px-4 py-3 font-medium">Reach</th>
                    <th className="px-4 py-3 font-medium">Why</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-fd-border">
                    <td className="px-4 py-3 font-medium text-accent-blue">
                      <code className="text-sm">readAdvertisedTerms</code>
                    </td>
                    <td className="px-4 py-3">All nine registered protocols</td>
                    <td className="px-4 py-3 text-fd-muted-foreground">
                      The reference is read out of each protocol&rsquo;s own
                      placement manifest — every carrier it declares, not the
                      first that answers.
                    </td>
                  </tr>
                  <tr className="border-b border-fd-border">
                    <td className="px-4 py-3 font-medium text-accent-blue">
                      <code className="text-sm">parseProposalUniversal</code>
                    </td>
                    <td className="px-4 py-3">x402, ACP</td>
                    <td className="px-4 py-3 text-fd-muted-foreground">
                      A proposal also carries an offer, and an amount with its
                      unit is protocol-native economics no manifest declares.
                    </td>
                  </tr>
                  <tr className="border-b border-fd-border">
                    <td className="px-4 py-3 font-medium text-accent-blue">
                      Parsers reached by name
                    </td>
                    <td className="px-4 py-3">AP2, MPP</td>
                    <td className="px-4 py-3 text-fd-muted-foreground">
                      Every AP2 envelope is also an A2A message, and an MPP
                      request body carries nothing that names MPP. Ambiguity
                      refuses rather than guesses.
                    </td>
                  </tr>
                  <tr className="border-b border-fd-border">
                    <td className="px-4 py-3 font-medium text-accent-blue">
                      <code className="text-sm">detectProtocol</code>
                    </td>
                    <td className="px-4 py-3">Never a guess</td>
                    <td className="px-4 py-3 text-fd-muted-foreground">
                      Collects every discriminant that fires, not the first. A
                      document that is legitimately two protocols&rsquo; comes
                      back named twice.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="mt-8 text-center">
              <Link
                href="/protocols"
                className="text-base font-medium text-fd-primary hover:underline"
              >
                Protocol coverage in detail &rarr;
              </Link>
            </div>
          </div>
        </section>

        {/* MCP */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-5xl">
            <h2 className="mb-4 text-center text-3xl font-bold">
              Or hand the checks to your agent host
            </h2>
            <p className="mx-auto mb-10 max-w-2xl text-center text-lg text-fd-muted-foreground [text-wrap:balance]">
              <code className="text-base">{siteConfig.packages.mcp.name}</code>{" "}
              is a read-only Model Context Protocol server. Every tool reads;
              nothing publishes, transmits, or holds a credential.
            </p>
            <div className="mx-auto mb-8 max-w-2xl text-left">
              <ServerCodeBlock
                lang="json"
                code={MCP_CONFIG}
                codeblock={{ title: ".mcp.json" }}
              />
            </div>
            <div className="mt-8 text-center">
              <Link
                href="/mcp"
                className="text-base font-medium text-fd-primary hover:underline"
              >
                The six tools &rarr;
              </Link>
            </div>
          </div>
        </section>

        {/* Properties */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-5xl">
            <h2 className="mb-10 text-center text-3xl font-bold">
              Properties worth relying on
            </h2>
            <div className="grid gap-6 md:grid-cols-2">
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  The prompt-injection boundary is architectural
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  The typed proposal <em>cannot</em> carry natural-language
                  prose, so the terms body can never reach policy evaluation.
                  That is a property of the type, not a matter of discipline.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  The fetcher is the SSRF guard
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  HTTPS-only, refuses redirects, re-checks every resolved
                  address is public unicast on every network fetch, and caps the
                  body while streaming. The URL came off the seller&rsquo;s
                  challenge.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  Runs wherever your agent runs
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  Node, Bun and Deno are measured on every release — against the
                  packed tarball, installed the way you would install it. The
                  package&rsquo;s own source imports no Node built-in.
                </p>
              </div>
              <div className="rounded-lg border border-fd-border p-6">
                <h3 className="mb-2 text-xl font-bold text-accent-blue">
                  Nothing calls home
                </h3>
                <p className="text-base text-fd-muted-foreground">
                  No telemetry, no callback, no registry check — no network
                  request other than fetching the terms the seller pointed you
                  at.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Get started */}
        <section className="border-t border-fd-border px-6 py-16">
          <div className="mx-auto max-w-3xl text-center">
            <h2 className="mb-4 text-3xl font-bold">Start here</h2>
            <p className="mb-10 text-lg text-fd-muted-foreground [text-wrap:balance]">
              Both packages implement the buyer side of the{" "}
              <a
                href={siteConfig.standard.specUrl}
                className="text-fd-primary hover:underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                Legal Context Protocol
              </a>
              , co-stewarded by Integra Ledger and AAA-ICDR. The seller-side
              application is separately licensed and is not part of this
              repository.
            </p>
            <p className="mb-8 text-base text-fd-muted-foreground">
              On npm:{" "}
              <a
                href={siteConfig.packages.terms.npm}
                className="text-fd-primary hover:underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                {siteConfig.packages.terms.name}
              </a>{" "}
              &middot;{" "}
              <a
                href={siteConfig.packages.mcp.npm}
                className="text-fd-primary hover:underline"
                target="_blank"
                rel="noopener noreferrer"
              >
                {siteConfig.packages.mcp.name}
              </a>
            </p>
            <div className="grid gap-6 text-left md:grid-cols-2">
              <Link
                href="/quickstart"
                className="rounded-lg border border-fd-border p-6 transition-colors hover:bg-fd-accent"
              >
                <h3 className="mb-2 text-lg font-bold">Gate a transaction</h3>
                <p className="text-base text-fd-muted-foreground">
                  Install, wire the ports, state a policy, and halt on a
                  fingerprint that disagrees.
                </p>
              </Link>
              <Link
                href="/mcp"
                className="rounded-lg border border-fd-border p-6 transition-colors hover:bg-fd-accent"
              >
                <h3 className="mb-2 text-lg font-bold">Wire the MCP server</h3>
                <p className="text-base text-fd-muted-foreground">
                  Give an agent host verify-before-pay, atrHash computation, and
                  reference placement — read-only.
                </p>
              </Link>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
