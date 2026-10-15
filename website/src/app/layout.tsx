import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { JsonLd } from "@/components/JsonLd";
import { organizationJsonLd, siteConfig, softwareJsonLd, webSiteJsonLd } from "@/lib/site";
import { packageVersion } from "@/lib/version";
import "./global.css";

export const metadata: Metadata = {
  metadataBase: new URL(siteConfig.url),
  title: { template: siteConfig.titleTemplate, default: siteConfig.title },
  description: siteConfig.description,
  applicationName: siteConfig.name,
  keywords: [...siteConfig.keywords],
  authors: [{ name: siteConfig.publisher.name, url: siteConfig.publisher.url }],
  publisher: siteConfig.publisher.name,
  robots: { index: true, follow: true },
  // The llms.txt index that describes each page (https://llmstxt.org), as <link rel="describedby">. Next.js writes
  // the metadata into the head in one order on every build. A link the layout renders itself is placed in the head in
  // the order its part of the page's server payload reaches the renderer, which on the not-found page puts it before
  // or after Next.js's robots meta element from one build to the next.
  icons: { other: [{ rel: "describedby", url: "/llms.txt", type: "text/plain" }] },
  openGraph: {
    type: "website",
    siteName: siteConfig.name,
    title: siteConfig.title,
    description: siteConfig.description,
    url: siteConfig.url,
    locale: siteConfig.locale,
  },
  twitter: { card: "summary_large_image", title: siteConfig.title, description: siteConfig.description },
  category: "technology",
};

/**
 * Text of the docs theme set here. The search dialog's close button shows "ESC", so its accessible name begins with
 * that label (WCAG 2.5.3).
 */
const translations = { "Close Search(search dialog)(aria-label)": "Esc: close search" };

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0b1220" },
  ],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <a
          href="#main"
          className="sr-only z-50 rounded-md bg-fd-primary px-4 py-2 text-fd-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
        >
          Skip to content
        </a>
        <JsonLd data={[organizationJsonLd(), webSiteJsonLd(), ...softwareJsonLd(packageVersion)]} />
        {/* The theme changes only through the layout's theme switch: no key pressed alone changes it (WCAG 2.1.4). */}
        <RootProvider
          search={{ enabled: true, options: { type: "static", api: "/api/search" } }}
          theme={{ hotKey: false }}
          i18n={{ translations }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
