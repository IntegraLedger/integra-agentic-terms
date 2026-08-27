import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import type { ReactNode } from "react";
import { JsonLd } from "@/components/JsonLd";
import {
  organizationJsonLd,
  siteConfig,
  softwareJsonLd,
  webSiteJsonLd,
} from "@/lib/site";
import { packageVersion } from "@/lib/version";
import "./global.css";

// Self-hosted at build time: the font files ship from this origin with the rest of the
// static export, so a page view makes no request to a third party. `display: swap` keeps
// text visible while they load.
const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL(siteConfig.url),
  title: {
    template: siteConfig.titleTemplate,
    default: siteConfig.title,
  },
  description: siteConfig.description,
  applicationName: siteConfig.name,
  keywords: [...siteConfig.keywords],
  authors: [{ name: siteConfig.publisher.name, url: siteConfig.publisher.url }],
  creator: siteConfig.publisher.name,
  publisher: siteConfig.publisher.name,
  // No layout-level canonical: each page sets its own (homepage -> "/", docs ->
  // page.url). A default here would silently mis-canonicalize any page that
  // forgot to set one, pointing it at the homepage.
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
  openGraph: {
    type: "website",
    siteName: siteConfig.name,
    title: siteConfig.title,
    description: siteConfig.description,
    url: siteConfig.url,
    locale: siteConfig.locale,
    // og:image is injected by the app/opengraph-image.tsx file convention —
    // single source, no duplicate tags.
  },
  twitter: {
    card: "summary_large_image",
    title: siteConfig.title,
    description: siteConfig.description,
  },
  // Favicon and apple-touch icon come from the app/icon.svg and app/apple-icon.tsx file
  // conventions; the manifest from app/manifest.ts. Nothing here to keep in sync.
  category: "technology",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0b1220" },
  ],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body>
        <a
          href="#main"
          className="sr-only z-50 rounded-md bg-fd-primary px-4 py-2 text-fd-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
        >
          Skip to content
        </a>
        <JsonLd
          data={[
            organizationJsonLd(),
            webSiteJsonLd(),
            ...softwareJsonLd(packageVersion),
          ]}
        />
        <RootProvider
          search={{
            enabled: true,
            options: { type: "static", api: "/api/search" },
          }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
