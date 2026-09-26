import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import type { ReactNode } from "react";
import { JsonLd } from "@/components/JsonLd";
import { organizationJsonLd, siteConfig, softwareJsonLd, webSiteJsonLd } from "@/lib/site";
import { packageVersion } from "@/lib/version";
import "./global.css";

// next/font downloads the fonts at build time and serves them from this origin.
const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const jetbrainsMono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains-mono", display: "swap" });

export const metadata: Metadata = {
  metadataBase: new URL(siteConfig.url),
  title: { template: siteConfig.titleTemplate, default: siteConfig.title },
  description: siteConfig.description,
  applicationName: siteConfig.name,
  keywords: [...siteConfig.keywords],
  authors: [{ name: siteConfig.publisher.name, url: siteConfig.publisher.url }],
  publisher: siteConfig.publisher.name,
  robots: { index: true, follow: true },
  openGraph: {
    type: "website",
    siteName: siteConfig.name,
    title: siteConfig.title,
    description: siteConfig.description,
    url: siteConfig.url,
    locale: siteConfig.locale,
  },
  twitter: { card: "summary", title: siteConfig.title, description: siteConfig.description },
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
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <body>
        <a
          href="#main"
          className="sr-only z-50 rounded-md bg-fd-primary px-4 py-2 text-fd-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
        >
          Skip to content
        </a>
        <JsonLd data={[organizationJsonLd(), webSiteJsonLd(), ...softwareJsonLd(packageVersion)]} />
        <RootProvider search={{ enabled: true, options: { type: "static", api: "/api/search" } }}>{children}</RootProvider>
      </body>
    </html>
  );
}
