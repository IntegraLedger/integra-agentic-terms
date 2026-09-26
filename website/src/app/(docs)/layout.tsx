import { DocsLayout } from "fumadocs-ui/layouts/docs";
import type { ReactNode } from "react";
import { Footer } from "@/components/Footer";
import { siteConfig } from "@/lib/site";
import { source } from "@/lib/source";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <DocsLayout tree={source.pageTree} nav={{ title: siteConfig.name }} githubUrl={siteConfig.githubUrl} sidebar={{ defaultOpenLevel: 1 }}>
        {children}
      </DocsLayout>
      <Footer />
    </>
  );
}
