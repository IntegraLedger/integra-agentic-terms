import { DocsLayout } from "fumadocs-ui/layouts/docs";
import type { ReactNode } from "react";
import { Footer } from "@/components/Footer";
import { MarkIcon } from "@/components/MarkIcon";
import { StandardBanner } from "@/components/StandardBanner";
import { siteConfig } from "@/lib/site";
import { source } from "@/lib/source";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <DocsLayout
        tree={source.pageTree}
        nav={{
          title: (
            <span className="flex items-center gap-2">
              <MarkIcon size={24} className="text-fd-primary" />
              Integra Agentic Terms
            </span>
          ),
        }}
        githubUrl={siteConfig.githubUrl}
        links={[
          {
            text: siteConfig.standard.name,
            url: siteConfig.standard.url,
            external: true,
          },
        ]}
        sidebar={{ defaultOpenLevel: 1, banner: <StandardBanner /> }}
      >
        {children}
      </DocsLayout>
      <Footer />
    </>
  );
}
