import { MarkdownCopyButton, ViewOptionsPopover } from "fumadocs-ui/layouts/docs/page";
import defaultMdxComponents from "fumadocs-ui/mdx";
import { DocsBody, DocsDescription, DocsPage, DocsTitle } from "fumadocs-ui/page";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { JsonLd } from "@/components/JsonLd";
import { Mermaid } from "@/components/Mermaid";
import { Table } from "@/components/Table";
import { TwoslashPopups } from "@/components/TwoslashPopups";
import { markdownPath, markdownUrl, ogImagePath } from "@/lib/llms";
import { absoluteUrl, breadcrumbJsonLd, docSourcePath, repoFile, siteConfig } from "@/lib/site";
import { source } from "@/lib/source";
import { popupsPath, twoslashPopups } from "@/lib/twoslash";

interface PageProps {
  params: Promise<{ slug?: string[] }>;
}

/** Home, each ancestor, then the current entry, each with its own title. */
function crumbs(slug: string[], title: string) {
  const out = [{ name: "Home", path: "/" }];
  slug.forEach((segment, i) => {
    const sub = slug.slice(0, i + 1);
    const page = source.getPage(sub);
    out.push({ name: i === slug.length - 1 ? title : (page?.data.title ?? segment), path: `/${sub.join("/")}` });
  });
  return out;
}

export default async function Page(props: PageProps) {
  const { slug = [] } = await props.params;
  const page = source.getPage(slug);
  if (!page) notFound();
  const MDX = page.data.body;
  const sourcePath = docSourcePath(page.data.type, page.data.info.path);
  const copyPath = markdownPath(page.url);
  const lastModified = "lastModified" in page.data ? page.data.lastModified : undefined;

  return (
    <DocsPage
      id="main"
      tabIndex={-1}
      toc={page.data.toc}
      full={page.data.full}
      {...(lastModified instanceof Date ? { lastUpdate: lastModified } : {})}
      {...(sourcePath === undefined
        ? {}
        : { editOnGithub: { owner: siteConfig.github.owner, repo: siteConfig.github.repo, sha: "main", path: sourcePath } })}
    >
      <JsonLd
        data={[
          {
            "@context": "https://schema.org",
            "@type": "TechArticle",
            headline: page.data.title,
            description: page.data.description,
            url: absoluteUrl(page.url),
            inLanguage: "en",
            isPartOf: { "@id": `${siteConfig.url}/#website` },
            publisher: { "@id": `${siteConfig.url}/#organization` },
            license: "https://www.apache.org/licenses/LICENSE-2.0",
          },
          breadcrumbJsonLd(crumbs(slug, page.data.title)),
        ]}
      />
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription>{page.data.description}</DocsDescription>
      <div className="flex flex-row items-center gap-2 border-b pb-6">
        <MarkdownCopyButton markdownUrl={copyPath} />
        <ViewOptionsPopover
          markdownUrl={absoluteUrl(copyPath)}
          {...(sourcePath === undefined ? {} : { githubUrl: repoFile(sourcePath) })}
        />
      </div>
      <DocsBody>
        <MDX components={{ ...defaultMdxComponents, Mermaid, table: Table }} />
      </DocsBody>
      {twoslashPopups(page).length > 0 ? <TwoslashPopups src={popupsPath(page.url)} /> : null}
    </DocsPage>
  );
}

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: PageProps): Promise<Metadata> {
  const { slug = [] } = await props.params;
  const page = source.getPage(slug);
  if (!page) return {};
  const title = slug.length === 0 ? siteConfig.title : page.data.title;
  const description = page.data.description ?? siteConfig.description;
  const image = { url: ogImagePath(page.slugs), width: 1200, height: 630, alt: title };
  return {
    title: slug.length === 0 ? { absolute: siteConfig.title } : page.data.title,
    description,
    alternates: { canonical: page.url, types: { "text/markdown": markdownUrl(page.url) } },
    openGraph: {
      type: "article",
      url: absoluteUrl(page.url),
      title,
      description,
      siteName: siteConfig.name,
      locale: siteConfig.locale,
      images: [image],
    },
    twitter: { card: "summary_large_image", title, description, images: [image] },
  };
}
