import { Callout } from "fumadocs-ui/components/callout";
import { Step, Steps } from "fumadocs-ui/components/steps";
import { Tab, Tabs } from "fumadocs-ui/components/tabs";
import {
  MarkdownCopyButton,
  ViewOptionsPopover,
} from "fumadocs-ui/layouts/docs/page";
import defaultMdxComponents from "fumadocs-ui/mdx";
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
} from "fumadocs-ui/page";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { JsonLd } from "@/components/JsonLd";
import { markdownPath } from "@/lib/llms";
import {
  absoluteUrl,
  breadcrumbJsonLd,
  docSourcePath,
  repoFile,
  siteConfig,
} from "@/lib/site";
import { source } from "@/lib/source";

interface PageProps {
  params: Promise<{ slug: string[] }>;
}

/** Title-case a slug segment as a breadcrumb fallback label. */
function humanize(segment: string): string {
  return segment
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Home → …ancestors… → current, using real page titles where resolvable. */
function buildCrumbs(slug: string[], title: string) {
  const crumbs = [{ name: "Home", path: "/" }];
  slug.forEach((segment, i) => {
    const sub = slug.slice(0, i + 1);
    const isLast = i === slug.length - 1;
    const page = source.getPage(sub);
    crumbs.push({
      name: isLast ? title : (page?.data.title ?? humanize(segment)),
      path: `/${sub.join("/")}`,
    });
  });
  return crumbs;
}

export default async function Page(props: PageProps) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();
  const MDX = page.data.body;
  const lastModified = page.data.lastModified;
  const sourcePath = docSourcePath(page.data.info.path);
  const markdownUrl = markdownPath(page.url);

  const techArticle = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    headline: page.data.title,
    name: page.data.title,
    description: page.data.description,
    url: absoluteUrl(page.url),
    inLanguage: "en",
    isPartOf: { "@id": `${siteConfig.url}/#website` },
    publisher: { "@id": `${siteConfig.url}/#organization` },
    image: absoluteUrl(siteConfig.ogImage),
    license: "https://www.apache.org/licenses/LICENSE-2.0",
    ...(lastModified ? { dateModified: lastModified.toISOString() } : {}),
  };

  return (
    <DocsPage
      id="main"
      tabIndex={-1}
      toc={page.data.toc}
      full={page.data.full}
      lastUpdate={lastModified}
      editOnGithub={{
        owner: siteConfig.github.owner,
        repo: siteConfig.github.repo,
        sha: "main",
        path: sourcePath,
      }}
    >
      <JsonLd
        data={[
          techArticle,
          breadcrumbJsonLd(buildCrumbs(params.slug, page.data.title)),
        ]}
      />
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription>{page.data.description}</DocsDescription>
      <div className="flex flex-row items-center gap-2 border-b pb-6">
        <MarkdownCopyButton markdownUrl={markdownUrl} />
        <ViewOptionsPopover
          markdownUrl={absoluteUrl(markdownUrl)}
          githubUrl={repoFile(sourcePath)}
        />
      </div>
      <DocsBody>
        <MDX
          components={{
            ...defaultMdxComponents,
            Callout,
            Step,
            Steps,
            Tab,
            Tabs,
          }}
        />
      </DocsBody>
    </DocsPage>
  );
}

export async function generateStaticParams() {
  return source.generateParams().filter((param) => param.slug.length > 0);
}

export async function generateMetadata(props: PageProps): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) return {};
  const description = page.data.description ?? siteConfig.description;
  const image = {
    url: siteConfig.ogImage,
    width: 1200,
    height: 630,
    alt: siteConfig.ogImageAlt,
  };
  return {
    title: page.data.title,
    description,
    alternates: { canonical: page.url },
    openGraph: {
      type: "article",
      url: absoluteUrl(page.url),
      title: page.data.title,
      description,
      siteName: siteConfig.name,
      // Nested `openGraph` replaces the root's whole block — nothing set at the root
      // reaches here, so locale and the file-convention image are restated.
      locale: siteConfig.locale,
      images: [image],
      ...(page.data.lastModified
        ? { modifiedTime: page.data.lastModified.toISOString() }
        : {}),
    },
    twitter: {
      card: "summary_large_image",
      title: page.data.title,
      description,
      images: [image],
    },
  };
}
