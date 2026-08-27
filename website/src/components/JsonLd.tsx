/**
 * Renders one or more Schema.org JSON-LD blocks into the document.
 * Statically serialized at build time (works under `output: export`).
 */
export function JsonLd({ data }: { data: object | object[] }) {
  const blocks = Array.isArray(data) ? data : [data];
  return (
    <>
      {blocks.map((block) => {
        // Author-controlled schema (siteConfig + MDX frontmatter), never user
        // input. Escaping `<` neutralizes any `</script>` breakout regardless.
        const json = JSON.stringify(block).replace(/</g, "\\u003c");
        return (
          <script
            key={json}
            type="application/ld+json"
            // biome-ignore lint/security/noDangerouslySetInnerHtml: JSON-LD has to be inline script text; the payload is build-time author data with `<` escaped
            dangerouslySetInnerHTML={{ __html: json }}
          />
        );
      })}
    </>
  );
}
