/** One or more Schema.org JSON-LD blocks, serialised at build time. `<` is escaped so no value can close the script. */
export function JsonLd({ data }: { data: object | object[] }) {
  const blocks = Array.isArray(data) ? data : [data];
  return (
    <>
      {blocks.map((block) => {
        const json = JSON.stringify(block).replace(/</g, "\\u003c");
        return <script key={json} type="application/ld+json" dangerouslySetInnerHTML={{ __html: json }} />;
      })}
    </>
  );
}
