import type { ComponentProps } from "react";

/**
 * A Markdown table, in a wrapper that scrolls sideways when the table is wider than the page. The wrapper is a region
 * a keyboard reaches with Tab and scrolls with the arrow keys (WCAG 2.1.1), named by the heading the table sits under
 * (`rehypeTableNames` in src/lib/rehype-docs.ts, which passes the name as `data-name`).
 */
export function Table({ "data-name": name, ...props }: ComponentProps<"table"> & { "data-name"?: string }) {
  return (
    <div
      className="relative overflow-auto prose-no-margin my-6"
      role="region"
      aria-label={name ?? "Table"}
      tabIndex={0}
    >
      <table {...props} />
    </div>
  );
}
