import { toHtml } from "hast-util-to-html";
import { renderMermaid } from "./mermaid";

/** The parts of a hast node these plugins read or write. */
interface HastNode {
  type: string;
  tagName?: string;
  value?: string;
  properties?: { className?: unknown } & Record<string, unknown>;
  data?: { meta?: string; estree?: unknown };
  children?: HastNode[];
}

function textOf(node: HastNode): string {
  if (node.type === "text") return node.value ?? "";
  return (node.children ?? []).map(textOf).join("");
}

function codeOf(pre: HastNode): HastNode | undefined {
  if (pre.type !== "element" || pre.tagName !== "pre") return undefined;
  const code = pre.children?.[0];
  return code?.type === "element" && code.tagName === "code" ? code : undefined;
}

function languageOf(code: HastNode): string | undefined {
  const classes = code.properties?.className;
  if (!Array.isArray(classes)) return undefined;
  const found = classes.find((c) => typeof c === "string" && c.startsWith("language-"));
  return typeof found === "string" ? found.slice("language-".length) : undefined;
}

/**
 * Renders each ```` ```mermaid ```` block to SVG at build time, in the light and the dark theme, and replaces it with a
 * `<Mermaid light="…" dark="…" />` element, which the page shows in the reader's theme. Runs before code highlighting.
 */
export function rehypeMermaid() {
  return async (tree: HastNode) => {
    const found: { parent: HastNode[]; index: number; chart: string }[] = [];
    const visit = (node: HastNode) => {
      const children = node.children ?? [];
      children.forEach((child, index) => {
        const code = codeOf(child);
        if (code && languageOf(code) === "mermaid") {
          found.push({ parent: children, index, chart: textOf(code).trimEnd() });
        } else {
          visit(child);
        }
      });
    };
    visit(tree);
    if (found.length === 0) return;
    const svgs = await renderMermaid(
      found.map((f) => f.chart),
      "mermaid",
    );
    found.forEach(({ parent, index }, i) => {
      const svg = svgs[i];
      if (!svg) throw new Error(`no SVG for Mermaid diagram ${i}`);
      parent[index] = {
        type: "mdxJsxFlowElement",
        name: "Mermaid",
        attributes: [
          { type: "mdxJsxAttribute", name: "light", value: svg.light },
          { type: "mdxJsxAttribute", name: "dark", value: svg.dark },
        ],
        children: [],
      } as HastNode;
    });
  };
}

/** An ESM `export const <name> = [<strings>]` node of an MDX tree. */
function exportStrings(name: string, values: string[]): HastNode {
  return {
    type: "mdxjsEsm",
    value: "",
    data: {
      estree: {
        type: "Program",
        sourceType: "module",
        body: [
          {
            type: "ExportNamedDeclaration",
            specifiers: [],
            source: null,
            declaration: {
              type: "VariableDeclaration",
              kind: "const",
              declarations: [
                {
                  type: "VariableDeclarator",
                  id: { type: "Identifier", name },
                  init: { type: "ArrayExpression", elements: values.map((value) => ({ type: "Literal", value })) },
                },
              ],
            },
          },
        ],
      },
    },
  };
}

/**
 * Replaces each Twoslash hover (a `Popup` element holding its `PopupContent` and `PopupTrigger`) with a plain trigger
 * button that names its popup by number, and exports the page's distinct popup contents, as HTML, as
 * `twoslashPopups`, which `src/lib/twoslash.ts` reads. The site serves them as a separate file, which the browser
 * fetches when a reader first opens a popup (`TwoslashPopups`). Runs after code highlighting.
 */
export function rehypeTwoslashPopups() {
  return (tree: HastNode) => {
    const popups: string[] = [];
    const numbers = new Map<string, number>();
    const visit = (node: HastNode) => {
      const children = node.children ?? [];
      children.forEach((child, i) => {
        if (child.type !== "element" || child.tagName !== "Popup") {
          visit(child);
          return;
        }
        const part = (tagName: string) => child.children?.find((c) => c.tagName === tagName)?.children ?? [];
        const html = toHtml({ type: "root", children: part("PopupContent") } as Parameters<typeof toHtml>[0]);
        let n = numbers.get(html);
        if (n === undefined) {
          n = popups.length;
          popups.push(html);
          numbers.set(html, n);
        }
        children[i] = {
          type: "element",
          tagName: "button",
          properties: {
            type: "button",
            className: ["twoslash-hover"],
            dataPopup: n,
            ariaHaspopup: "dialog",
            ariaExpanded: "false",
          },
          children: part("PopupTrigger"),
        };
      });
    };
    visit(tree);
    if (popups.length > 0) tree.children?.unshift(exportStrings("twoslashPopups", popups));
  };
}

/** A heading's text as a name: each image's alt text, and no footnote reference. */
function headingName(node: HastNode): string {
  if (node.type === "text") return node.value ?? "";
  if (node.type === "element" && node.tagName === "img") {
    return typeof node.properties?.alt === "string" ? node.properties.alt : "";
  }
  if (node.type === "element" && node.tagName === "sup" && node.children?.some((c) => c.properties?.dataFootnoteRef)) {
    return "";
  }
  return (node.children ?? []).map(headingName).join("");
}

/**
 * Names each table by the heading it sits under, as `data-name`, which the table's region takes as its accessible name
 * (src/components/Table.tsx). Tables that would share a name, such as two under one heading, are told apart by their
 * place among them ("Stellar, table 2 of 2"), so each region of a page has its own name. A heading's name is its text,
 * with each image's alt text and without its footnote references. A table before any heading, or under a heading with
 * no name, is named "Table".
 */
export function rehypeTableNames() {
  return (tree: HastNode) => {
    const tables: { table: HastNode; name: string }[] = [];
    let heading = "Table";
    const visit = (node: HastNode) => {
      for (const child of node.children ?? []) {
        if (child.type === "element" && /^h[1-6]$/.test(child.tagName ?? "")) {
          heading = headingName(child).replace(/\s+/g, " ").trim() || "Table";
        } else if (child.type === "element" && child.tagName === "table") {
          tables.push({ table: child, name: heading });
        } else {
          visit(child);
        }
      }
    };
    visit(tree);
    const counts = new Map<string, number>();
    for (const { name } of tables) counts.set(name, (counts.get(name) ?? 0) + 1);
    const seen = new Map<string, number>();
    for (const { table, name } of tables) {
      const total = counts.get(name) ?? 1;
      const place = (seen.get(name) ?? 0) + 1;
      seen.set(name, place);
      table.properties = { ...table.properties, dataName: total > 1 ? `${name}, table ${place} of ${total}` : name };
    }
  };
}
