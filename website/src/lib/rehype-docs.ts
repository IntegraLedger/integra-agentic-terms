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
