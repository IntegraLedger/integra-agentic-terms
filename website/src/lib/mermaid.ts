import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright-core";
import { browserExecutable } from "../../scripts/browser.mjs";
import { FONT, fontFaceCss, notInFont } from "./font";

/** A diagram as SVG in each of the site's two themes. */
export interface DiagramSvg {
  light: string;
  dark: string;
}

/** The browser's font configuration: no font folder and no rule. */
const FONTCONFIG = '<?xml version="1.0"?>\n<fontconfig></fontconfig>\n';

/**
 * Renders Mermaid diagrams to SVG with the `mermaid` package itself, in the headless browser build the repository
 * pins and fetches by its SHA-256 (`scripts/browser.mjs`), once in Mermaid's `default` theme and once in its `dark`
 * theme. `prefix` and each chart's index make the SVG ids unique on the page. An id inside an SVG that nothing in that
 * SVG references is removed, so the two copies of a diagram share no id.
 *
 * Mermaid measures and draws every text in one font, Inter, from the package the lockfile pins (`./font.ts`), so one
 * commit gives one set of SVGs on any machine:
 * - the render page loads every face of the package's stylesheet, inlined, before the first diagram, and gives every
 *   element that font with `!important`, which also governs the generic `sans-serif` that Mermaid measures text in
 *   beside its configured font;
 * - the browser runs with an environment of its own, holding only its folder (`HOME`, `TMPDIR`) and a font
 *   configuration with no font folder and no rule, so neither the machine's fonts nor its rendering settings (hinting,
 *   antialiasing) reach a diagram;
 * - a chart with a character Inter does not draw is refused before the browser starts, since the browser has no other
 *   font to draw it in.
 * - the page reads its clock in UTC and formats in the en-US locale, so a chart that writes a date or a number writes it
 *   the same on every machine.
 * The SVGs name the font, and `src/app/global.css` loads the same files, so a reader sees the diagram in the font it
 * is measured in.
 *
 * Each call gives the browser a folder of its own in the system temporary directory, holding its profile, its font
 * configuration, Playwright's artifacts and every file the browser writes to `TMPDIR` or `HOME`. Chrome Headless
 * Shell opens no Unix socket there, so the folder's path may be any length. The folder is removed once the browser has
 * closed, whether the diagrams rendered or not, and also when the browser fails to launch.
 */
export async function renderMermaid(charts: string[], prefix: string): Promise<DiagramSvg[]> {
  for (const [i, chart] of charts.entries()) {
    const missing = notInFont(chart);
    if (missing.length > 0) {
      const named = missing.map((c) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")} "${c}"`);
      throw new Error(`Mermaid diagram ${i + 1} of the page has characters ${FONT} does not draw: ${named.join(", ")}`);
    }
  }
  const executablePath = browserExecutable();
  const script = createRequire(import.meta.url).resolve("mermaid/dist/mermaid.min.js");
  const dir = await mkdtemp(join(tmpdir(), "mermaid-"));
  try {
    await writeFile(join(dir, "fonts.conf"), FONTCONFIG);
    const context = await chromium.launchPersistentContext(join(dir, "profile"), {
      executablePath,
      headless: true,
      artifactsDir: dir,
      env: { HOME: dir, TMPDIR: dir, FONTCONFIG_FILE: join(dir, "fonts.conf"), TZ: "UTC" },
      timezoneId: "UTC",
      locale: "en-US",
    });
    try {
      const page = await context.newPage();
      await page.setContent("<!doctype html><html><body></body></html>");
      await page.addStyleTag({ content: `${fontFaceCss()}\n* { font-family: "${FONT}" !important; }` });
      await page.addScriptTag({ path: script });
      return await page.evaluate(
        async ({ charts, prefix, font }) => {
          interface Mermaid {
            initialize(config: Record<string, unknown>): void;
            render(id: string, text: string): Promise<{ svg: string }>;
          }
          for (const face of document.fonts) {
            await face.load();
          }
          const mermaid = (window as unknown as { mermaid: Mermaid }).mermaid;
          const withoutUnusedIds = (svg: string): string => {
            const doc = new DOMParser().parseFromString(svg, "image/svg+xml");
            for (const el of doc.documentElement.querySelectorAll("[id]")) {
              if (!svg.includes(`#${el.id})`) && !svg.includes(`"#${el.id}"`)) el.removeAttribute("id");
            }
            return new XMLSerializer().serializeToString(doc.documentElement);
          };
          const out: { light: string; dark: string }[] = [];
          for (const [i, chart] of charts.entries()) {
            const svgs: Record<string, string> = {};
            for (const [name, theme] of [
              ["light", "default"],
              ["dark", "dark"],
            ] as const) {
              mermaid.initialize({
                startOnLoad: false,
                securityLevel: "strict",
                theme,
                fontFamily: `"${font}"`,
                htmlLabels: false,
              });
              const { svg } = await mermaid.render(`${prefix}-${i}-${name}`, chart);
              svgs[name] = withoutUnusedIds(svg);
            }
            out.push({ light: svgs.light ?? "", dark: svgs.dark ?? "" });
          }
          return out;
        },
        { charts, prefix, font: FONT },
      );
    } finally {
      await context.close();
    }
  } finally {
    // When a launch fails, the browser can go on closing and writing to its profile: Playwright closes it, or kills it
    // after 30 seconds. The removal retries for 36 seconds in all (1 + 2 + ... + 8), longer than that.
    await rm(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 1000 });
  }
}
