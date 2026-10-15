import { readFileSync } from "node:fs";
import { join } from "node:path";
import { cmapReader, sfntTable } from "./cmap";

/**
 * The one font the social cards are drawn in (src/app/og/[...slug]/route.tsx): Geist Regular, the font next/og
 * bundles, read from the installed `next` package, which the site's lockfile fixes by version and integrity.
 *
 * next/og draws with the fonts it is given, and asks for more only for a character none of them draws: it then fetches
 * a font from Google Fonts, or an emoji from Twemoji, at build time. A card is drawn with this font alone, and only
 * when every character of its text is one the font draws (`notInCardFont`), so next/og never asks.
 */
const FILE = join(process.cwd(), "node_modules", "next", "dist", "compiled", "@vercel", "og", "Geist-Regular.ttf");

let loaded: { data: Buffer; has: (cp: number) => boolean } | undefined;

function font(): { data: Buffer; has: (cp: number) => boolean } {
  if (loaded) return loaded;
  const data = readFileSync(FILE);
  loaded = { data, has: cmapReader(FILE, sfntTable(FILE, data, "cmap")) };
  return loaded;
}

/** The font, as next/og's `fonts` option takes it. */
export function cardFont(): { name: string; data: Buffer; weight: 400; style: "normal" } {
  return { name: "Geist", data: font().data, weight: 400, style: "normal" };
}

/**
 * The characters of `text` the card font does not draw, each named as `U+XXXX "c"`. A line break and a tab are not
 * counted: next/og never asks for a font for either.
 */
export function notInCardFont(text: string): string[] {
  const { has } = font();
  const missing = new Set<string>();
  for (const char of text) {
    if (char === "\n" || char === "\t") continue;
    if (!has(char.codePointAt(0) ?? 0)) missing.add(char);
  }
  return [...missing].map((c) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")} "${c}"`);
}
