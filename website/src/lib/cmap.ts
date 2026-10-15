/**
 * A font's `cmap` table, read: which code points the font maps to a glyph other than `.notdef`. The diagrams' font
 * (font.ts) and the social cards' font (card-font.ts) are read with it.
 */

/**
 * The lookup of a `cmap` table: a format 12 subtable for Unicode's full repertoire, or else a format 4 subtable for its
 * Basic Multilingual Plane (OpenType's cmap table).
 */
export function cmapReader(name: string, table: Buffer): (cp: number) => boolean {
  const subtables: { platform: number; encoding: number; format: number; at: number }[] = [];
  for (let i = 0; i < table.readUInt16BE(2); i++) {
    const record = 4 + i * 8;
    const start = table.readUInt32BE(record + 4);
    subtables.push({
      platform: table.readUInt16BE(record),
      encoding: table.readUInt16BE(record + 2),
      format: table.readUInt16BE(start),
      at: start,
    });
  }
  const unicode = (s: { platform: number; encoding: number }) =>
    s.platform === 0 || (s.platform === 3 && (s.encoding === 1 || s.encoding === 10));
  const full = subtables.find((s) => unicode(s) && s.format === 12);
  if (full) {
    const groups: [number, number, number][] = [];
    for (let i = 0; i < table.readUInt32BE(full.at + 12); i++) {
      const g = full.at + 16 + i * 12;
      groups.push([table.readUInt32BE(g), table.readUInt32BE(g + 4), table.readUInt32BE(g + 8)]);
    }
    return (cp) => groups.some(([first, last, glyph]) => cp >= first && cp <= last && glyph + (cp - first) !== 0);
  }
  const bmp = subtables.find((s) => unicode(s) && s.format === 4);
  if (!bmp) throw new Error(`${name} has no Unicode cmap subtable of format 12 or 4`);
  const segments = table.readUInt16BE(bmp.at + 6) / 2;
  const ends = bmp.at + 14;
  const starts = ends + segments * 2 + 2;
  const deltas = starts + segments * 2;
  const rangeOffsets = deltas + segments * 2;
  return (cp) => {
    if (cp > 0xffff) return false;
    for (let s = 0; s < segments; s++) {
      if (cp > table.readUInt16BE(ends + s * 2)) continue;
      const first = table.readUInt16BE(starts + s * 2);
      if (cp < first) return false;
      const delta = table.readUInt16BE(deltas + s * 2);
      const rangeOffset = table.readUInt16BE(rangeOffsets + s * 2);
      if (rangeOffset === 0) return ((cp + delta) & 0xffff) !== 0;
      const glyph = table.readUInt16BE(rangeOffsets + s * 2 + rangeOffset + (cp - first) * 2);
      return glyph !== 0 && ((glyph + delta) & 0xffff) !== 0;
    }
    return false;
  };
}

/** A table of an OpenType or TrueType font file (an sfnt), by its tag, read from the file's table directory. */
export function sfntTable(name: string, font: Buffer, tag: string): Buffer {
  const version = font.readUInt32BE(0);
  if (version !== 0x00010000 && font.toString("latin1", 0, 4) !== "OTTO" && font.toString("latin1", 0, 4) !== "true") {
    throw new Error(`${name} is not an OpenType or TrueType font file`);
  }
  for (let i = 0; i < font.readUInt16BE(4); i++) {
    const record = 12 + i * 16;
    if (font.toString("latin1", record, record + 4) === tag) {
      const offset = font.readUInt32BE(record + 8);
      return font.subarray(offset, offset + font.readUInt32BE(record + 12));
    }
  }
  throw new Error(`${name} has no ${tag} table`);
}
