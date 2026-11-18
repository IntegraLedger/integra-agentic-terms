import "server-only";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { brief } from "@/lib/llms";

/**
 * A file of the packages the site serves byte for byte, from the commit it is built from: the gate's profile
 * (`/profiles/<name>.md`, from agentic-terms/profiles/), its vector files (`/vectors/<name>.json`, from
 * agentic-terms/vectors/) and the MCP server's skill (`/.well-known/agent-skills/<name>/SKILL.md`, from
 * agentic-terms-mcp/skills/). Server only: it reads the filesystem at build time.
 */
export interface ServedFile {
  /** The file's name: a skill's is its folder's. */
  name: string;
  /** Its address on the site. */
  path: string;
  /** Its bytes, as the repository holds them. */
  bytes: Buffer;
  /** The line an index lists it with. */
  description: string;
}

/** `next build` runs in website/; the packages are its siblings. */
const REPO = join(process.cwd(), "..");

function filesOf(folder: string, ext: string): Array<{ name: string; bytes: Buffer }> {
  return readdirSync(join(REPO, folder))
    .filter((name) => name.endsWith(ext))
    .sort()
    .map((name) => ({ name, bytes: readFileSync(join(REPO, folder, name)) }));
}

/** The gate's profiles, described by their opening sentence (`**terms profile `x`: …**`). */
export function profiles(): ServedFile[] {
  return filesOf("agentic-terms/profiles", ".md").map(({ name, bytes }) => {
    const text = bytes.toString("utf8");
    const opening = /^\*\*(.+?)\*\*/.exec(text)?.[1] ?? text.split(/\n\s*\n/)[0] ?? name;
    return { name, path: `/profiles/${name}`, bytes, description: brief(opening.replace(/\.$/, "")) };
  });
}

/** The gate's vector files, described by the first sentence of their `about`. */
export function vectorFiles(): ServedFile[] {
  return filesOf("agentic-terms/vectors", ".json").map(({ name, bytes }) => {
    const about: unknown = (JSON.parse(bytes.toString("utf8")) as { about?: unknown }).about;
    if (typeof about !== "string" || about.length === 0) throw new Error(`agentic-terms/vectors/${name} has no about`);
    const first = /^.+?(?<!\b(?:e\.g|i\.e|etc|vs))[.!?](?=\s|$)/s.exec(about.trim())?.[0] ?? about;
    return { name, path: `/vectors/${name}`, bytes, description: brief(first) };
  });
}

/** A skill of the MCP server: its file, and the `name` and `description` of its frontmatter. */
export interface Skill extends ServedFile {
  /** The SHA-256 of its bytes, as hex. */
  sha256: string;
  /** Its frontmatter's `description`, whole: what tells an agent when it applies. */
  when: string;
}

/** The MCP server's skills, `agentic-terms-mcp/skills/<name>/SKILL.md`. */
export function skills(): Skill[] {
  const root = join(REPO, "agentic-terms-mcp", "skills");
  return readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort()
    .map((folder) => {
      const bytes = readFileSync(join(root, folder, "SKILL.md"));
      const front = /^---\n([\s\S]*?)\n---\n/.exec(bytes.toString("utf8"))?.[1] ?? "";
      const field = (key: string) => new RegExp(`^${key}:\\s*(.+)$`, "m").exec(front)?.[1]?.trim();
      const name = field("name");
      const when = field("description");
      if (name !== folder || when === undefined) {
        throw new Error(`agentic-terms-mcp/skills/${folder}/SKILL.md: its frontmatter must name it ${folder} and describe it`);
      }
      return {
        name,
        path: `/.well-known/agent-skills/${name}/SKILL.md`,
        bytes,
        description: brief(when),
        when,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
    });
}
