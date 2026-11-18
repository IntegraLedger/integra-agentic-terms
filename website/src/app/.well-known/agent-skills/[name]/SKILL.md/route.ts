import { textResponse } from "@/lib/llms-files";
import { skills } from "@/lib/terms-files";

export const dynamic = "force-static";
export const dynamicParams = false;

/** `/.well-known/agent-skills/<name>/SKILL.md`: each skill of agentic-terms-mcp/skills/, byte for byte. */
export function generateStaticParams() {
  return skills().map((s) => ({ name: s.name }));
}

export async function GET(_request: Request, context: { params: Promise<{ name: string }> }) {
  const { name } = await context.params;
  const skill = skills().find((s) => s.name === name);
  if (skill === undefined) return new Response("not found", { status: 404 });
  return textResponse(skill.bytes, "text/markdown; charset=utf-8");
}
