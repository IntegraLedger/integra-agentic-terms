import { textResponse } from "@/lib/llms-files";
import { profiles } from "@/lib/terms-files";

export const dynamic = "force-static";
export const dynamicParams = false;

/** `/profiles/<name>.md`: the gate's profile, from agentic-terms/profiles/, byte for byte. */
export function generateStaticParams() {
  return profiles().map((f) => ({ name: f.name }));
}

export async function GET(_request: Request, context: { params: Promise<{ name: string }> }) {
  const { name } = await context.params;
  const file = profiles().find((f) => f.name === name);
  if (file === undefined) return new Response("not found", { status: 404 });
  return textResponse(file.bytes, "text/markdown; charset=utf-8");
}
