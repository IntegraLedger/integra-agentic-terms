import { skillsIndex, textResponse } from "@/lib/llms-files";

export const dynamic = "force-static";

/** `/.well-known/agent-skills/index.json`: the MCP server's skills, for an agent that discovers skills there. */
export function GET() {
  return textResponse(skillsIndex(), "application/json");
}
