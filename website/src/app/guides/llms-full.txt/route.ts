import { sectionFile, textResponse } from "@/lib/llms-files";

export const dynamic = "force-static";

/** `/guides/llms-full.txt`: the pages of one section of `/llms.txt` (`SECTION_FILES` in src/lib/llms.ts). */
export async function GET() {
  return textResponse(await sectionFile("/guides"));
}
