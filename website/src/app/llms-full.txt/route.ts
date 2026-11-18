import { fullFile, textResponse } from "@/lib/llms-files";

export const dynamic = "force-static";

/** `/llms-full.txt`: every page as Markdown, in sidebar order, from the same source the HTML is rendered from. */
export async function GET() {
  return textResponse(await fullFile());
}
