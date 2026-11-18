import { llmsIndex, textResponse } from "@/lib/llms-files";

export const dynamic = "force-static";

/** `/llms.txt` (https://llmstxt.org): the index of every page, in sidebar order; `llmsIndex` writes it. */
export async function GET() {
  return textResponse(await llmsIndex());
}
