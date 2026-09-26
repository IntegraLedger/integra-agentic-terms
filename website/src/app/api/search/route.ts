import { createFromSource } from "fumadocs-core/search/server";
import { source } from "@/lib/source";

export const revalidate = false;

/** The search index, written at build time as a static file. */
export const { staticGET: GET } = createFromSource(source);
